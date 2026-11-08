/* Firebase is loaded with the compat build so the existing single-page app can
 * use one small service boundary instead of spreading SDK calls throughout UI code. */
(function initialiseFirebaseServices() {
  const config = window.SAPC_FIREBASE_CONFIG;
  const isConfigured = config && !Object.values(config).some(value => String(value).startsWith("REPLACE_WITH"));

  if (!isConfigured || !window.firebase) {
    window.sapcFirebase = {
      configured: false,
      getCurrentUser: () => null,
      getIdToken: async () => null
    };
    return;
  }

  firebase.initializeApp(config);
  const auth = firebase.auth();
  const db = firebase.firestore();

  // Enable offline persistence for instantaneous local message loading
  db.enablePersistence({ synchronizeTabs: true }).catch((err) => {
    if (err.code == 'failed-precondition') {
      console.warn("Persistence failed: Multiple browser tabs open.");
    } else if (err.code == 'unimplemented') {
      console.warn("Persistence is not supported by this browser.");
    }
  });

  const provider = new firebase.auth.GoogleAuthProvider();
  provider.setCustomParameters({ prompt: "select_account" });

  const profileRef = user => db.collection("users").doc(user.uid);
  const deckCollection = user => profileRef(user).collection("decks");
  const publicProfileRef = uid => db.collection("publicProfiles").doc(uid);
  
  const getRecipientId = (profile) => profile?.id || profile?.uid || "";
  const chatConversationId = (firstId, secondId) => {
    if (!firstId || !secondId) throw new Error("Invalid chat participants.");
    return [String(firstId), String(secondId)].sort().join("_");
  };
  
  const chatPrivateKeyName = user => `sapc_chat_private_key_${user.uid}`;
  const sessionKeyCache = new Map(); // Cache per-account derived keys for fast decryption
  const keyPreparationCache = new Map();
  const identityCache = new Map();
  const conversationSetupCache = new Map();

  async function ensureChatIdentity(user) {
    if (identityCache.has(user.uid)) return identityCache.get(user.uid);
    const identityPromise = (async () => {
      const storageKey = chatPrivateKeyName(user);
      const stored = localStorage.getItem(storageKey);
      let keyPair;
      let savedKeys;
      if (stored) {
        try {
          savedKeys = JSON.parse(stored);
          keyPair = {
            privateKey: await crypto.subtle.importKey("jwk", savedKeys.privateKey, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]),
            publicKey: await crypto.subtle.importKey("jwk", savedKeys.publicKey, { name: "ECDH", namedCurve: "P-256" }, true, [])
          };
        } catch {
          localStorage.removeItem(storageKey);
          savedKeys = null;
        }
      }
      if (!keyPair) {
        keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
        const [privateKey, publicKey] = await Promise.all([
          crypto.subtle.exportKey("jwk", keyPair.privateKey),
          crypto.subtle.exportKey("jwk", keyPair.publicKey)
        ]);
        savedKeys = { privateKey, publicKey };
        localStorage.setItem(storageKey, JSON.stringify(savedKeys));
      }
      await publicProfileRef(user.uid).set({ chatPublicKey: savedKeys.publicKey }, { merge: true });
      return keyPair;
    })();
    identityCache.set(user.uid, identityPromise);
    try {
      return await identityPromise;
    } catch (error) {
      identityCache.delete(user.uid);
      throw error;
    }
  }

  async function deriveChatKey(user, otherProfile) {
    const recipientId = getRecipientId(otherProfile);
    if (!recipientId) throw new Error("Missing recipient identifier for chat key.");

    const cacheKey = `${user.uid}:${recipientId}`;
    if (sessionKeyCache.has(cacheKey)) {
      return sessionKeyCache.get(cacheKey);
    }
    if (keyPreparationCache.has(cacheKey)) return keyPreparationCache.get(cacheKey);

    const preparation = (async () => {
      let targetProfile = otherProfile;
      if (!targetProfile?.chatPublicKey) {
        const publicSnap = await publicProfileRef(recipientId).get();
        if (publicSnap.exists) {
          targetProfile = publicSnap.data();
        }
      }

      if (!targetProfile?.chatPublicKey) {
        throw new Error("This user has not initialized secure chat on this device yet.");
      }

      const identity = await ensureChatIdentity(user);
      const publicKey = await crypto.subtle.importKey("jwk", targetProfile.chatPublicKey, { name: "ECDH", namedCurve: "P-256" }, true, []);
      const derivedKey = await crypto.subtle.deriveKey(
        { name: "ECDH", public: publicKey },
        identity.privateKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
      sessionKeyCache.set(cacheKey, derivedKey);
      return derivedKey;
    })();
    keyPreparationCache.set(cacheKey, preparation);
    try {
      return await preparation;
    } finally {
      keyPreparationCache.delete(cacheKey);
    }
  }

  async function encryptChatPayload(user, otherProfile, payload) {
    try {
      const key = await deriveChatKey(user, otherProfile);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(JSON.stringify(payload));
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
      return {
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        iv: btoa(String.fromCharCode(...iv))
      };
    } catch (e) {
      const jsonStr = JSON.stringify(payload);
      return {
        ciphertext: btoa(jsonStr),
        iv: "PLAIN"
      };
    }
  }

  async function decryptChatPayload(user, otherProfile, message) {
    if (message.iv === "PLAIN" || !message.iv) {
      try {
        return JSON.parse(atob(message.ciphertext));
      } catch {
        return { text: message.ciphertext || message.text };
      }
    }

    try {
      const key = await deriveChatKey(user, otherProfile);
      const decode = value => Uint8Array.from(atob(value), character => character.charCodeAt(0));
      const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode(message.iv) }, key, decode(message.ciphertext));
      const decoded = new TextDecoder().decode(plaintext);
      try {
        return JSON.parse(decoded);
      } catch (error) {
        return { text: decoded };
      }
    } catch (cryptoErr) {
      try {
        const decodedPlain = atob(message.ciphertext);
        const parsed = JSON.parse(decodedPlain);
        return parsed.text ? parsed : { text: decodedPlain };
      } catch {
        return { text: message.text || message.ciphertext || "[Encrypted Message]" };
      }
    }
  }

  async function optimizeChatImage(file) {
    if (!file.type.startsWith("image/") || file.type === "image/gif"
      || file.type === "image/svg+xml" || file.size < 450 * 1024
      || typeof createImageBitmap !== "function" || typeof File !== "function") return file;
    try {
      const bitmap = await createImageBitmap(file);
      const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
      const canvas = document.createElement("canvas");
      canvas.width = Math.max(1, Math.round(bitmap.width * scale));
      canvas.height = Math.max(1, Math.round(bitmap.height * scale));
      canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      bitmap.close?.();
      const blob = await new Promise(resolve => canvas.toBlob(resolve, "image/jpeg", 0.82));
      if (!blob || blob.size >= file.size * 0.9) return file;
      const baseName = file.name.replace(/\.[^.]+$/, "");
      return new File([blob], `${baseName}.jpg`, { type: "image/jpeg", lastModified: file.lastModified });
    } catch (error) {
      console.warn("Could not optimize chat image; uploading the original.", error);
      return file;
    }
  }

  async function ensureProfile(user) {
    const ref = profileRef(user);
    const snapshot = await ref.get();
    const existing = snapshot.exists ? snapshot.data() : {};
    const profile = {
      email: user.email || existing.email || "",
      displayName: existing.displayName || user.displayName || user.email?.split("@")[0] || "Paduan",
      username: existing.username || "",
      photoURL: existing.photoURL || user.photoURL || "",
      updatedAt: firebase.firestore.FieldValue.serverTimestamp()
    };
    if (!snapshot.exists) profile.createdAt = firebase.firestore.FieldValue.serverTimestamp();
    await ref.set(profile, { merge: true });
    await publicProfileRef(user.uid).set({
      displayName: profile.displayName,
      displayNameLower: String(profile.displayName || "").toLowerCase(),
      email: profile.email,
      username: profile.username,
      usernameLower: String(profile.username || "").toLowerCase(),
      photoURL: profile.photoURL,
      lastSeenAt: firebase.firestore.FieldValue.serverTimestamp(),
      gradeLevel: existing.gradeLevel || "",
      strand: existing.strand || "",
      updatedAt: firebase.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    return { ...existing, ...profile };
  }

  async function saveDeck(user, deck) {
    const ref = deck.id ? deckCollection(user).doc(deck.id) : deckCollection(user).doc();
    const payload = {
      title: String(deck.title || "Saved Reviewer Deck").trim().slice(0, 120),
      subjectMode: deck.subjectMode || "general",
      gradeLevel: deck.gradeLevel || "Grade 11",
      academicStrand: deck.academicStrand || "General",
      tags: Array.isArray(deck.tags) ? deck.tags.slice(0, 20) : [],
      cards: Array.isArray(deck.cards) ? deck.cards : [],
      updatedAt: firebase.firestore.FieldValue.serverTimestamp()
    };
    if (!deck.id) payload.createdAt = firebase.firestore.FieldValue.serverTimestamp();
    await ref.set(payload, { merge: true });
    return { id: ref.id, ...payload };
  }

  async function ensureChatConversation(user, otherProfile) {
    const recipientId = getRecipientId(otherProfile);
    const conversationId = chatConversationId(user.uid, recipientId);
    const cacheKey = conversationId;
    if (conversationSetupCache.has(cacheKey)) return conversationSetupCache.get(cacheKey);
    const conversation = db.collection("chatConversations").doc(conversationId);
    const setup = conversation.set({
      participants: [user.uid, recipientId].sort(),
      updatedAt: firebase.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    conversationSetupCache.set(cacheKey, setup);
    try {
      await setup;
    } catch (error) {
      conversationSetupCache.delete(cacheKey);
      throw error;
    }
  }

  async function recordStudySession(user, data) {
    const session = {
      deckId: data.deckId || "local-session",
      correct: Number(data.correct) || 0,
      total: Number(data.total) || 0,
      durationSeconds: Number(data.durationSeconds) || 0,
      completedAt: firebase.firestore.FieldValue.serverTimestamp()
    };
    await profileRef(user).collection("studySessions").add(session);
    await profileRef(user).set({
      lastStudiedAt: firebase.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
  }

  window.sapcFirebase = {
    configured: true,
    auth,
    db,
    provider,
    getCurrentUser: () => auth.currentUser,
    getIdToken: () => auth.currentUser ? auth.currentUser.getIdToken() : null,
    ensureProfile,
    updatePresence: user => publicProfileRef(user.uid).set({
      lastSeenAt: firebase.firestore.FieldValue.serverTimestamp()
    }, { merge: true }),
    ensureChatIdentity,
    ensureChatConversation,
    prepareChatKey: async (user, otherProfile) => {
      try {
        await deriveChatKey(user, otherProfile);
      } catch (error) {
        if (!String(error.message).includes("has not initialized secure chat")) throw error;
      }
    },
    sendChatMessage: async (user, otherProfile, payload) => {
      const recipientId = getRecipientId(otherProfile);
      await ensureChatConversation(user, otherProfile);
      const encrypted = await encryptChatPayload(user, otherProfile, payload);
      const conversationId = chatConversationId(user.uid, recipientId);
      const conversation = db.collection("chatConversations").doc(conversationId);
      const serverAck = await conversation.collection("messages").add({
        senderId: user.uid,
        messageType: payload.attachment ? "attachment" : "text",
        deliveredAt: null,
        seenBy: {},
        ...encrypted,
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      });
      return { serverAck };
    },
    unsendChatMessage: async (user, otherProfile, messageId) => {
      const recipientId = getRecipientId(otherProfile);
      const conversationId = chatConversationId(user.uid, recipientId);
      const messageRef = db.collection("chatConversations").doc(conversationId)
        .collection("messages").doc(messageId);
      
      const doc = await messageRef.get();
      if (!doc.exists) throw new Error("Message not found.");
      if (doc.data().senderId !== user.uid) throw new Error("You can only unsend your own messages.");

      const encrypted = await encryptChatPayload(user, otherProfile, {
        text: "This message was unsent",
        attachment: null,
        isUnsent: true
      });

      await messageRef.update({
        ...encrypted,
        messageType: "text",
        isUnsent: true,
        updatedAt: firebase.firestore.FieldValue.serverTimestamp()
      });
    },
    removeChatMessageForMe: async (user, otherProfile, messageId) => {
      const recipientId = getRecipientId(otherProfile);
      const conversationId = chatConversationId(user.uid, recipientId);
      const messageRef = db.collection("chatConversations").doc(conversationId)
        .collection("messages").doc(messageId);
      const doc = await messageRef.get();
      if (!doc.exists) throw new Error("Message not found.");
      const hiddenFor = doc.data().hiddenFor || [];
      if (hiddenFor.includes(user.uid)) return;
      await messageRef.update({
        hiddenFor: firebase.firestore.FieldValue.arrayUnion(user.uid),
        updatedAt: firebase.firestore.FieldValue.serverTimestamp()
      });
    },
    uploadChatAttachment: async (user, file) => {
      const allowed = file.type.startsWith("image/") || file.type === "application/pdf";
      if (!allowed) throw new Error("Only images, GIFs, and PDFs can be sent.");
      if (file.size > 30 * 1024 * 1024) throw new Error("Attachments must be 30 MB or smaller.");
      const config = window.SAPC_CLOUDINARY_CONFIG;
      if (!config?.cloudName || config.cloudName.startsWith("REPLACE_WITH")
        || !config.uploadPreset || config.uploadPreset.startsWith("REPLACE_WITH")) {
        throw new Error("Cloudinary uploads are not configured yet. Add the cloud name and unsigned upload preset.");
      }
      const uploadFile = await optimizeChatImage(file);
      const formData = new FormData();
      formData.append("file", uploadFile);
      formData.append("upload_preset", config.uploadPreset);
      formData.append("folder", `sapc-chat/${user.uid}`);
      const response = await fetch(`https://api.cloudinary.com/v1_1/${encodeURIComponent(config.cloudName)}/auto/upload`, {
        method: "POST",
        body: formData
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok || !result.secure_url) {
        throw new Error(result.error?.message || "Cloudinary could not upload this attachment.");
      }
      return result.secure_url;
    },
    listChatMessages: async (user, otherProfile) => {
      const recipientId = getRecipientId(otherProfile);
      const conversationId = chatConversationId(user.uid, recipientId);
      const snapshot = await db.collection("chatConversations").doc(conversationId)
        .collection("messages").orderBy("createdAt", "asc").limitToLast(100).get();
      const messages = await Promise.all(snapshot.docs.map(async doc => {
        const data = doc.data();
        if ((data.hiddenFor || []).includes(user.uid)) return null;
        const payload = await decryptChatPayload(user, otherProfile, data);
        return {
          id: doc.id,
          senderId: data.senderId,
          createdAt: data.createdAt,
          deliveredAt: data.deliveredAt,
          seenBy: data.seenBy || {},
          isUnsent: data.isUnsent || false,
          hiddenFor: data.hiddenFor || [],
          ...payload
        };
      }));
      return messages.filter(Boolean);
    },
    subscribeToChatMessages: (user, otherProfile, callback, onError = () => {}) => {
      const recipientId = getRecipientId(otherProfile);
      const conversationId = chatConversationId(user.uid, recipientId);
      const messagesRef = db.collection("chatConversations").doc(conversationId)
        .collection("messages").orderBy("createdAt", "asc").limitToLast(100);
      let latestSnapshotVersion = 0;

      return messagesRef.onSnapshot(snapshot => {
        const snapshotVersion = ++latestSnapshotVersion;
        Promise.all(snapshot.docs.map(async doc => {
          const data = doc.data();
          if ((data.hiddenFor || []).includes(user.uid)) return null;
          const payload = await decryptChatPayload(user, otherProfile, data);
          return {
            id: doc.id,
            senderId: data.senderId,
            createdAt: data.createdAt,
            deliveredAt: data.deliveredAt,
            seenBy: data.seenBy || {},
            isUnsent: data.isUnsent || false,
            hiddenFor: data.hiddenFor || [],
            ...payload
          };
        })).then(messages => {
          if (snapshotVersion === latestSnapshotVersion) callback(messages.filter(Boolean));
        }).catch(error => {
          console.error("Could not decrypt chat messages:", error);
          onError(error);
        });
      }, (error) => {
        console.error("Real-time chat listener error:", error);
        onError(error);
      });
    },
    markChatMessagesSeen: async (user, otherProfile, messages) => {
      const recipientId = getRecipientId(otherProfile);
      const conversationId = chatConversationId(user.uid, recipientId);
      const conversation = db.collection("chatConversations").doc(conversationId);
      await Promise.all(messages.filter(message => message.senderId !== user.uid && !message.seenBy?.[user.uid]).map(message =>
        conversation.collection("messages").doc(message.id).update({
          deliveredAt: firebase.firestore.FieldValue.serverTimestamp(),
          [`seenBy.${user.uid}`]: firebase.firestore.FieldValue.serverTimestamp()
        })
      ));
    },
    signIn: (email, password) => auth.signInWithEmailAndPassword(email, password),
    resolveLoginEmail: async identifier => {
      const value = String(identifier || "").trim().toLowerCase();
      if (value.includes("@")) return value;
      const snapshot = await db.collection("publicProfiles")
        .where("usernameLower", "==", value)
        .limit(1)
        .get();
      if (snapshot.empty) throw new Error("No account was found with that username.");
      return snapshot.docs[0].data().email;
    },
    isUsernameAvailable: async username => {
      const snapshot = await db.collection("publicProfiles")
        .where("usernameLower", "==", String(username || "").trim().toLowerCase())
        .limit(1)
        .get();
      return snapshot.empty;
    },
    register: (email, password) => auth.createUserWithEmailAndPassword(email, password),
    signInWithGoogle: () => auth.signInWithPopup(provider),
    linkGoogle: user => user.linkWithPopup(provider),
    sendPasswordReset: email => auth.sendPasswordResetEmail(email, {
      url: "https://ai-driven-academic-flashcards.web.app/reset-password.html",
      handleCodeInApp: false
    }),
    signOut: () => auth.signOut(),
    listDecks: async user => {
      const snapshot = await deckCollection(user).orderBy("updatedAt", "desc").limit(100).get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    },
    saveDeck,
    deleteDeck: (user, deckId) => deckCollection(user).doc(deckId).delete(),
    recordStudySession,
    saveProfile: async (user, profile) => {
      const safeProfile = {
        displayName: String(profile.displayName || "").trim().slice(0, 80),
        username: String(profile.username || "").trim().toLowerCase().slice(0, 24),
        bio: String(profile.bio || "").trim().slice(0, 300),
        gradeLevel: String(profile.gradeLevel || "").slice(0, 30),
        strand: String(profile.strand || "").slice(0, 50),
        photoURL: String(profile.photoURL || "").slice(0, 400000),
        updatedAt: firebase.firestore.FieldValue.serverTimestamp()
      };
      await profileRef(user).set(safeProfile, { merge: true });
      await publicProfileRef(user.uid).set({
        displayName: safeProfile.displayName,
        displayNameLower: String(safeProfile.displayName || "").toLowerCase(),
        username: safeProfile.username,
        usernameLower: safeProfile.username,
        email: user.email || "",
        photoURL: safeProfile.photoURL,
        gradeLevel: safeProfile.gradeLevel,
        strand: safeProfile.strand,
        updatedAt: firebase.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
      return safeProfile;
    },
    getProfile: async user => {
      const snapshot = await profileRef(user).get();
      return snapshot.exists ? snapshot.data() : {};
    },
    createShare: async (user, deck) => {
      const shareRef = db.collection("sharedDecks").doc();
      await shareRef.set({
        ownerId: user.uid,
        title: deck.title || "Shared Reviewer Deck",
        cards: deck.cards || [],
        subjectMode: deck.subjectMode || "general",
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      });
      return shareRef.id;
    },
    getSharedDeck: async shareId => {
      const snapshot = await db.collection("sharedDecks").doc(shareId).get();
      return snapshot.exists ? { id: snapshot.id, ...snapshot.data() } : null;
    },
    getPublicProfile: async uid => {
      const snapshot = await publicProfileRef(uid).get();
      return snapshot.exists ? { id: snapshot.id, ...snapshot.data() } : null;
    },
    searchUsers: async (query, currentUser) => {
      const normalized = String(query || "").trim().toLowerCase();
      if (normalized.length < 2) return [];
      const snapshot = await db.collection("publicProfiles")
        .orderBy("displayNameLower")
        .startAt(normalized)
        .endAt(`${normalized}\uf8ff`)
        .limit(20)
        .get();
      return snapshot.docs
        .map(doc => ({ id: doc.id, ...doc.data() }))
        .filter(profile => profile.id !== currentUser.uid);
    },
    sendFriendRequest: async (user, target) => {
      const targetId = getRecipientId(target);
      const requestId = `${user.uid}_${targetId}`;
      const requestRef = db.collection("friendRequests").doc(requestId);
      await requestRef.set({
        fromId: user.uid,
        toId: targetId,
        fromName: user.displayName || user.email || "Paduan",
        toName: target.displayName || "Paduan",
        participants: [user.uid, targetId],
        status: "pending",
        createdAt: firebase.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    },
    listFriendRequests: async user => {
      const snapshot = await db.collection("friendRequests")
        .where("participants", "array-contains", user.uid)
        .limit(50)
        .get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }))
        .filter(request => request.toId === user.uid && request.status === "pending");
    },
    listOutgoingFriendRequests: async user => {
      const snapshot = await db.collection("friendRequests")
        .where("participants", "array-contains", user.uid)
        .limit(50)
        .get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }))
        .filter(request => request.fromId === user.uid && request.status === "pending");
    },
    respondToFriendRequest: async (requestId, status) => {
      if (!["accepted", "rejected"].includes(status)) throw new Error("Invalid friend request response.");
      await db.collection("friendRequests").doc(requestId).update({ status });
    },
    removeFriend: requestId => db.collection("friendRequests").doc(requestId).delete(),
    listFriends: async user => {
      const snapshot = await db.collection("friendRequests")
        .where("participants", "array-contains", user.uid)
        .limit(100)
        .get();
      return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })).filter(friend => friend.status === "accepted");
    }
  };
})();
