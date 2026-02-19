// crypto_utils.js
async function generateKeyPairs() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-384", // P-256 is standard, P-384 offers higher security
        },
        true, // extractable
        ["deriveKey", "deriveBits"]
    );
    return keyPair;
}

async function exportPublicKey(publicKey) {
    // Export to raw ArrayBuffer so it can be sent via WebSockets
    const exportedKey = await window.crypto.subtle.exportKey(
        "raw",
        publicKey
    );
    return exportedKey;
}

async function importPublicKey(rawKeyBytes) {
    return await window.crypto.subtle.importKey(
        "raw",
        rawKeyBytes,
        { name: "ECDH", namedCurve: "P-384" },
        true,
        []
    );
}

async function deriveSharedAESKey(privateKey, importedPublicKey) {
    const sharedKey = await window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: importedPublicKey,
        },
        privateKey,
        {
            name: "AES-GCM",
            length: 256, // 256-bit AES key
        },
        false, // The shared key should NEVER be extractable
        ["encrypt", "decrypt"]
    );
    return sharedKey;
}

async function encryptMessage(text, sharedKey) {
    const encoder = new TextEncoder();
    const encodedText = encoder.encode(text);
    
    // AES-GCM requires a unique Initialization Vector for every single encryption
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); 

    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        sharedKey,
        encodedText
    );

    return { ciphertext, iv };
}

async function decryptMessage(ciphertext, iv, sharedKey) {
    const decryptedBytes = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        sharedKey,
        ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBytes);
}