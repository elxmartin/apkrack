/**
 * Decrypts OpenSSL AES-256-CBC encrypted, Gzip-compressed base64 payloads
 */
async function fetchAndDecryptReport(reportUrl, passphrase) {
    const response = await fetch(`${reportUrl}?t=${Date.now()}`, { cache: 'no-store' });
    if (!response.ok) {
        throw new Error(`Report binary not found (${response.status} ${response.statusText}).`);
    }

    const base64Str = await response.text();
    const cleanBase64 = base64Str.replace(/\s+/g, '');

    let rawBinary;
    try {
        rawBinary = Uint8Array.from(atob(cleanBase64), c => c.charCodeAt(0));
    } catch (e) {
        throw new Error("Failed to decode Base64 payload. File might be corrupted.");
    }

    if (rawBinary.length < 16) {
        throw new Error("Payload size too short for valid OpenSSL container.");
    }

    // Check OpenSSL "Salted__" magic header
    const magic = new TextDecoder().decode(rawBinary.subarray(0, 8));
    if (magic !== "Salted__") {
        throw new Error("Invalid payload: Missing OpenSSL 'Salted__' magic header.");
    }

    const salt = rawBinary.subarray(8, 16);
    const ciphertext = rawBinary.subarray(16);

    const enc = new TextEncoder();
    const passKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(passphrase),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    // Derive 256-bit Key + 128-bit IV (384 bits total) via SHA-256 PBKDF2 (100k iterations)
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        passKey,
        384
    );

    const keyBytes = derivedBits.slice(0, 32);
    const ivBytes = derivedBits.slice(32, 48);

    const aesKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
    );

    let decryptedGzipBuffer;
    try {
        decryptedGzipBuffer = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv: ivBytes },
            aesKey,
            ciphertext
        );
    } catch (err) {
        throw new Error("Decryption failed. Invalid passphrase or corrupted data.");
    }

    // Decompress Gzip Stream safely using Response stream wrapping
    try {
        const gzipBlob = new Blob([decryptedGzipBuffer]);
        const decompressedStream = gzipBlob.stream().pipeThrough(new DecompressionStream('gzip'));
        const decompressedBuffer = await new Response(decompressedStream).arrayBuffer();
        return new TextDecoder().decode(decompressedBuffer);
    } catch (gzipErr) {
        // Fallback for raw text uncompressed payloads
        return new TextDecoder().decode(decryptedGzipBuffer);
    }
}