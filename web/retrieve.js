const KEY_BYTE_LENGTH = 32; // Must match creation
const NONCE_BYTE_LENGTH = 12; // Must match creation

const contentBox = document.getElementById('pasteContent');
const statusLine = document.getElementById('status');
const copyButton = document.getElementById('copyButton');

function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Accepts URL-safe or standard Base64, with or without padding.
function base64UrlToArrayBuffer(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    return base64ToArrayBuffer(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
}

// The AES key is the SHA-256 of the random key material carried in the link fragment.
async function deriveKey(fragmentKeyBytes) {
    const hashedKey = await window.crypto.subtle.digest('SHA-256', fragmentKeyBytes);
    return window.crypto.subtle.importKey('raw', hashedKey, { name: 'AES-GCM' }, false, ['decrypt']);
}

function setStatus(message, kind) {
    statusLine.textContent = message;
    statusLine.classList.toggle('is-error', kind === 'error');
    statusLine.classList.toggle('is-ok', kind === 'ok');
}

async function getAndDecryptPaste() {
    try {
        const pathParts = window.location.pathname.split('/');
        const pasteId = pathParts[pathParts.length - 1];
        const fragmentKeyB64 = window.location.hash.substring(1);

        if (!pasteId) {
            throw new Error('This link has no secret ID. Check that you copied the whole link.');
        }
        if (!fragmentKeyB64) {
            throw new Error('The decryption key (the part after #) is missing from the link.');
        }
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('This browser only allows decryption on HTTPS (or localhost). Open this link over HTTPS.');
        }

        let fragmentKeyBytes;
        try {
            fragmentKeyBytes = base64UrlToArrayBuffer(fragmentKeyB64);
        } catch (e) {
            fragmentKeyBytes = null;
        }
        if (!fragmentKeyBytes || fragmentKeyBytes.byteLength !== KEY_BYTE_LENGTH) {
            throw new Error('The decryption key in the link is corrupted or incomplete.');
        }
        const aesKey = await deriveKey(fragmentKeyBytes);

        // Drop the key from the address bar and this history entry now that it has been read.
        window.history.replaceState(null, '', window.location.pathname);

        setStatus('Fetching ciphertext...');
        const response = await fetch(`/api/paste/${encodeURIComponent(pasteId)}`);
        if (response.status === 404 || response.status === 400) {
            throw new Error('Secret not found. It may have expired, or the link is incorrect.');
        }
        if (!response.ok) {
            throw new Error(`Server error ${response.status}`);
        }
        const responseData = await response.json();

        const encryptedDataBytes = base64ToArrayBuffer(responseData.encrypted_data_b64);
        const nonceBytes = base64ToArrayBuffer(responseData.nonce_b64);
        if (nonceBytes.byteLength !== NONCE_BYTE_LENGTH) {
            throw new Error('Received an invalid nonce from the server.');
        }

        setStatus('Decrypting...');
        let decryptedDataBytes;
        try {
            decryptedDataBytes = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonceBytes },
                aesKey,
                encryptedDataBytes
            );
        } catch (e) {
            throw new Error('Decryption failed. The key in the link is wrong, or the data was tampered with.');
        }

        contentBox.textContent = new TextDecoder().decode(decryptedDataBytes);
        contentBox.classList.remove('is-hidden');
        copyButton.classList.remove('is-hidden');
        setStatus('Decrypted in your browser.', 'ok');
    } catch (error) {
        console.error('Retrieval/decryption error:', error);
        const message = (error && typeof error.message === 'string') ? error.message : String(error ?? 'Unknown error');
        setStatus(message, 'error');
    }
}

async function copySecret() {
    try {
        await navigator.clipboard.writeText(contentBox.textContent);
        copyButton.textContent = 'Copied';
    } catch (error) {
        // Clipboard access can be refused; select the text for a manual copy.
        window.getSelection().selectAllChildren(contentBox);
        copyButton.textContent = 'Press Ctrl+C';
    }
}

copyButton.addEventListener('click', copySecret);
getAndDecryptPaste();
