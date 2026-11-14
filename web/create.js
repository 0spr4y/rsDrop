const KEY_BYTE_LENGTH = 32;
const NONCE_BYTE_LENGTH = 12; // AES-GCM standard nonce length
const GCM_TAG_BYTE_LENGTH = 16;
// Must match MAX_ENCRYPTED_SIZE on the server (ciphertext + nonce).
const MAX_ENCRYPTED_BYTES = 640 * 1024;
const MAX_PLAINTEXT_BYTES = MAX_ENCRYPTED_BYTES - NONCE_BYTE_LENGTH - GCM_TAG_BYTE_LENGTH;

const form = document.getElementById('shareForm');
const contentInput = document.getElementById('content');
const sizeMeta = document.getElementById('sizeMeta');
const submitButton = document.getElementById('submitButton');
const statusLine = document.getElementById('status');
const resultCard = document.getElementById('result');
const shareLink = document.getElementById('shareLink');
const copyButton = document.getElementById('copyButton');
const openLink = document.getElementById('openLink');

function arrayBufferToBase64(buffer) {
    return window.btoa(Array.from(new Uint8Array(buffer), (byte) => String.fromCharCode(byte)).join(''));
}

// URL-safe, unpadded Base64: survives being pasted into chat apps and emails intact.
function arrayBufferToBase64Url(buffer) {
    return arrayBufferToBase64(buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// The AES key is the SHA-256 of the random key material carried in the link fragment.
async function deriveKey(fragmentKeyBytes) {
    const hashedKey = await window.crypto.subtle.digest('SHA-256', fragmentKeyBytes);
    return window.crypto.subtle.importKey('raw', hashedKey, { name: 'AES-GCM' }, false, ['encrypt']);
}

// The create token, when the server requires one, is carried in this page's URL fragment: /#TOKEN
function createToken() {
    return window.location.hash.substring(1);
}

// With a token required but none supplied, the stylesheet shows only "Create token required".
function syncTokenState() {
    document.body.classList.toggle('has-token', createToken() !== '');
}

function setStatus(message, kind) {
    statusLine.textContent = message;
    statusLine.classList.toggle('is-error', kind === 'error');
    statusLine.classList.toggle('is-ok', kind === 'ok');
}

function updateSize() {
    const bytes = new TextEncoder().encode(contentInput.value).length;
    const over = bytes > MAX_PLAINTEXT_BYTES;
    sizeMeta.textContent = `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KB / 640 KB · expires after 60 minutes`;
    sizeMeta.classList.toggle('is-over', over);
    return { bytes, over };
}

async function createEncryptedShare(event) {
    event.preventDefault();
    resultCard.classList.add('is-hidden');

    const { bytes, over } = updateSize();
    if (bytes === 0) {
        setStatus('Nothing to encrypt yet.', 'error');
        return;
    }
    if (over) {
        setStatus('That is too large. The limit is 640 KB.', 'error');
        return;
    }
    if (!window.crypto || !window.crypto.subtle) {
        setStatus('This browser only allows encryption on HTTPS (or localhost). Open this page over HTTPS.', 'error');
        return;
    }

    submitButton.disabled = true;
    try {
        setStatus('Encrypting...');
        const fragmentKeyBytes = window.crypto.getRandomValues(new Uint8Array(KEY_BYTE_LENGTH));
        const aesKey = await deriveKey(fragmentKeyBytes);
        const nonceBytes = window.crypto.getRandomValues(new Uint8Array(NONCE_BYTE_LENGTH));
        const encryptedDataBytes = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonceBytes },
            aesKey,
            new TextEncoder().encode(contentInput.value)
        );

        setStatus('Uploading ciphertext...');
        const response = await fetch('/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Create-Token': createToken()
            },
            body: JSON.stringify({
                encrypted_data_b64: arrayBufferToBase64(encryptedDataBytes),
                nonce_b64: arrayBufferToBase64(nonceBytes)
            }),
        });
        if (!response.ok) {
            throw new Error((await response.text()) || `Server error ${response.status}`);
        }
        const shareId = (await response.json()).share_id;
        if (!shareId) {
            throw new Error('Server did not return a share ID.');
        }

        const shareUrl = `${window.location.origin}/s/${shareId}#${arrayBufferToBase64Url(fragmentKeyBytes)}`;
        shareLink.value = shareUrl;
        openLink.href = shareUrl;
        copyButton.textContent = 'Copy';
        resultCard.classList.remove('is-hidden');
        contentInput.value = '';
        updateSize();
        setStatus('Done. Encrypted in your browser; keep the full link private.', 'ok');
        shareLink.focus();
        shareLink.select();
    } catch (error) {
        console.error('Encryption/creation error:', error);
        setStatus(error.message, 'error');
    } finally {
        submitButton.disabled = false;
    }
}

async function copyShareLink() {
    try {
        await navigator.clipboard.writeText(shareLink.value);
        copyButton.textContent = 'Copied';
    } catch (error) {
        // Clipboard access can be refused; leave the link selected for a manual copy.
        shareLink.focus();
        shareLink.select();
        copyButton.textContent = 'Press Ctrl+C';
    }
}

syncTokenState();
updateSize();
window.addEventListener('hashchange', syncTokenState);
contentInput.addEventListener('input', updateSize);
form.addEventListener('submit', createEncryptedShare);
copyButton.addEventListener('click', copyShareLink);
shareLink.addEventListener('focus', () => shareLink.select());
