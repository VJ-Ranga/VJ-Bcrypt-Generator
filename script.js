document.addEventListener('DOMContentLoaded', () => {
    // --- Tabs ---
    const tabBtns = document.querySelectorAll('.tab-btn');
    const sections = document.querySelectorAll('.content-section');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all
            tabBtns.forEach(b => b.classList.remove('active'));
            sections.forEach(s => s.classList.add('hidden'));

            // Activate clicked
            btn.classList.add('active');
            const tabId = btn.dataset.tab;
            document.getElementById(tabId + 'Section').classList.remove('hidden');
        });
    });

    // --- Generate Section ---
    const passwordInput = document.getElementById('passwordInput');

    const algoSelector = document.getElementById('algoSelector');
    const bcryptOptions = document.getElementById('bcryptOptions');
    const roundsInput = document.getElementById('rounds');
    const roundsValue = document.getElementById('roundsValue');

    // Argon2 Options
    const argon2Options = document.getElementById('argon2Options');
    const argon2MemoryInput = document.getElementById('argon2Memory');
    const argon2MemoryValue = document.getElementById('argon2MemoryValue');
    const argon2IterationsSelect = document.getElementById('argon2Iterations');

    // Scrypt Options
    const scryptOptions = document.getElementById('scryptOptions');
    const scryptCostInput = document.getElementById('scryptCost');
    const scryptCostValue = document.getElementById('scryptCostValue');

    // PBKDF2 Options
    const pbkdf2Options = document.getElementById('pbkdf2Options');
    const pbkdf2IterationsSelect = document.getElementById('pbkdf2Iterations');
    const pbkdf2IterationsValue = document.getElementById('pbkdf2IterationsValue');
    const pbkdf2KeySizeSelect = document.getElementById('pbkdf2KeySize');
    const pbkdf2KeySizeValue = document.getElementById('pbkdf2KeySizeValue');

    const generateBtn = document.getElementById('generateBtn');

    const outputGroup = document.getElementById('outputGroup');
    const hashOutput = document.getElementById('hashOutput');
    const copyBtn = document.getElementById('copyBtn');
    const statusMsg = document.getElementById('statusMsg');

    let currentAlgo = 'bcrypt';

    // Algorithm Selection
    algoSelector.addEventListener('click', (e) => {
        const chip = e.target.closest('.chip');
        if (!chip) return;

        // UI Update
        document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');

        // Logic Update
        currentAlgo = chip.dataset.algo;

        // Show/Hide Options
        bcryptOptions.classList.add('hidden');
        argon2Options.classList.add('hidden');
        scryptOptions.classList.add('hidden');
        pbkdf2Options.classList.add('hidden');

        if (currentAlgo === 'bcrypt') {
            bcryptOptions.classList.remove('hidden');
        } else if (currentAlgo === 'argon2id') {
            argon2Options.classList.remove('hidden');
        } else if (currentAlgo === 'scrypt') {
            scryptOptions.classList.remove('hidden');
        } else if (currentAlgo === 'pbkdf2') {
            pbkdf2Options.classList.remove('hidden');
        }
    });

    // Rounds Value Update
    roundsInput.addEventListener('input', (e) => {
        roundsValue.textContent = e.target.value;
    });

    // Argon2 Value Updates
    argon2MemoryInput.addEventListener('input', (e) => {
        argon2MemoryValue.textContent = e.target.value;
    });
    // Iterations is now a select, no realtime value update needed for label

    // Scrypt Value Updates
    scryptCostInput.addEventListener('input', (e) => {
        scryptCostValue.textContent = e.target.value;
    });

    // PBKDF2 Value Updates
    pbkdf2IterationsSelect.addEventListener('change', (e) => {
        pbkdf2IterationsValue.textContent = parseInt(e.target.value).toLocaleString();
    });
    pbkdf2KeySizeSelect.addEventListener('change', (e) => {
        pbkdf2KeySizeValue.textContent = e.target.value;
    });

    // Rate Limiting
    let lastGenerateTime = 0;
    const COOLDOWN_MS = 1000;

    // Generate Hash
    generateBtn.addEventListener('click', () => {
        const password = passwordInput.value;
        if (!password) {
            showStatus(statusMsg, 'Please enter text to hash', 'error');
            return;
        }

        // Rate Limit Check
        const now = Date.now();
        if (now - lastGenerateTime < COOLDOWN_MS) {
            showStatus(statusMsg, 'Please wait a moment...', 'error');
            return;
        }
        lastGenerateTime = now;

        // Warnings
        if (password.length > 128) {
            showStatus(statusMsg, 'Warning: Password clipped to 128 chars', 'error');
            // actually input maxlength handles this, but good for paste checking if we wanted to be strict
        }
        if (currentAlgo === 'bcrypt' && new TextEncoder().encode(password).length > 72) {
            showStatus(statusMsg, 'Note: Bcrypt truncates to 72 bytes', 'error');
            // Allow proceed, but warn
        }


        // Prevent spamming
        setLoading(generateBtn, true);
        outputGroup.classList.remove('visible'); // Reset animation

        // Use a Promise to handle both Sync and Async algorithms
        new Promise((resolve, reject) => {
            // Small delay for UI "heaviness"
            setTimeout(() => {
                try {
                    if (currentAlgo === 'argon2id') {
                        // Argon2id is Async
                        const salt = window.crypto.getRandomValues(new Uint8Array(16));
                        // Ensure window.argon2 is available (fix for "argon2 is not defined")
                        const argon2Lib = window.argon2;
                        if (!argon2Lib) throw new Error("Argon2 library not loaded");

                        argon2Lib.hash({
                            pass: password,
                            salt: salt,
                            type: argon2Lib.ArgonType.Argon2id,
                            mem: parseInt(argon2MemoryInput.value),
                            time: parseInt(argon2IterationsSelect.value),
                            parallelism: 1,
                            hashLen: 32
                        })
                            .then(h => resolve(h.encoded))
                            .catch(reject);

                    } else if (currentAlgo === 'scrypt') {
                        // Scrypt is Async
                        const passwordBuffer = new TextEncoder().encode(password);
                        const salt = window.crypto.getRandomValues(new Uint8Array(16));
                        const N = parseInt(scryptCostInput.value);
                        const r = 8;
                        const p = 1;
                        const dkLen = 64;

                        scrypt.scrypt(passwordBuffer, salt, N, r, p, dkLen)
                            .then(derivedKey => {
                                // Scrypt-js returns raw bytes (Uint8Array). We need to format it strictly.
                                // There isn't a standard "modular crypt format" for scrypt in widespread use like bcrypt/argon2 strings.
                                // Common convention: N$r$p$salt_hex$hash_hex or just hex(hash).
                                // For this tool, let's output a hex string of the derived key to keep it simple and verifiable.
                                const hex = Array.from(derivedKey).map(b => b.toString(16).padStart(2, '0')).join('');
                                resolve(hex);
                            })
                            .catch(reject);

                    } else if (currentAlgo === 'pbkdf2') {
                        // PBKDF2 (CryptoJS)
                        const salt = CryptoJS.lib.WordArray.random(128 / 8);
                        const iterations = parseInt(pbkdf2IterationsSelect.value);
                        const keySize = parseInt(pbkdf2KeySizeSelect.value) / 32; // CryptoJS keySize is in 32-bit words

                        const derivedKey = CryptoJS.PBKDF2(password, salt, {
                            keySize: keySize,
                            iterations: iterations
                        });
                        // Standard output: salt + hash? Or just hash? 
                        // Let's output the Hex string of the derived key.
                        resolve(derivedKey.toString(CryptoJS.enc.Hex));

                    } else {
                        // Sync Algorithms
                        let hash = '';
                        switch (currentAlgo) {
                            case 'bcrypt':
                                const salt = dcodeIO.bcrypt.genSaltSync(parseInt(roundsInput.value));
                                hash = dcodeIO.bcrypt.hashSync(password, salt);
                                break;
                            case 'md5':
                                hash = CryptoJS.MD5(password).toString();
                                break;
                            case 'sha1':
                                hash = CryptoJS.SHA1(password).toString();
                                break;
                            case 'sha256':
                                hash = CryptoJS.SHA256(password).toString();
                                break;
                            case 'sha512':
                                hash = CryptoJS.SHA512(password).toString();
                                break;
                        }
                        resolve(hash);
                    }
                } catch (err) {
                    reject(err);
                }
            }, 300);
        })
            .then(hash => {
                hashOutput.value = hash;
                outputGroup.classList.remove('hidden');
                void outputGroup.offsetWidth; // Force Reflow
                outputGroup.classList.add('visible');
                showStatus(statusMsg, 'Hash generated successfully!', 'success');
            })
            .catch(err => {
                console.error(err);
                showStatus(statusMsg, 'Error generating hash: ' + err.message, 'error');
            })
            .finally(() => {
                setLoading(generateBtn, false);
            });
    });

    // Copy to Clipboard
    copyBtn.addEventListener('click', () => {
        if (!hashOutput.value) return;
        copyToClipboard(hashOutput.value, statusMsg);
    });

    // --- Verify Section ---
    const verifyHashInput = document.getElementById('verifyHashInput');
    const verifyPasswordInput = document.getElementById('verifyPasswordInput');

    const verifyBtn = document.getElementById('verifyBtn');
    const verifyStatusMsg = document.getElementById('verifyStatusMsg');

    // Verify Algorithm Selection
    const verifyAlgoSelector = document.getElementById('verifyAlgoSelector');
    let currentVerifyAlgo = 'bcrypt';

    verifyAlgoSelector.addEventListener('click', (e) => {
        const chip = e.target.closest('.chip');
        if (!chip) return;

        // UI Update
        document.querySelectorAll('#verifyAlgoSelector .chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');

        // Logic Update
        currentVerifyAlgo = chip.dataset.algo;
    });

    verifyBtn.addEventListener('click', () => {
        const hash = verifyHashInput.value.trim();
        const password = verifyPasswordInput.value;

        if (!hash || !password) {
            showStatus(verifyStatusMsg, 'Please enter both hash and text', 'error');
            return;
        }

        setLoading(verifyBtn, true);

        // Small delay for consistency
        new Promise((resolve, reject) => {
            setTimeout(() => {
                try {
                    // Strict format checking based on selected algorithm
                    if (currentVerifyAlgo === 'bcrypt') {
                        // Bcrypt Check - must start with $2
                        if (!hash.startsWith('$2a$') && !hash.startsWith('$2b$') && !hash.startsWith('$2y$')) {
                            reject(new Error('Invalid Bcrypt hash format. Expected hash starting with $2a$, $2b$, or $2y$'));
                            return;
                        }
                        const isMatch = dcodeIO.bcrypt.compareSync(password, hash);
                        resolve(isMatch);
                    } else if (currentVerifyAlgo === 'md5') {
                        // MD5 - 32 hex chars
                        if (!/^[a-f0-9]{32}$/i.test(hash)) {
                            reject(new Error('Invalid MD5 hash format. Expected 32 hexadecimal characters'));
                            return;
                        }
                        const computed = CryptoJS.MD5(password).toString();
                        resolve(computed.toLowerCase() === hash.toLowerCase());
                    } else if (currentVerifyAlgo === 'sha1') {
                        // SHA1 - 40 hex chars
                        if (!/^[a-f0-9]{40}$/i.test(hash)) {
                            reject(new Error('Invalid SHA1 hash format. Expected 40 hexadecimal characters'));
                            return;
                        }
                        const computed = CryptoJS.SHA1(password).toString();
                        resolve(computed.toLowerCase() === hash.toLowerCase());
                    } else if (currentVerifyAlgo === 'sha256') {
                        // SHA256 - 64 hex chars
                        if (!/^[a-f0-9]{64}$/i.test(hash)) {
                            reject(new Error('Invalid SHA256 hash format. Expected 64 hexadecimal characters'));
                            return;
                        }
                        const computed = CryptoJS.SHA256(password).toString();
                        resolve(computed.toLowerCase() === hash.toLowerCase());
                    } else if (currentVerifyAlgo === 'sha512') {
                        // SHA512 - 128 hex chars
                        if (!/^[a-f0-9]{128}$/i.test(hash)) {
                            reject(new Error('Invalid SHA512 hash format. Expected 128 hexadecimal characters'));
                            return;
                        }
                        const computed = CryptoJS.SHA512(password).toString();
                        resolve(computed.toLowerCase() === hash.toLowerCase());
                    } else {
                        reject(new Error('Unsupported verification algorithm'));
                    }
                } catch (err) {
                    reject(err);
                }
            }, 300);
        })
            .then(isMatch => {
                if (isMatch) {
                    showStatus(verifyStatusMsg, 'Success! Text matches the hash.', 'success');
                } else {
                    showStatus(verifyStatusMsg, 'Failed! Text does not match.', 'error');
                }
            })
            .catch(err => {
                console.error(err);
                showStatus(verifyStatusMsg, 'Invalid hash format or error', 'error');
            })
            .finally(() => {
                setLoading(verifyBtn, false);
            });
    });

    // --- Accordion Logic ---
    const accordions = document.querySelectorAll('.accordion-header');

    accordions.forEach(acc => {
        acc.addEventListener('click', () => {
            // Toggle active class
            acc.classList.toggle('active');

            // Toggle panel
            const panel = acc.nextElementSibling;
            if (panel.style.maxHeight) {
                panel.style.maxHeight = null;
            } else {
                panel.style.maxHeight = panel.scrollHeight + "px";
            }
        });
    });

    // --- Utils ---

    function setLoading(btn, isLoading) {
        if (isLoading) {
            const originalText = btn.innerHTML;
            btn.dataset.originalText = originalText;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing...';
            btn.disabled = true;
            btn.style.opacity = '0.7';
            btn.style.cursor = 'not-allowed';
        } else {
            if (btn.dataset.originalText) {
                btn.innerHTML = btn.dataset.originalText;
            }
            btn.disabled = false;
            btn.style.opacity = '1';
            btn.style.cursor = 'pointer';
        }
    }

    function showStatus(element, msg, type) {
        element.textContent = msg;
        element.className = 'status-msg ' + (type === 'error' ? 'status-error' : 'status-success');

        // Clear after 3 sec
        setTimeout(() => {
            if (element.textContent === msg) {
                element.textContent = '';
                element.className = 'status-msg';
            }
        }, 3000);
    }

    function copyToClipboard(text, statusElement) {
        navigator.clipboard.writeText(text).then(() => {
            showStatus(statusElement, 'Copied to clipboard!', 'success');
        }).catch(() => {
            // Fallback
            const textArea = document.createElement("textarea");
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand("Copy");
            textArea.remove();
            showStatus(statusElement, 'Copied to clipboard!', 'success');
        });
    }
});
