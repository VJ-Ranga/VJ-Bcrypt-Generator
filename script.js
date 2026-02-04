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

        // Show/Hide Bcrypt Options
        if (currentAlgo === 'bcrypt') {
            bcryptOptions.classList.remove('hidden');
        } else {
            bcryptOptions.classList.add('hidden');
        }
    });

    // Rounds Value Update
    roundsInput.addEventListener('input', (e) => {
        roundsValue.textContent = e.target.value;
    });

    // Generate Hash
    generateBtn.addEventListener('click', () => {
        const password = passwordInput.value;
        if (!password) {
            showStatus(statusMsg, 'Please enter text to hash', 'error');
            return;
        }

        // Prevent spamming
        setLoading(generateBtn, true);
        outputGroup.classList.remove('visible'); // Reset animation

        // Small delay to allow UI to update and feel "heavy"
        setTimeout(() => {
            let hash = '';
            try {
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

                hashOutput.value = hash;
                outputGroup.classList.remove('hidden');
                void outputGroup.offsetWidth; // Force Reflow
                outputGroup.classList.add('visible');
                showStatus(statusMsg, 'Hash generated successfully!', 'success');

            } catch (err) {
                console.error(err);
                showStatus(statusMsg, 'Error generating hash', 'error');
            } finally {
                setLoading(generateBtn, false);
            }
        }, 300); // 300ms aesthetic delay
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

    verifyBtn.addEventListener('click', () => {
        const hash = verifyHashInput.value.trim();
        const password = verifyPasswordInput.value;

        if (!hash || !password) {
            showStatus(verifyStatusMsg, 'Please enter both hash and text', 'error');
            return;
        }

        setLoading(verifyBtn, true);

        setTimeout(() => {
            try {
                let isMatch = false;

                // Auto-detect format basics
                if (hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$')) {
                    // Bcrypt
                    isMatch = dcodeIO.bcrypt.compareSync(password, hash);
                } else {
                    // Simple comparison for plain hashes
                    const candidates = [
                        CryptoJS.MD5(password).toString(),
                        CryptoJS.SHA1(password).toString(),
                        CryptoJS.SHA256(password).toString(),
                        CryptoJS.SHA512(password).toString()
                    ];

                    isMatch = candidates.includes(hash.toLowerCase());
                }

                if (isMatch) {
                    showStatus(verifyStatusMsg, 'Success! Text matches the hash.', 'success');
                } else {
                    showStatus(verifyStatusMsg, 'Failed! Text does not match.', 'error');
                }

            } catch (err) {
                console.error(err);
                showStatus(verifyStatusMsg, 'Invalid hash format or error', 'error');
            } finally {
                setLoading(verifyBtn, false);
            }
        }, 300);
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
