# VJ Bcrypt Generator

A simple, powerful, and secure web tool to generate and verify password hashes directly in your browser.

## Live Demo
Check out the live version here: **[bcrypt.vjranga.com](https://bcrypt.vjranga.com)**

## Why I Built This?
This started as a fun, personal project because I needed a quick way to generate a couple of hashes manually for my own work. I decided to polish it up and share it so anyone can use it to generate hashes or understand how they work.

## Features
-   **Client-Side Security**: All hashing happens locally in your browser (JavaScript). No data is ever sent to a server.
-   **Multiple Algorithms**: Supports Bcrypt, Argon2id, Scrypt, PBKDF2, MD5, SHA-1, SHA-256, and SHA-512.
-   **Verify Mode**: easily check if a plain text password matches a hash.
-   **Dark Mode UI**: Clean, minimalist design.

## Usage
1.  Open `index.html` or visit the live site.
2.  **Generate**: Type text, select an algorithm, and click "Encrypt".
3.  **Verify**: Switch to the verify tab, paste a hash and the text to check if they match.

## Installation
1.  Clone or download this repository.
2.  Open `index.html` directly, or serve the folder with any static server.
3.  An internet connection is required to load CDN dependencies.

## Notes
-   Bcrypt only uses the first 72 bytes of input.

## Browser Compatibility
-   Latest Chrome, Edge, Firefox, and Safari.
-   JavaScript and Web Crypto API required.

## License
This project is licensed under the **MIT License**.
Free to use and share! Check the `LICENSE` file for details.
