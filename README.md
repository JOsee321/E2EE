# E2EE - Smart Automated Decoder & Identifier

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg)

One tool, every decode. Paste in any text - Base64, Hex, Binary, URL Encoded, even multiple layers stacked together - and E2EE automatically peels it back to plaintext, while recognizing hashes and classic ciphers along the way.

Built for **CTF** and **Penetration Testing** workflows, 100% Python standard library - no `pip install` required.

```
     ___________  ___________   ____   ____
    / ____/__  / / / ____/ ___/ / __ \ / __ \
   / __/    / / / / __/  \__ \ / / / // / / /
  / /___   / /_/ / /___  ___/ // /_/ // /_/ /
 /_____/  /_____/_____/ /____(_)____(_)____/

      Smart Automated Decoder & Identifier  |  v2.0
```

---

## Features

- **Recursive Auto-Decode** - Peels back multi-layer encoding in a single run (e.g. `URL -> Base64 -> Hex -> plaintext`), stopping automatically once it hits plaintext.
- **7 Encoding Formats** - HTML Entity, URL Encoding, Binary (`0`/`1`), Decimal ASCII (`72 101 108...`), Hexadecimal (compact / spaced / `\x`), Base32, Base64 (including URL-safe variant).
- **Hash Identifier** - Automatically detects MD5, SHA-1, SHA-224/256/384/512, bcrypt, and MD5-Crypt based on length patterns and regex.
- **Hash OSINT Lookup** (opt-in) - Reverse-lookup hashes against public databases via `urllib.request`. Disabled by default to protect client/target data (see [OPSEC Note](#opsec-note)).
- **Caesar Cipher Brute Force** - Automatically tries all 25 possible shifts when a classic cipher pattern is detected.
- **Smart Encoder / Payload Builder** - Encode text into Base64, Hex, URL, or HTML Entity for WAF bypass experimentation.
- **Pipe-friendly** - Chain it with other pentest tools via `stdin`/`stdout`.
- **Crash-resistant** - Strict UTF-8 validation at every decode step; won't blow up when it hits random binary data.
- ASCII art banner and ANSI-colored output, with zero external dependencies.

---

## Installation

No installation required beyond Python 3.

```bash
git clone https://github.com/JOsee321/E2EE.git
cd E2EE
python E2EE_Decoder.py
```

**Requirements:** Python 3.7+ (uses only built-in modules: `sys`, `re`, `json`, `html`, `base64`, `argparse`, `urllib`).

---

## Usage

### 1. Interactive Mode

```bash
python E2EE_Decoder.py
```

The banner appears, then choose `[1] Decoder` or `[2] Encoder`. Type `mode` at any time to switch, `exit` to quit.

### 2. Pipe Mode (chaining with other tools)

```bash
echo "NDY0YzQxNDc3YjZkNzU2Yzc0Njk1ZjZjNjE3OTY1NzI1ZjY0NjU2MzZmNjQ2NTVmNzQ2NTczNzQ3ZA%3D%3D" | python E2EE_Decoder.py
```
```
[*] Input  : NDY0YzQxNDc3YjZkNzU2Yzc0Njk1ZjZjNjE3OTY1NzI1ZjY0NjU2MzZmNjQ2NTVmNzQ2NTczNzQ3ZA%3D%3D
[+] Flow: URL Decode -> Base64 Decode -> Hex Decode
[+] Final Result: FLAG{multi_layer_decode_test}
```

```bash
cat hash.txt | python E2EE_Decoder.py
```

### 3. Encoder Mode (CLI one-shot)

```bash
python E2EE_Decoder.py --encode "FLAG{test}"
```
```
[+] BASE64: RkxBR3t0ZXN0fQ==
[+] HEX   : 464c41477b746573747d
[+] URL   : FLAG%7Btest%7D
[+] HTML  : FLAG{test}
```

Or target a single method with `--method base64|hex|url|html`.

### 4. Hash OSINT Lookup (optional)

```bash
echo "5f4dcc3b5aa765d61d8327deb882cf99" | python E2EE_Decoder.py --online-lookup
```

---

## OPSEC Note

The **Hash Online Lookup** feature sends hashes to a third-party service over the internet. During an authorized pentest engagement, this **may violate the Rules of Engagement / NDA**, since data leaves the agreed-upon scope. Because of this:

- The feature is **disabled by default**.
- It only runs via the explicit `--online-lookup` flag, or manual confirmation (`y/N`) in interactive mode.
- Always confirm your engagement policy permits this before enabling it.

---

## Motivation

Most CTF decoder tools only handle one layer at a time - if the encoding is stacked, you end up decoding manually back and forth. E2EE automates that process and doubles as a "first responder" for suspicious strings: is it an encoding? a hash? a classic cipher? One tool, one run.

---

## Contributing

Pull requests and issues are welcome from anyone. Ideas for future features: Vigenere cipher, ROT47, JWT decoder, or parallel multi-encoding support.
