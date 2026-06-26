#!/usr/bin/env python3
"""
=====================================================================
 E2EE - Smart Automated Decoder & Identifier
=====================================================================
Tool CLI untuk kebutuhan Penetration Testing & CTF (Capture The Flag).

Fitur utama:
    1. Smart Recursive Decoding
       -> Base64, Base32, Hexadecimal (rapat/spasi/\\x), URL Encoding,
          HTML Entities. Dijalankan rekursif sampai mentok di plaintext.
    2. Hash Identifier (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
       bcrypt, MD5-Crypt) berdasarkan panjang karakter & pola regex.
    3. Caesar Cipher Brute Force (25 kemungkinan pergeseran).
    4. Mendukung input manual (input()) maupun input lewat pipe (stdin),
       sehingga bisa dirantai dengan tool pentest lain di terminal.

Catatan desain:
    - Hanya memakai modul bawaan Python (sys, re, base64,
      urllib.parse, html) -> tanpa dependensi eksternal.
    - Semua proses decoding dibungkus try/except + validasi printable
      ratio, sehingga tidak akan crash saat mencoba decode data biner
      yang rusak/acak.
=====================================================================
"""

import sys
import re
import base64
import urllib.parse
import html


# =====================================================================
# 1. WARNA ANSI UNTUK OUTPUT TERMINAL
# =====================================================================
class Colors:
    """Kode warna ANSI standar agar output terminal lebih profesional."""
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# =====================================================================
# 2. BANNER ASCII ART (hanya tampil saat mode interaktif, bukan piping)
# =====================================================================
def print_banner() -> None:
    """
    Cetak banner ASCII Art besar bertuliskan 'E2EE' (gaya block/slant).
    Dipanggil hanya kalau script dijalankan langsung di terminal (TTY),
    bukan saat menerima data dari pipe -> agar output piping tetap bersih.
    """
    banner = r"""
     ___________  ___________   ____   ____
    / ____/__  / / / ____/ ___/ / __ \ / __ \
   / __/    / / / / __/  \__ \ / / / // / / /
  / /___   / /_/ / /___  ___/ // /_/ // /_/ /
 /_____/  /_____/_____/ /____(_)____(_)____/
"""
    print(Colors.BLUE + Colors.BOLD + banner + Colors.RESET)
    title = "Smart Automated Decoder & Identifier"
    subtitle = "Recursive Decode | Hash ID | Caesar Bruteforce  -- by Jose"
    print(Colors.CYAN + Colors.BOLD + title.center(58) + Colors.RESET)
    print(Colors.GREY + subtitle.center(58) + Colors.RESET)
    print(Colors.BLUE + "=" * 58 + Colors.RESET)
    print()


# =====================================================================
# 3. UTILITAS: VALIDASI HASIL DECODE (ANTI-CRASH)
# =====================================================================
def safe_bytes_to_text(raw: bytes, printable_threshold: float = 0.9):
    """
    Ubah bytes hasil decode -> string dengan AMAN, sekaligus jadi "filter"
    supaya data biner acak (misal isi digest MD5/SHA, potongan file gambar)
    TIDAK salah dikira plaintext valid.

    PENTING - kenapa harus ketat:
        Python `str.isprintable()` menganggap banyak karakter Latin-1/Unicode
        (misal 'å', 'ÿ', dst) sebagai "printable", padahal kalau ini muncul
        dari hasil decode Base64/Hex acak, itu sebenarnya cuma BYTE SAMPAH,
        bukan teks asli. Makanya validasinya dibuat 2 lapis:

        1. Decode HARUS valid UTF-8 (strict, tanpa fallback ke latin-1).
           UTF-8 punya aturan continuation-byte yang ketat, sehingga data
           biner acak besar kemungkinan akan GAGAL di tahap ini -> langsung
           ditolak (return None), tidak akan terus diproses sebagai "teks".
        2. Dari teks yang lolos UTF-8, hitung rasio karakter yang benar-benar
           printable ASCII (kode 32-126) atau whitespace umum (\\n \\t \\r).
           Kalau rasionya di bawah threshold -> tetap ditolak.

    Return:
        str  -> jika hasil dianggap teks yang valid.
        None -> jika hasil dianggap sampah/biner (gagal validasi).
    """
    if not raw:
        return None

    try:
        text = raw.decode("utf-8")  # strict: TIDAK ada fallback ke latin-1
    except UnicodeDecodeError:
        return None

    if not text:
        return None

    printable_count = sum(1 for c in text if (32 <= ord(c) <= 126) or c in "\n\t\r")
    ratio = printable_count / len(text)

    return text if ratio >= printable_threshold else None


# =====================================================================
# 4. MODUL DECODER -- masing-masing return None kalau pattern tidak
#    cocok ATAU hasil decode-nya tidak valid (lihat safe_bytes_to_text)
# =====================================================================
def try_html_entity_decode(text: str):
    """Decode HTML Entities, misal '&lt;script&gt;' atau '&#65;'."""
    if re.search(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", text):
        decoded = html.unescape(text)
        if decoded != text:
            return decoded
    return None


def try_url_decode(text: str):
    """Decode URL/Percent-Encoding, misal '%20', '%41'."""
    if re.search(r"%[0-9a-fA-F]{2}", text):
        try:
            decoded = urllib.parse.unquote(text, errors="strict")
        except Exception:
            return None
        if decoded != text:
            return decoded
    return None


def try_hex_decode(text: str):
    """
    Decode Hexadecimal, mendukung 3 format:
        - Rapat : 48656c6c6f
        - Spasi : 48 65 6c 6c 6f
        - \\x    : \\x48\\x65\\x6c\\x6c\\x6f
    """
    # Normalisasi: buang prefix \x, 0x, dan semua whitespace
    cleaned = re.sub(r"\\x|0x|0X", "", text)
    cleaned = re.sub(r"\s+", "", cleaned)

    if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0 and len(cleaned) >= 4:
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError:
            return None
        return safe_bytes_to_text(raw)
    return None


def try_base32_decode(text: str):
    """Decode Base32 (alfabet A-Z2-7, opsional padding '=')."""
    candidate = text.strip().upper()
    if re.fullmatch(r"[A-Z2-7]+=*", candidate) and len(candidate) >= 8:
        padded = candidate + "=" * (-len(candidate) % 8)
        try:
            raw = base64.b32decode(padded)
        except Exception:
            return None
        return safe_bytes_to_text(raw)
    return None


def try_base64_decode(text: str):
    """Decode Base64 standar maupun varian URL-safe (-, _)."""
    candidate = text.strip()
    normalized = candidate.replace("-", "+").replace("_", "/")

    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", normalized) and len(normalized) % 4 == 0 and len(normalized) >= 4:
        try:
            raw = base64.b64decode(normalized, validate=True)
        except Exception:
            return None
        return safe_bytes_to_text(raw)
    return None


# Urutan pengecekan penting: dari yang paling spesifik/jarang
# salah-tebak (HTML/URL) -> ke yang charset-nya lebih "umum" (Base64).
DECODER_PIPELINE = [
    ("HTML Entity Decode", try_html_entity_decode),
    ("URL Decode", try_url_decode),
    ("Hex Decode", try_hex_decode),
    ("Base32 Decode", try_base32_decode),
    ("Base64 Decode", try_base64_decode),
]


# =====================================================================
# 5. SMART RECURSIVE DECODER (otak utama tool ini)
# =====================================================================
def smart_recursive_decode(input_text: str, max_layers: int = 12):
    """
    Coba kupas encoding berlapis-lapis secara rekursif/loop.

    Algoritma:
        - Di setiap iterasi, coba SEMUA decoder di DECODER_PIPELINE secara urut.
        - Begitu salah satu decoder berhasil menghasilkan string yang BERBEDA
          dan valid (lolos safe_bytes_to_text), pakai hasil itu sebagai input
          untuk iterasi selanjutnya, lalu mulai lagi dari decoder pertama.
        - Berhenti kalau: tidak ada decoder yang berhasil lagi (mentok di
          plaintext/hash/cipher), atau sudah mencapai max_layers (jaga-jaga
          supaya tidak infinite loop).

    Return:
        (final_text, history)
        final_text -> teks hasil akhir setelah semua layer dikupas
        history    -> list nama metode decode yang dipakai, urut sesuai alur
    """
    current = input_text.strip()
    history = []

    for _ in range(max_layers):
        progressed = False
        for method_name, decoder_func in DECODER_PIPELINE:
            result = decoder_func(current)
            if result is not None and result.strip() != current.strip():
                history.append(method_name)
                current = result.strip()
                progressed = True
                break  # mulai lagi dari decoder pertama untuk layer baru
        if not progressed:
            break  # tidak ada layer encoding lain yang terdeteksi -> stop

    return current, history


# =====================================================================
# 6. HASH IDENTIFIER
# =====================================================================
HASH_PATTERNS = [
    (re.compile(r"^[0-9a-fA-F]{32}$"), "MD5 atau NTLM (32 hex char)"),
    (re.compile(r"^[0-9a-fA-F]{40}$"), "SHA-1 (40 hex char)"),
    (re.compile(r"^[0-9a-fA-F]{56}$"), "SHA-224 (56 hex char)"),
    (re.compile(r"^[0-9a-fA-F]{64}$"), "SHA-256 (64 hex char)"),
    (re.compile(r"^[0-9a-fA-F]{96}$"), "SHA-384 (96 hex char)"),
    (re.compile(r"^[0-9a-fA-F]{128}$"), "SHA-512 (128 hex char)"),
    (re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$"), "bcrypt"),
    (re.compile(r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$"), "MD5-Crypt (Unix)"),
]


def identify_hash(text: str):
    """
    Cocokkan teks dengan pola panjang/format hash umum lewat regex.
    Return nama hash (str) kalau cocok, None kalau tidak ada yang cocok.
    Catatan: panjang hex yang sama bisa berarti beberapa algoritma
    berbeda (misal 32 char = MD5 ATAU NTLM) -- ini wajar di dunia nyata,
    cocok-kan dengan konteks (misal hasil dump SAM/NTDS -> NTLM).
    """
    candidate = text.strip()
    for pattern, label in HASH_PATTERNS:
        if pattern.match(candidate):
            return label
    return None


# =====================================================================
# 7. CAESAR CIPHER BRUTE FORCE
# =====================================================================
def caesar_shift(text: str, shift: int) -> str:
    """Geser setiap huruf di 'text' sejauh 'shift' posisi (A-Z/a-z saja)."""
    result_chars = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shifted = chr((ord(char) - base + shift) % 26 + base)
            result_chars.append(shifted)
        else:
            result_chars.append(char)  # spasi/simbol/angka dibiarkan apa adanya
    return "".join(result_chars)


def looks_like_alpha_text(text: str) -> bool:
    """
    Heuristik sederhana: anggap 'kandidat classic cipher' kalau mayoritas
    karakternya huruf/spasi (bukan hex-only, bukan base64-charset, dst).
    """
    candidate = text.strip()
    if len(candidate) < 3:
        return False
    alpha_count = sum(1 for c in candidate if c.isalpha())
    return (alpha_count / len(candidate)) > 0.6


def caesar_bruteforce(text: str) -> None:
    """Cetak ke-25 kemungkinan hasil Caesar Cipher (shift 1-25)."""
    print(Colors.YELLOW + "[!] Pola menyerupai teks alfabet (kemungkinan Classic/Caesar Cipher)." + Colors.RESET)
    print(Colors.YELLOW + "[+] Menjalankan Brute Force 25 kemungkinan shift...\n" + Colors.RESET)
    for shift in range(1, 26):
        shifted = caesar_shift(text, shift)
        print(f"  {Colors.GREY}Shift {shift:>2}:{Colors.RESET} {shifted}")
    print()


# =====================================================================
# 8. PRESENTASI / OUTPUT HASIL
# =====================================================================
def print_decode_flow(history: list) -> None:
    """Cetak visualisasi alur decode, contoh:
    [+] Alur: URL Decode -> Hex Decode -> Base64 Decode
    """
    flow = " -> ".join(history)
    print(Colors.GREEN + f"[+] Alur: {flow}" + Colors.RESET)


def analyze_and_print(raw_input: str) -> None:
    """
    Fungsi orkestrator: jalankan decode rekursif, lalu tampilkan hasil
    analisis (decoded text / hash terdeteksi / caesar bruteforce) dengan
    format & warna yang sesuai. Dipakai baik untuk mode interaktif maupun
    mode piping.
    """
    if not raw_input or not raw_input.strip():
        print(Colors.RED + "[!] Input kosong, dilewati." + Colors.RESET)
        return

    print(Colors.BLUE + f"[*] Input  : {raw_input.strip()}" + Colors.RESET)

    final_text, history = smart_recursive_decode(raw_input)

    if history:
        print_decode_flow(history)
        print(Colors.GREEN + f"[+] Hasil Akhir: {final_text}" + Colors.RESET)
    else:
        print(Colors.CYAN + "[i] Tidak ada layer encoding (Base64/Base32/Hex/URL/HTML) yang terdeteksi." + Colors.RESET)

    # Setelah decode mentok, cek apakah hasil akhirnya adalah Hash dikenal
    hash_label = identify_hash(final_text)
    if hash_label:
        layer_note = " (setelah dikupas beberapa layer)" if history else ""
        print(Colors.YELLOW + f"[!] Terdeteksi format Hash{layer_note}: {hash_label}" + Colors.RESET)

    # Kalau bukan hash dan tidak ada decoding sama sekali, coba cek classic cipher
    elif not history and looks_like_alpha_text(final_text):
        caesar_bruteforce(final_text)

    print(Colors.BLUE + "-" * 58 + Colors.RESET + "\n")


# =====================================================================
# 9. ENTRY POINT -- handle Input Manual (input()) vs Input Piping (stdin)
# =====================================================================
def run_interactive_mode() -> None:
    """Mode interaktif: tampilkan banner, lalu loop minta input dari user."""
    print_banner()
    print(Colors.GREY + "Ketik teks/hash yang ingin dianalisis (ketik 'exit' atau 'quit' untuk keluar)\n" + Colors.RESET)

    while True:
        try:
            user_input = input(Colors.BOLD + "E2EE> " + Colors.RESET).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n" + Colors.RED + "[!] Keluar." + Colors.RESET)
            break

        if user_input.lower() in ("exit", "quit", "q"):
            print(Colors.RED + "[!] Sampai jumpa." + Colors.RESET)
            break

        analyze_and_print(user_input)


def run_pipe_mode() -> None:
    """
    Mode piping: baca seluruh stdin (tanpa banner, tanpa prompt input()),
    lalu proses baris demi baris. Cocok dipakai seperti:
        cat hash.txt | python3 e2ee_decoder.py
        echo "<base64_string>" | python3 e2ee_decoder.py
    """
    data = sys.stdin.read()
    lines = [line for line in data.splitlines() if line.strip()]

    if not lines:
        print(Colors.RED + "[!] Tidak ada data yang diterima dari stdin." + Colors.RESET)
        return

    for line in lines:
        analyze_and_print(line)


def main() -> None:
    # sys.stdin.isatty() == True  -> dijalankan langsung di terminal (interaktif)
    # sys.stdin.isatty() == False -> menerima data dari pipe/redirect
    if sys.stdin.isatty():
        run_interactive_mode()
    else:
        run_pipe_mode()


if __name__ == "__main__":
    main()