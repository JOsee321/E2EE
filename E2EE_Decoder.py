#!/usr/bin/env python3
"""
=====================================================================
 E2EE v2.0 - Smart Automated Decoder & Identifier + Encoder
=====================================================================
Tool CLI untuk kebutuhan Penetration Testing & CTF (Capture The Flag).

Changelog v2.0:
    [FIX]  Bug: Base64 panjang sering salah terdeteksi sebagai Caesar
           Cipher. Root cause: heuristik lama (`looks_like_alpha_text`)
           menganggap SEMUA string yang mayoritas hurufnya alfabet
           sebagai "kandidat Caesar", padahal Base64/Hex yang GAGAL
           divalidasi sebagai teks (karena hasil decode-nya bukan UTF-8
           valid) juga mayoritas alfabet. Fix: deteksi Caesar SEKARANG
           wajib menunggu seluruh DECODER_PIPELINE benar-benar mentok
           (tidak ada layer berhasil di-decode SAMA SEKALI), DAN wajib
           ada whitespace/struktur kata (Caesar klasik selalu menyisakan
           spasi asli, sedangkan Base64/Hex selalu 1 token tanpa spasi).
    [NEW]  Decoder baru: Binary-to-String & Decimal Escape.
    [NEW]  Hash Online Lookup (OSINT) via urllib.request -- opt-in,
           ada disclaimer OPSEC, default NONAKTIF.
    [NEW]  Smart Encoder Mode (Payload Builder): Base64/Hex/URL/HTML,
           lewat argumen CLI (--encode) atau menu interaktif.

Fitur dari v1 yang dipertahankan:
    - Smart Recursive Decoding (HTML Entity, URL, Hex, Base32, Base64)
    - Hash Identifier (MD5, SHA-1/224/256/384/512, bcrypt, MD5-Crypt)
    - Caesar Cipher Brute Force (25 shift)
    - Mendukung input manual (input()) maupun pipe (stdin)
    - Hanya modul bawaan Python (sys, re, base64, urllib, html, json, argparse)
    - Banner ASCII Art "E2EE" + warna ANSI
    - Validasi UTF-8 strict di safe_bytes_to_text -> anti-crash
=====================================================================
"""

import sys
import re
import json
import html
import base64
import argparse
import urllib.parse
import urllib.request
import urllib.error


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
    """Cetak banner ASCII Art besar 'E2EE' (gaya block/slant) + info versi."""
    banner = r"""
     ___________  ___________   ____   ____
    / ____/__  / / / ____/ ___/ / __ \ / __ \
   / __/    / / / / __/  \__ \ / / / // / / /
  / /___   / /_/ / /___  ___/ // /_/ // /_/ /
 /_____/  /_____/_____/ /____(_)____(_)____/
"""
    print(Colors.BLUE + Colors.BOLD + banner + Colors.RESET)
    title = "Smart Automated Decoder & Identifier  |  v2.0"
    subtitle = "Recursive Decode + Encoder + Hash OSINT  -- by Jose"
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
    supaya data biner acak (digest hash, potongan file biner, dll) TIDAK
    salah dikira plaintext valid.

    Validasi 2 lapis:
        1. Decode HARUS valid UTF-8 strict (TANPA fallback ke latin-1,
           karena latin-1 nyaris selalu "berhasil" walau isinya sampah --
           itu sumber bug false-positive di versi sebelumnya).
        2. Dari teks yang lolos UTF-8, hitung rasio karakter printable
           ASCII (kode 32-126) + whitespace umum. Di bawah threshold ->
           tetap ditolak (anggap bukan teks valid).

    Return:
        str  -> kalau hasil dianggap teks valid.
        None -> kalau hasil dianggap sampah/biner (gagal validasi).
    """
    if not raw:
        return None

    try:
        text = raw.decode("utf-8")  # strict, no latin-1 fallback
    except UnicodeDecodeError:
        return None

    if not text:
        return None

    printable_count = sum(1 for c in text if (32 <= ord(c) <= 126) or c in "\n\t\r")
    ratio = printable_count / len(text)

    return text if ratio >= printable_threshold else None


# =====================================================================
# 4. MODUL DECODER -- masing-masing return None kalau pattern tidak
#    cocok ATAU hasil decode-nya gagal divalidasi (lihat safe_bytes_to_text)
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


def try_binary_decode(text: str):
    """
    [BARU v2.0] Decode deretan bilangan biner (hanya '0' & '1') jadi teks.
    Mendukung 2 format:
        - Rapat : 0100100001100101011011000110110001101111
        - Spasi : 01001000 01100101 01101100 01101100 01101111
    Setiap 8 bit dianggap 1 byte/karakter -> wajib kelipatan 8.
    """
    cleaned = re.sub(r"\s+", "", text)
    if re.fullmatch(r"[01]+", cleaned) and len(cleaned) % 8 == 0 and len(cleaned) >= 8:
        try:
            byte_values = [int(cleaned[i:i + 8], 2) for i in range(0, len(cleaned), 8)]
            raw = bytes(byte_values)
        except (ValueError, OverflowError):
            return None
        return safe_bytes_to_text(raw)
    return None


def try_decimal_decode(text: str):
    """
    [BARU v2.0] Decode deretan angka desimal ASCII, misal:
        "72 101 108 108 111" -> "Hello"
    Aturan: setiap token harus angka 0-255 (1 byte valid), dipisah
    spasi/koma, dan minimal 3 token (menghindari salah tebak angka biasa).
    Kalau tidak ada pemisah whitespace/koma sama sekali, fungsi ini
    langsung mundur (None) supaya tidak rebutan pattern dengan Hex Decode.
    """
    candidate = text.strip()
    if not re.search(r"[\s,]", candidate):
        return None

    tokens = [t for t in re.split(r"[\s,]+", candidate) if t]
    if len(tokens) < 3:
        return None
    if not all(re.fullmatch(r"\d{1,3}", t) for t in tokens):
        return None

    try:
        values = [int(t) for t in tokens]
    except ValueError:
        return None
    if not all(0 <= v <= 255 for v in values):
        return None

    return safe_bytes_to_text(bytes(values))


def try_hex_decode(text: str):
    """
    Decode Hexadecimal, mendukung 3 format:
        - Rapat : 48656c6c6f
        - Spasi : 48 65 6c 6c 6f
        - \\x    : \\x48\\x65\\x6c\\x6c\\x6f
    """
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


# Urutan pipeline penting:
#   1. HTML/URL dulu (pattern '&...;' dan '%XX' sangat spesifik, jarang
#      salah tebak).
#   2. Binary & Decimal sebelum Hex -- karena charset '01' dan digit
#      desimal adalah SUBSET dari charset Hex, jadi kalau Hex dicoba
#      lebih dulu dia bisa "mencuri" pattern yang sebenarnya Binary/Desimal.
#   3. Hex, baru Base32, baru Base64 (charset Base64 paling "longgar"
#      jadi paling akhir supaya tidak salah tebak duluan).
DECODER_PIPELINE = [
    ("HTML Entity Decode", try_html_entity_decode),
    ("URL Decode", try_url_decode),
    ("Binary Decode", try_binary_decode),
    ("Decimal Escape Decode", try_decimal_decode),
    ("Hex Decode", try_hex_decode),
    ("Base32 Decode", try_base32_decode),
    ("Base64 Decode", try_base64_decode),
]


# =====================================================================
# 5. SMART RECURSIVE DECODER (otak utama tool ini)
# =====================================================================
def smart_recursive_decode(input_text: str, max_layers: int = 14):
    """
    Coba kupas encoding berlapis-lapis secara rekursif/loop sampai BENAR-
    BENAR MENTOK (tidak ada decoder manapun di DECODER_PIPELINE yang bisa
    progress lagi) atau sampai max_layers tercapai (jaga-jaga anti infinite
    loop).

    INI BAGIAN PALING PENTING UNTUK BUG FIX v2.0:
    Fungsi ini TIDAK PERNAH memanggil identify_hash() atau caesar_bruteforce()
    di tengah jalan. Ia hanya mengembalikan (final_text, history) setelah
    pipeline selesai total. Keputusan "ini hash / ini caesar / ini plaintext"
    SEPENUHNYA didelegasikan ke caller (lihat analyze_decode_and_identify),
    yang baru dipanggil SETELAH proses ini berhenti. Dengan begitu, Caesar
    Cipher tidak akan pernah dievaluasi di atas teks yang masih "setengah
    decode" atau yang sebenarnya satu layer encoding yang gagal divalidasi.
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
            break  # pipeline benar-benar mentok -> baru boleh lanjut ke identifikasi

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
    Return label hash (str) kalau cocok, None kalau tidak ada yang cocok.
    """
    candidate = text.strip()
    for pattern, label in HASH_PATTERNS:
        if pattern.match(candidate):
            return label
    return None


# =====================================================================
# 7. HASH ONLINE LOOKUP (OSINT) -- urllib.request, opt-in, ada disclaimer
# =====================================================================
def _lookup_md5_gromweb(md5_hash: str) -> dict:
    """
    Reverse-lookup MD5 ke md5.gromweb.com -- endpoint publik, TANPA API
    key, berbasis dictionary/rainbow-table (jadi hanya berhasil untuk hash
    dari kata/password umum, bukan "membongkar" MD5 secara matematis).

    CATATAN JUJUR: ini endpoint pihak ketiga yang tidak resmi/tidak
    didokumentasikan -> treat sebagai best-effort OSINT, BUKAN sumber
    otoritatif. Kalau formatnya berubah di masa depan, fungsi ini akan
    gagal dengan rapi (return found=False), tidak crash.
    """
    url = "https://md5.gromweb.com/?method=lookup&hash=" + urllib.parse.quote(md5_hash)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (E2EE-CTF-Tool)"})

    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as e:
        return {"found": False, "error": f"Gagal menghubungi layanan lookup ({e})"}
    except Exception as e:  # jaga-jaga: jangan pernah crash gara-gara network call
        return {"found": False, "error": f"Error tak terduga saat lookup ({e})"}

    match = re.search(r"<string>(.*?)</string>", body, re.DOTALL)
    if match:
        return {"found": True, "plaintext": html.unescape(match.group(1).strip())}
    return {"found": False, "error": "Hash tidak ditemukan di database publik"}


def _lookup_hash_placeholder(hash_value: str, hash_label: str) -> dict:
    """
    [MOCK / PLACEHOLDER] Untuk SHA-1/SHA-256/dst, TIDAK ADA API publik
    keyless yang reliable (layanan seperti md5decrypt.net atau hashes.com
    mewajibkan API key/akun -- lihat komentar di bawah). Fungsi ini
    menunjukkan STRUKTUR kode standar untuk integrasi API berbayar
    tersebut, supaya Anda bisa lihat alur OSINT-nya, meskipun endpoint di
    bawah ini bukan endpoint sungguhan (sengaja memakai domain contoh).

    Cara pakai sungguhan: daftar API key gratis/berbayar di salah satu
    layanan berikut, lalu ganti 2 konstanta di bawah:
        - https://md5decrypt.net/en/Api/   (butuh API key gratis via email)
        - https://hashes.com/en/docs       (butuh API key)
    """
    PLACEHOLDER_API_URL = "https://api.example-hashdb.local/v1/lookup"  # << GANTI dengan endpoint asli
    PLACEHOLDER_API_KEY = "ISI_API_KEY_ANDA_DI_SINI"                    # << GANTI dengan API key Anda

    query = urllib.parse.urlencode({
        "hash": hash_value,
        "hash_type": hash_label,
        "api_key": PLACEHOLDER_API_KEY,
    })
    url = f"{PLACEHOLDER_API_URL}?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": "E2EE-CTF-Tool"})

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw_body = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw_body)
        if data.get("found"):
            return {"found": True, "plaintext": data.get("plaintext", "")}
        return {"found": False, "error": "Hash tidak ditemukan (sesuai struktur response placeholder)"}
    except Exception as e:
        # Endpoint contoh ini memang tidak benar-benar aktif -> selalu akan
        # mendarat di sini. Itu DISENGAJA: fokusnya menunjukkan struktur kode
        # request+parsing+error-handling yang aman, bukan koneksi nyata.
        return {
            "found": False,
            "error": (
                f"Mode placeholder (endpoint contoh, bukan API aktif): {e}. "
                "Ganti PLACEHOLDER_API_URL & PLACEHOLDER_API_KEY dengan API key "
                "layanan reverse-hash sungguhan untuk hash selain MD5."
            ),
        }


def lookup_hash_online(hash_value: str, hash_label: str) -> dict:
    """
    Router: pilih backend lookup sesuai jenis hash.
    Return dict: {"found": bool, "plaintext": str} atau {"found": False, "error": str}
    """
    if "md5" in hash_label.lower():
        return _lookup_md5_gromweb(hash_value)
    return _lookup_hash_placeholder(hash_value, hash_label)


def maybe_lookup_hash(hash_value: str, hash_label: str, online_lookup_enabled: bool, interactive: bool) -> None:
    """
    Gerbang (gate) sebelum benar-benar mengirim data ke layanan pihak
    ketiga.

    >>> CATATAN OPSEC (penting buat pentest profesional) <<<
    Mengirim hash milik klien/target ke layanan pihak ketiga di internet
    BISA melanggar Rules of Engagement / NDA, karena data (walau "cuma"
    hash) keluar dari lingkup yang disepakati. Makanya fitur ini:
        - NONAKTIF secara default.
        - Hanya jalan otomatis kalau eksplisit diaktifkan lewat flag
          `--online-lookup` saat menjalankan script.
        - Di mode interaktif tanpa flag tersebut, tool akan TANYA dulu
          (konfirmasi y/N) sebelum mengirim apa pun ke internet.
        - Di mode pipe tanpa flag, lookup di-skip total (tidak ada
          input() yang bisa nge-block/crash karena stdin sudah dipakai).
    """
    if online_lookup_enabled:
        do_lookup = True
    elif interactive:
        print(Colors.YELLOW + "    [OPSEC] Online lookup akan mengirim hash ini ke layanan pihak ketiga." + Colors.RESET)
        try:
            choice = input(Colors.YELLOW + "    Lanjutkan lookup online? (y/N): " + Colors.RESET).strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "n"
        do_lookup = choice == "y"
    else:
        print(Colors.GREY + "    [i] Online lookup nonaktif di mode pipe. Pakai flag --online-lookup untuk mengaktifkan." + Colors.RESET)
        return

    if not do_lookup:
        return

    print(Colors.CYAN + f"    [*] Query ke layanan reverse-lookup untuk {hash_label}..." + Colors.RESET)
    result = lookup_hash_online(hash_value, hash_label)
    if result.get("found"):
        print(Colors.GREEN + f"    [+] DITEMUKAN! Plaintext kemungkinan: {result['plaintext']}" + Colors.RESET)
    else:
        print(Colors.YELLOW + f"    [!] Tidak ditemukan/gagal: {result.get('error', 'unknown error')}" + Colors.RESET)


# =====================================================================
# 8. CAESAR CIPHER BRUTE FORCE
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
            result_chars.append(char)
    return "".join(result_chars)


def looks_like_classic_cipher_text(text: str) -> bool:
    """
    [FIX BUG v2.0] Heuristik "ini kandidat Caesar Cipher, bukan encoding
    yang gagal divalidasi".

    Versi lama hanya cek "mayoritas karakternya huruf" -> Base64/Hex
    panjang yang GAGAL didecode (karena hasil bytes-nya bukan UTF-8 valid)
    juga mayoritas huruf, jadi false-positive dianggap Caesar.

    Fix: WAJIB ada whitespace di dalam teks. Caesar Cipher klasik hanya
    menggeser huruf dan SELALU membiarkan spasi/struktur kata apa adanya
    -> ciphertext-nya selalu terlihat seperti "kata-kata terpisah spasi".
    Base64/Hex/Base32 sebaliknya SELALU satu token utuh tanpa spasi sama
    sekali. Dengan syarat whitespace ini, string Base64 panjang otomatis
    gugur dari kandidat Caesar.
    """
    candidate = text.strip()
    if len(candidate) < 3:
        return False
    if not re.search(r"\s", candidate):
        return False  # satu token tanpa spasi -> kemungkinan besar encoded data, bukan Caesar

    alpha_count = sum(1 for c in candidate if c.isalpha())
    return (alpha_count / len(candidate)) > 0.6


def caesar_bruteforce(text: str) -> None:
    """Cetak ke-25 kemungkinan hasil Caesar Cipher (shift 1-25)."""
    print(Colors.YELLOW + "[!] Pola menyerupai teks alfabet berstruktur kata (kemungkinan Classic/Caesar Cipher)." + Colors.RESET)
    print(Colors.YELLOW + "[+] Menjalankan Brute Force 25 kemungkinan shift...\n" + Colors.RESET)
    for shift in range(1, 26):
        shifted = caesar_shift(text, shift)
        print(f"  {Colors.GREY}Shift {shift:>2}:{Colors.RESET} {shifted}")
    print()


# =====================================================================
# 9. SMART ENCODER MODE (Payload Builder untuk bypass WAF)
# =====================================================================
def encode_text(text: str, method: str):
    """Encode 'text' dengan satu metode spesifik. Return None kalau method tidak dikenal."""
    method = method.lower()
    if method in ("base64", "b64"):
        return base64.b64encode(text.encode("utf-8")).decode()
    if method == "hex":
        return text.encode("utf-8").hex()
    if method in ("url", "urlencode"):
        return urllib.parse.quote(text, safe="")
    if method in ("html", "htmlentity"):
        return html.escape(text)
    return None


ENCODE_METHODS = ["base64", "hex", "url", "html"]


def encode_text_all(text: str) -> dict:
    """Encode 'text' dengan SEMUA metode yang didukung -> dict {method: hasil}."""
    return {method: encode_text(text, method) for method in ENCODE_METHODS}


def print_encode_results(text: str, results: dict) -> None:
    print(Colors.BLUE + f"[*] Plaintext : {text}" + Colors.RESET)
    for method, value in results.items():
        print(Colors.GREEN + f"[+] {method.upper():<6}: {value}" + Colors.RESET)
    print()


def handle_encode_interactive(text: str) -> None:
    """Dipanggil dari loop interaktif saat mode == 'encode'. Tampilkan SEMUA
    varian encoding sekaligus -- cocok untuk eksplorasi payload bypass WAF
    (tinggal pilih mana yang paling mungkin lolos filter target)."""
    print_encode_results(text, encode_text_all(text))


def run_encode_cli(text: str, method: str) -> None:
    """Mode one-shot lewat argumen CLI: `--encode "<text>" --method base64`."""
    if method == "all":
        print_encode_results(text, encode_text_all(text))
    else:
        result = encode_text(text, method)
        print_encode_results(text, {method: result})


# =====================================================================
# 10. PRESENTASI / ORKESTRATOR ANALISIS DECODE
# =====================================================================
def print_decode_flow(history: list) -> None:
    """Cetak visualisasi alur decode, contoh:
    [+] Alur: URL Decode -> Hex Decode -> Base64 Decode
    """
    flow = " -> ".join(history)
    print(Colors.GREEN + f"[+] Alur: {flow}" + Colors.RESET)


def analyze_decode_and_identify(raw_input: str, interactive: bool, online_lookup_enabled: bool) -> None:
    """
    Orkestrator utama mode decode. URUTAN EKSEKUSI (ini inti bug fix v2.0):

        1. Jalankan smart_recursive_decode() SAMPAI TUNTAS (pipeline mentok).
        2. BARU setelah itu, evaluasi hasil akhirnya:
             a. Cek identify_hash() dulu (selalu dicek, baik ada layer
                decode atau tidak -- misal hash yang dibungkus Base64).
             b. Kalau bukan hash DAN tidak ada satupun layer yang berhasil
                di-decode (history kosong) DAN pola-nya menyerupai teks
                Caesar (looks_like_classic_cipher_text) -> jalankan brute
                force Caesar.
             c. Kalau tidak masuk kategori manapun -> beri tahu user
                dengan jelas, tidak dipaksakan jadi salah satu kategori.

    Caesar TIDAK PERNAH dievaluasi selama pipeline masih berhasil mengubah
    teks (history non-empty) -- sesuai requirement: jangan tebak Caesar di
    atas hasil decoding yang masih "berjalan/berhasil mengubah teks".
    """
    if not raw_input or not raw_input.strip():
        print(Colors.RED + "[!] Input kosong, dilewati." + Colors.RESET)
        return

    print(Colors.BLUE + f"[*] Input  : {raw_input.strip()}" + Colors.RESET)

    # --- Tahap 1: kupas semua layer encoding sampai benar-benar mentok ---
    final_text, history = smart_recursive_decode(raw_input)

    if history:
        print_decode_flow(history)
        print(Colors.GREEN + f"[+] Hasil Akhir: {final_text}" + Colors.RESET)
    else:
        print(Colors.CYAN + "[i] Tidak ada layer encoding (HTML/URL/Binary/Decimal/Hex/Base32/Base64) yang terdeteksi." + Colors.RESET)

    # --- Tahap 2: identifikasi hasil akhir (HANYA setelah pipeline mentok) ---
    hash_label = identify_hash(final_text)

    if hash_label:
        layer_note = " (ditemukan setelah dikupas beberapa layer)" if history else ""
        print(Colors.YELLOW + f"[!] Terdeteksi format Hash{layer_note}: {hash_label}" + Colors.RESET)
        maybe_lookup_hash(final_text.strip(), hash_label, online_lookup_enabled, interactive)

    elif not history and looks_like_classic_cipher_text(final_text):
        # Caesar HANYA dicek kalau: (1) tidak ada satupun decoder yang
        # progress (history kosong) -- supaya tidak "menabrak" hasil decode
        # yang masih berjalan/berubah, DAN (2) pola-nya benar memenuhi
        # struktur Caesar (ada spasi, bukan token tunggal seperti Base64).
        caesar_bruteforce(final_text)

    else:
        print(Colors.GREY + "[i] Tidak teridentifikasi sebagai hash atau cipher klasik dikenal." + Colors.RESET)
        print(Colors.GREY + "    Kemungkinan: plaintext asli, data terenkripsi, atau random string." + Colors.RESET)

    print(Colors.BLUE + "-" * 58 + Colors.RESET + "\n")


# =====================================================================
# 11. ENTRY POINT -- Interaktif vs Pipe, Decode-mode vs Encode-mode
# =====================================================================
def choose_mode_interactively() -> str:
    """Menu awal saat mode interaktif: pilih Decoder atau Encoder."""
    print(Colors.CYAN + "Pilih Mode:" + Colors.RESET)
    print("  [1] Smart Decoder & Identifier  (default)")
    print("  [2] Smart Encoder / Payload Builder")
    choice = input(Colors.BOLD + "Pilihan (1/2, Enter=1): " + Colors.RESET).strip()
    return "encode" if choice == "2" else "decode"


def run_interactive_mode(online_lookup_enabled: bool) -> None:
    """
    Mode interaktif: tampilkan banner, lalu loop minta input dari user.
    User bisa ketik 'mode' kapan saja untuk berpindah antara mode Decode
    <-> Encode tanpa harus restart tool.
    """
    print_banner()
    mode = choose_mode_interactively()
    print()
    print(Colors.GREY + "Perintah: 'mode' = ganti mode decode/encode | 'exit' / 'quit' = keluar\n" + Colors.RESET)

    while True:
        prompt_label = "E2EE[decode]> " if mode == "decode" else "E2EE[encode]> "
        try:
            user_input = input(Colors.BOLD + prompt_label + Colors.RESET).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n" + Colors.RED + "[!] Keluar." + Colors.RESET)
            break

        low = user_input.lower()
        if low in ("exit", "quit", "q"):
            print(Colors.RED + "[!] Sampai jumpa." + Colors.RESET)
            break
        if low in ("mode", "switch", "m"):
            mode = "encode" if mode == "decode" else "decode"
            print(Colors.CYAN + f"[i] Mode beralih ke: {mode}\n" + Colors.RESET)
            continue
        if not user_input:
            continue

        if mode == "decode":
            analyze_decode_and_identify(user_input, interactive=True, online_lookup_enabled=online_lookup_enabled)
        else:
            handle_encode_interactive(user_input)


def run_pipe_mode(online_lookup_enabled: bool) -> None:
    """
    Mode piping: baca seluruh stdin (tanpa banner/prompt input()), proses
    baris demi baris. Cocok untuk dirantai dengan tool pentest lain:
        cat hash.txt | python3 e2ee_decoder.py
        echo "<base64_string>" | python3 e2ee_decoder.py --online-lookup
    Mode ini selalu jalan sebagai Decoder (encode lewat pipe pakai flag
    --encode, lihat main()).
    """
    data = sys.stdin.read()
    lines = [line for line in data.splitlines() if line.strip()]

    if not lines:
        print(Colors.RED + "[!] Tidak ada data yang diterima dari stdin." + Colors.RESET)
        return

    for line in lines:
        analyze_decode_and_identify(line, interactive=False, online_lookup_enabled=online_lookup_enabled)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="e2ee_decoder.py",
        description="E2EE v2.0 - Smart Automated Decoder & Identifier + Encoder (Pentest/CTF tool).",
    )
    parser.add_argument(
        "-e", "--encode", metavar="TEXT",
        help="Mode one-shot: encode TEXT lalu langsung keluar (tidak masuk mode interaktif).",
    )
    parser.add_argument(
        "-m", "--method", choices=ENCODE_METHODS + ["all"], default="all",
        help="Metode encoding yang dipakai bersama --encode (default: all = tampilkan semua varian).",
    )
    parser.add_argument(
        "--online-lookup", action="store_true",
        help="Izinkan tool mengirim hash terdeteksi ke layanan reverse-lookup pihak ketiga. "
             "Default nonaktif demi OPSEC -- lihat komentar di maybe_lookup_hash().",
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()

    # --encode tersedia sebagai mode one-shot, bisa dipakai baik di terminal
    # interaktif maupun lewat pipe -- tidak butuh banner/menu sama sekali.
    if args.encode is not None:
        run_encode_cli(args.encode, args.method)
        return

    # sys.stdin.isatty() == True  -> dijalankan langsung di terminal (interaktif)
    # sys.stdin.isatty() == False -> menerima data dari pipe/redirect
    if sys.stdin.isatty():
        run_interactive_mode(online_lookup_enabled=args.online_lookup)
    else:
        run_pipe_mode(online_lookup_enabled=args.online_lookup)


if __name__ == "__main__":
    main()