#!/usr/bin/env python3

#import llamaApiConnector
import argparse
import base64
import binascii
import collections
import math
import re
import sys
from pathlib import Path
import numpy as np
from itertools import cycle

HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
LETTERS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SMALL_SAMPLE = 64
MIN_CLASSICAL = 10

enc_scores = {
    "AES-CBC": 0, "AES-ECB": 0, "AES-GCM": 0, "ChaCha20": 0,
    "DES-ECB": 0, "3DES-CBC": 0, "Blowfish": 0, "RC4": 0,
    "RSA": 0,
    "Vigenere": 0, "Hill": 0, "Playfair": 0,
    "Caesar": 0, "Affine": 0, "Simple Substitution": 0,
    "Rail Fence": 0, "Columnar Transposition": 0,
    "One-Time Pad": 0,
    "XTS-AES": 0, "Salsa20": 0, "Camellia": 0, "SM4": 0
}

ALL_METHODS = list(enc_scores.keys())

def choose_best_cipher(score_dict):
    """
    Choose the best cipher based on scores. If tied, favor modern ciphers with block clues over classical ones.
    """
    if not score_dict:
        return "No clues detected."

    sorted_scores = sorted(score_dict.items(), key=lambda x: -x[1])
    top_score = sorted_scores[0][1]
    top_ciphers = [cipher for cipher, score in sorted_scores if score == top_score]

    if len(top_ciphers) == 1:
        return f"Most likely: {top_ciphers[0]} (score={top_score})"

    block_ciphers = {
        "AES-CBC", "AES-GCM", "AES-ECB", "XTS-AES",
        "DES-ECB", "3DES-CBC", "Blowfish", "Camellia", "SM4"
    }
    for cipher in top_ciphers:
        if cipher in block_ciphers:
            return f"Most likely: {cipher} (score={top_score}, favored for block alignment)"

    if "RC4" in top_ciphers:
        return f"Most likely: RC4 (score={top_score}, stream pattern match)"

    return f"Tie between: {', '.join(top_ciphers)} (score={top_score})"

def modinv(a, m):
    """Modular inverse for affine cipher"""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def decrypt_caesar(text):
    """Returns list of (shift, decrypted_bytes) for all Caesar shifts"""
    results = []
    for shift in range(26):
        decrypted = bytes(((b - 65 - shift) % 26) + 65 if 65 <= b <= 90 else b for b in text)
        results.append((shift, decrypted))
    return results

def decrypt_affine(text):
    """Returns list of ((a, b), decrypted_bytes) for all valid affine parameters"""
    results = []
    valid_a = [a for a in range(1, 26, 2) if math.gcd(a, 26) == 1]
    for a in valid_a:
        a_inv = modinv(a, 26)
        for b in range(26):
            decrypted = bytes(((a_inv * ((c - 65 - b)) % 26) + 65) if 65 <= c <= 90 else c for c in text)
            results.append(((a, b), decrypted))
    return results

def decrypt_vigenere(text, max_key_len=6):
    """Returns list of ((key_shifts), decrypted_bytes) guesses for small key lengths"""
    candidates = []
    for keylen in range(1, max_key_len + 1):
        key = []
        for i in range(keylen):
            segment = [c for j, c in enumerate(text) if j % keylen == i]
            best_shift = 0
            best_dist = 1.0
            for s in range(26):
                shifted = bytes(((b - 65 - s) % 26) + 65 for b in segment)
                dist = cosine_similarity_to_english(shifted)
                if dist < best_dist:
                    best_dist = dist
                    best_shift = s
            key.append(best_shift)
        full_key = cycle(key)
        decrypted = bytes(((b - 65 - next(full_key)) % 26) + 65 if 65 <= b <= 90 else b for b in text)
        candidates.append((tuple(key), decrypted))
    return candidates

def add_clue(method: str, reason: str = "", scores: dict = enc_scores):
    scores[method] = scores.get(method, 0) + 1
    return f"{method} +1: {reason}"

def best_guess(scores: dict = enc_scores, top_n: int = 1):
    if not scores:
        return None
    max_score = max(scores.values())
    tied = [m for m, v in scores.items() if v == max_score]
    return tied[:top_n] if top_n else tied

def smart_decode(raw: bytes) -> bytes:
    s = raw.strip()
    if HEX_RE.fullmatch(s.decode("ascii", "ignore")):
        try:
            return binascii.unhexlify(s)
        except binascii.Error:
            pass
    return raw

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())

def index_of_coincidence(text: bytes) -> float:
    if len(text) < 2:
        return 0.0
    freq = collections.Counter(text)
    n = len(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

def repeating_blocks(data: bytes, block_len: int) -> bool:
    if len(data) < 2 * block_len:
        return False
    blocks = [data[i : i + block_len] for i in range(0, len(data), block_len)]
    return len(blocks) != len(set(blocks))

def cosine_similarity_to_english(byte_data: bytes) -> float:
    ENGLISH_FREQ = np.array([
        8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
        6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
        0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
        1.974, 0.074
    ])
    ENGLISH_FREQ /= ENGLISH_FREQ.sum()

    text = [b for b in byte_data.upper() if 65 <= b <= 90]
    if not text:
        return 0.0
    obs = np.zeros(26)
    for b in text:
        obs[b - 65] += 1
    obs /= np.sum(obs)

    # manually compute cosine similarity instead of using scipy
    dot_product = np.dot(ENGLISH_FREQ, obs)
    norm_product = np.linalg.norm(ENGLISH_FREQ) * np.linalg.norm(obs)
    return 1 - (dot_product / norm_product if norm_product != 0 else 0.0)

class Scorer:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logs = []

    def _log(self, msg: str):
        self.logs.append(msg)
        if self.verbose:
            print("[DEBUG]", msg)

    def _add(self, method: str, reason: str = ""):
        if method in enc_scores:
            log = add_clue(method, reason)
            self._log(log)

    def _container(self, text: str):
        if re.search(r"-----BEGIN (?:RSA|.*PUBLIC KEY|PGP MESSAGE)", text):
            self._add("RSA", "Found PEM-like public key header")
        if text.startswith("Salted__"):
            self._add("AES-CBC", "Starts with 'Salted__' – OpenSSL pattern")

    def _length(self, n: int):
        if n % 16 == 0:
            for m in ("AES-CBC", "AES-GCM", "AES-ECB", "XTS-AES"):
                self._add(m, "Length divisible by 16 (128-bit block)")
        if n % 8 == 0 and n % 16 != 0:
            for m in ("DES-ECB", "3DES-CBC", "Blowfish", "Camellia", "SM4"):
                self._add(m, "Length divisible by 8 (64-bit block only)")

    def _randomness(self, data: bytes):
        h = shannon_entropy(data)
        self._log(f"Entropy: {h:.4f} for {len(data)} bytes")

        if len(data) >= 24 and h > 4.5:
            self._add("RC4", f"Moderate entropy stream-like pattern: {h:.2f}")

        if h > 7.9 and not repeating_blocks(data, 16):
            for m in ("ChaCha20", "RC4", "Salsa20"):
                self._add(m, f"Very high entropy and no block repetition: {h:.2f}")
        if h > 7.5:
            for m in ("AES-CBC", "AES-GCM", "ChaCha20", "RC4", "One-Time Pad", "Salsa20", "Camellia", "XTS-AES"):
                self._add(m, f"High entropy: {h:.2f}")
        elif h < 5.5 and len(data) >= MIN_CLASSICAL:
            for m in ("Caesar", "Affine", "Simple Substitution", "Vigenere",
                      "Hill", "Playfair", "Rail Fence", "Columnar Transposition"):
                self._add(m, f"Low entropy: {h:.2f}")

    def _block_patterns(self, data: bytes):
        if repeating_blocks(data, 16):
            self._add("AES-ECB", "Detected repeating 16-byte blocks")
        if repeating_blocks(data, 8):
            self._add("DES-ECB", "Detected repeating 8-byte blocks")

    def _decrypt_classicals(self, data: bytes):
        letters = bytes([b for b in data.upper() if b in LETTERS])
        if len(letters) < MIN_CLASSICAL:
            return

        results = []

        for shift, dec in decrypt_caesar(letters):
            dist = cosine_similarity_to_english(dec)
            results.append((f"Caesar (shift={shift})", dec, dist))

        for (a, b), dec in decrypt_affine(letters):
            dist = cosine_similarity_to_english(dec)
            results.append((f"Affine (a={a}, b={b})", dec, dist))

        for key, dec in decrypt_vigenere(letters):
            dist = cosine_similarity_to_english(dec)
            keystr = ",".join(str(k) for k in key)
            results.append((f"Vigenère (shifts={keystr})", dec, dist))

        if results:
            results.sort(key=lambda x: x[2])  # sort by cosine distance
            print("\n[Top Classical Decryptions]:")
            for method, dec, score in results[:3]:  # show top 3
                print(f"\n{method} (cosine distance={score:.3f}):")
                print(dec.decode('ascii', 'ignore'))

    def _classical(self, data: bytes):
        letters = bytes([b for b in data.upper() if b in LETTERS])
        if len(letters) < MIN_CLASSICAL:
            return

        ioc = index_of_coincidence(letters)
        sim = cosine_similarity_to_english(letters)
        self._log(f"Index of Coincidence: {ioc:.4f}, Cosine similarity: {sim:.4f}")

        if ioc > 0.058:
            if sim > 0.95:
                self._add("Caesar", "High I.o.C. and cosine similarity")
            elif sim > 0.85:
                self._add("Affine", "High I.o.C. and moderate cosine similarity")
            else:
                self._add("Simple Substitution", "High I.o.C. but low similarity")

        trigrams = [letters[i:i + 3] for i in range(len(letters) - 2)]
        dupes = len(trigrams) - len(set(trigrams))
        if dupes >= 2:
            for m in ("Caesar", "Affine", "Simple Substitution", "Vigenere"):
                self._add(m, f"{dupes} repeated trigrams")

        self._decrypt_classicals(data)

    def _structure_signatures(self, data: bytes):
        if len(data) >= 28:
            if len(data) % 16 == 12:
                self._add("AES-GCM", "Possible GCM structure (12-byte IV + ciphertext + 16-byte tag)")

        if len(data) >= 32:
            if b"nonce" in data.lower():
                self._add("Salsa20", "Detected 'nonce' reference, possible Salsa20 structure")
            if b"tag" in data.lower() or b"auth" in data.lower():
                self._add("AES-GCM", "Contains 'tag' or 'auth' keywords")

        if len(data) >= 16 and data[:4] == b"\x00\x00\x00\x00":
            self._add("XTS-AES", "Leading zero sector pattern suggests AES-XTS")

    def analyse(self, data: bytes):
        view = data.decode("ascii", "ignore")
        self._container(view)
        self._length(len(data))
        self._randomness(data)
        self._block_patterns(data)
        self._classical(data)
        self._structure_signatures(data)

    def get_logs(self):
        return self.logs


def main():
    """Heuristic cipher identifier – prints scores once, clues only with --debug."""
    ap = argparse.ArgumentParser(description="Heuristic cipher identifier (scores only, no duplicates)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-f", "--file", help="Path to ciphertext file")
    src.add_argument("-s", "--string", help="Ciphertext given directly")
    ap.add_argument("-b64", action="store_true", help="Input is Base64; decode first")

    ap.add_argument("--all", action="store_true", help="Show zero‑scores too")
    ap.add_argument("--debug", action="store_true", help="Show heuristic clue logs (once)")
    args = ap.parse_args()

    # --- Load & decode input ---
    raw = Path(args.file).read_bytes() if args.file else args.string.encode()
    if args.b64:
        try:
            raw = base64.b64decode(raw, validate=True)
        except Exception as e:
            sys.exit(f"Base64 decode failed: {e}")

    data = smart_decode(raw)

    # Analyse (always collect logs, never print during analysis)
    scorer = Scorer(verbose=False)
    scorer.analyse(data)

    # --- Display scores (single pass) ---
    print("Heuristics Likeliest:", ", ".join(best_guess()) or "(no strong candidate)")


    # --- Optional debug clues (printed once) ---
    if args.debug:
        print("\n--- DEBUG LOG ---")
        for log in scorer.get_logs():
            print(log)
        print("\n--- CLUES ---")
        for cipher, score in enc_scores.items():
            if score > 0 or args.all:
                print(f"{cipher}: {score}")

    print("\n--- FINAL LLM DETERMINATION ---")
    print("Currently this feature is disabled, Please read the read me for more information!")
    #print(llamaApiConnector.connector(choose_best_cipher(enc_scores), "qwen2.5-coder:32b"))

if __name__ == "__main__":
    main()
