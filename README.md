# Cryptonomicon Heuristic Cipher Identifier (`cryptonomicon.py`)
> “Stop guessing what the ciphertext **might** be—let the heuristics tell you what it **probably** is.”

---

## 1  What this script does
`cryptonomicon.py` inspects an **unknown blob of bytes** and ranks which encryption / encipherment method most likely produced it.  
It combines:

* **Statistical tests** – Shannon entropy, index‑of‑coincidence, cosine similarity to English.
* **Structural clues** – block‑size alignment, repeating blocks, PEM / "Salted__" headers, IV + tag length patterns, XTS zero sectors, etc.
* **Quick classical‑cipher brute force** – Caesar, Affine and Vigenère (1‑6‑character keys) with automatic English‑fitness scoring.

The result is a score table and a one‑line “Heuristics Likeliest” summary.  
A commented‑out stub is ready for forwarding that answer to an LLM via **`llamaApiConnector`** once you enable it.

---

## 2  Requirements

| Package           | Why                               | Install                         |
|-------------------|-----------------------------------|---------------------------------|
| **Python 3.8 +**  | language runtime                  | already on most systems         |
| **NumPy**         | fast vector math (cosine distance)| `pip install numpy`             |

Everything else is from the standard library.

---

## 3  Quick‑start

# help
python cryptonomicon.py -h

3.1  Analyse a ciphertext file

python cryptonomicon.py -f secret.bin
# ➜ Heuristics Likeliest: AES‑CBC

3.2  Analyse a literal string

python cryptonomicon.py -s "WKH UHSXEOLF VKDOO..."      # Caesar demo

3.3  Base64‑encoded input

python cryptonomicon.py -f dump.b64 -b64

3.4  See the detective work (--debug)

python cryptonomicon.py -s "RC'B XENA..." --debug

3.5  Show zero‑scores too (--all)

python cryptonomicon.py -s "hello" --all

4  How the scoring works

    Containers & headers – PEM, “Salted__”, etc.

    Length tests – 128‑bit vs 64‑bit block alignment clues.

    Entropy

        H < 5.5 → bias toward classical ciphers

        H > 7.5 → bias toward modern / stream / OTP ciphers

        H > 7.9 & no repeated 16‑byte blocks → extra votes for ChaCha20 / RC4 / Salsa20

    Repeating blocks – strong evidence for ECB / DES.

    Classical extras – I.o.C, trigram repeats, plus live trial decryptions.

    Structure signatures – GCM (12|cipher|16), XTS zero sector, “nonce”, “tag”, etc.

Each rule adds +1 to that method’s score.
choose_best_cipher() breaks ties by favouring modern block ciphers, then RC4, else reports the tie.
5  Extending / hacking

    New heuristics: add a helper in Scorer and call it from analyse().

    New cipher names: list them in enc_scores so they appear in the output.

    Enable the LLM hand‑off: uncomment the last line and provide your own llamaApiConnector.

6  Limitations & caveats

    Heuristics are probabilistic—small samples or crafted ciphertext can fool them.

    Classical brute force tries only very short Vigenère keys and no hill‑climbing.

    Exotic block modes (e.g. Camellia‑GCM) may masquerade as AES.

    “LLM determination” is currently disabled; integrate at your own risk.

7  Example session

# random data → likely stream cipher
head -c 128 /dev/urandom | base64 > rnd.b64
python cryptonomicon.py -f rnd.b64 -b64
# ➜ Heuristics Likeliest: ChaCha20, RC4 (tied)

# OpenSSL salt header → AES‑CBC
echo "U2FsdGVkX19mZedU..." | python cryptonomicon.py -s -b64
# ➜ Heuristics Likeliest: AES‑CBC

8  Suggested directory layout

Task Scheduler/
└─ Cryptonomicon/
   ├─ cryptonomicon.py
   ├─ README.md          ← this file
   └─ samples/
       ├─ classic_caesar.txt
       └─ openssl_aes.bin
       
# LLM Integration
I left this commented out if anyone wants to run the program natively. While this program is not comprehensive
My idea was to utilyze LLM technology to fill in some of those gaps 

To enable LLM's 

First Download Ollama (https://ollama.com/download) && download a model through the ollama interface
Build yourself an API interface (https://ollama.com/blog/openai-compatibility)
and edit line 343 in main to reflect your API name.
You will need to prompt engineer the AI to give you the exact anwer your looking for but this can be done through chatgpt if needed.

9  License & author

MIT License

Copyright (c) 2025 Leonard Meredith
