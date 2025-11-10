ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def clean_text(s, keep_nonletters=False):
    if keep_nonletters:
        return s.upper()
    else:
        return ''.join(ch.upper() for ch in s if ch.isalpha())

# --- Vigenere Cipher ---
def vigenere_encrypt(plaintext, key):
    ciphertext = []
    key_letters = ''.join([k for k in key.upper() if k.isalpha()])
    if len(key_letters) == 0:
        raise ValueError('Vigenere key must contain letters')
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            p = ALPHABET.index(ch.upper())
            k = ALPHABET.index(key_letters[ki % len(key_letters)])
            c = ALPHABET[(p + k) % 26]
            ciphertext.append(c)
            ki += 1
        else:
            ciphertext.append(ch)
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key):
    plaintext = []
    key_letters = ''.join([k for k in key.upper() if k.isalpha()])
    if len(key_letters) == 0:
        raise ValueError('Vigenere key must contain letters')
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            c = ALPHABET.index(ch.upper())
            k = ALPHABET.index(key_letters[ki % len(key_letters)])
            p = (c - k) % 26
            plaintext.append(ALPHABET[p])
            ki += 1
        else:
            plaintext.append(ch)
    return ''.join(plaintext)

# --- Affine Cipher ---
def mod_inverse(a, m=26):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_encrypt(plaintext, a, b):
    ciphertext = []
    for ch in plaintext:
        if ch.isalpha():
            p = ALPHABET.index(ch.upper())
            c = (a * p + b) % 26
            ciphertext.append(ALPHABET[c])
        else:
            ciphertext.append(ch)
    return ''.join(ciphertext)

def affine_decrypt(ciphertext, a, b):
    plaintext = []
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        raise ValueError('a has no modular inverse mod 26')
    for ch in ciphertext:
        if ch.isalpha():
            c = ALPHABET.index(ch.upper())
            p = (a_inv * (c - b)) % 26
            plaintext.append(ALPHABET[p])
        else:
            plaintext.append(ch)
    return ''.join(plaintext)

# --- Combined Cipher (Vigenere followed by Affine) ---
def combined_encrypt(plaintext, key, keep_nonletters=False):
    text = clean_text(plaintext, keep_nonletters)
    # First apply Vigenere
    stage1 = vigenere_encrypt(text, key)
    # Then apply Affine with fixed parameters
    a, b = 5, 7  # Fixed affine parameters
    stage2 = affine_encrypt(stage1, a, b)
    return stage2

def combined_decrypt(ciphertext, key, keep_nonletters=False):
    # First remove Affine layer
    a, b = 5, 7  # Same fixed parameters
    stage1 = affine_decrypt(ciphertext, a, b)
    # Then remove Vigenere layer
    stage2 = vigenere_decrypt(stage1, key)
    return stage2