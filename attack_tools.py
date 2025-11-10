import math
import time
from collections import Counter
from cipher_core import ALPHABET, affine_decrypt, vigenere_decrypt, affine_encrypt, vigenere_encrypt

ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702, 'F': 2.228,
    'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153, 'K': 0.772, 'L': 4.025,
    'M': 2.406, 'N': 6.749, 'O': 7.507, 'P': 1.929, 'Q': 0.095, 'R': 5.987,
    'S': 6.327, 'T': 9.056, 'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150,
    'Y': 1.974, 'Z': 0.074
}

def frequency_analysis(ciphertext):
    """Basic frequency analysis of ciphertext"""
    filtered = ''.join(ch for ch in ciphertext.upper() if ch.isalpha())
    if not filtered:
        return "No alphabetic characters in ciphertext."
    
    freq = Counter(filtered)
    total = sum(freq.values())
    
    lines = ["Letter : Count (Percent)"]
    for ch in ALPHABET:
        count = freq.get(ch, 0)
        percent = (count / total) * 100
        lines.append(f"{ch:>2} : {count:>4} ({percent:6.2f}%)")
    
    # Chi-squared test
    chi2 = 0.0
    for ch in ALPHABET:
        observed = freq.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * total / 100.0
        chi2 += ((observed - expected) ** 2) / (expected + 1e-9)
    
    lines.append(f"\nChi-squared statistic (vs English): {chi2:.2f}")
    return "\n".join(lines)

def calculate_english_score(text):
    """Calculate how English-like the text is"""
    if not text:
        return 0
    
    text_upper = text.upper()
    total_chars = len([ch for ch in text_upper if ch in ALPHABET])
    if total_chars == 0:
        return 0
    
    freq = Counter(text_upper)
    score = 0
    
    # Check for common English words
    common_words = ['THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THAT', 'WAS', 'FOR', 'ARE', 'WITH']
    text_words = text_upper.split()
    word_score = sum(10 for word in text_words if word in common_words)
    
    for letter, expected_freq in ENGLISH_FREQ.items():
        observed_count = freq.get(letter, 0)
        observed_freq = (observed_count / total_chars) * 100
        # Higher score for closer match to English frequencies
        score += max(0, 10 - abs(observed_freq - expected_freq))
    
    return score + word_score

def known_plaintext_attack(ciphertext, known_plaintext, known_ciphertext):
    """
    EFFICIENT KNOWN-PLAINTEXT ATTACK
    Uses the fact that affine parameters are fixed (a=5, b=7)
    Only need to find the Vigenere key
    """
    # Clean inputs
    full_cipher_clean = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())
    known_plain_clean = ''.join(ch.upper() for ch in known_plaintext if ch.isalpha())
    known_cipher_clean = ''.join(ch.upper() for ch in known_ciphertext if ch.isalpha())
    
    if not full_cipher_clean or not known_plain_clean or not known_cipher_clean:
        return "Need alphabetic characters for all inputs."
    
    if len(known_plain_clean) != len(known_cipher_clean):
        return "Known plaintext and known ciphertext must be same length!"
    
    if len(known_plain_clean) < 4:
        return "Known plaintext should be at least 4 characters for reliable attack."
    
    # Fixed affine parameters (as used in encryption)
    AFFINE_A = 5
    AFFINE_B = 7

    print("Starting efficient known-plaintext attack...")
    print(f"Using fixed affine parameters: a={AFFINE_A}, b={AFFINE_B}")

    # Locate known ciphertext inside full ciphertext so we know alignment
    pos = full_cipher_clean.find(known_cipher_clean)
    if pos == -1:
        return "Known ciphertext fragment not found inside full ciphertext. Please provide the ciphertext substring that matches the known plaintext."

    try:
        # Remove affine layer from known ciphertext fragment
        after_affine_known = affine_decrypt(known_cipher_clean, AFFINE_A, AFFINE_B)

        # Derive Vigenere key fragment from known plaintext <-> stage1 relationship
        derived_fragment = []
        for i in range(len(known_plain_clean)):
            vig_char = after_affine_known[i]
            plain_char = known_plain_clean[i]
            vig_idx = ALPHABET.index(vig_char)
            plain_idx = ALPHABET.index(plain_char)
            key_idx = (vig_idx - plain_idx) % 26
            derived_fragment.append(ALPHABET[key_idx])
        derived_fragment = ''.join(derived_fragment)

        # Remove affine layer from full ciphertext once
        after_affine_full = affine_decrypt(full_cipher_clean, AFFINE_A, AFFINE_B)

        # Build a keystream by repeating the derived fragment, aligned at the found position
        m = len(derived_fragment)
        keystream = []
        for j in range(len(after_affine_full)):
            # keystream at position j is derived_fragment[(j - pos) % m]
            # This assumes the derived fragment is a repeating segment of the Vigenere keystream
            idx = (j - pos) % m
            keystream.append(derived_fragment[idx])

        # Decrypt using keystream (apply keystream char-by-char)
        plaintext_chars = []
        for j, ch in enumerate(after_affine_full):
            if ch.isalpha():
                c_idx = ALPHABET.index(ch)
                k_idx = ALPHABET.index(keystream[j])
                p_idx = (c_idx - k_idx) % 26
                plaintext_chars.append(ALPHABET[p_idx])
            else:
                plaintext_chars.append(ch)
        final_plaintext = ''.join(plaintext_chars)

        english_score = calculate_english_score(final_plaintext)

        output = [
            "KNOWN-PLAINTEXT ATTACK - SUCCESS (aligned keystream)",
            "=" * 60,
            f"Affine parameters: a={AFFINE_A}, b={AFFINE_B}",
            f"Position of known fragment in ciphertext: {pos}",
            f"Derived fragment (from known sample): '{derived_fragment}'",
            f"Keystream length (derived fragment): {m}",
            f"English similarity score: {english_score:.2f}",
            "Full decrypted text:",
            final_plaintext,
            "=" * 60
        ]

        return "\n".join(output)

    except Exception as e:
        return f"Attack failed with error: {str(e)}"

def break_combined_frequency(ciphertext):
    """
    FREQUENCY-BASED ATTACK
    Tries common affine combinations and looks for English-like text
    """
    c_clean = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())
    
    if not c_clean:
        return "No alphabetic characters in ciphertext."
    
    results = []
    
    # Only try common affine parameters
    common_affine_params = [
        (3, 1), (3, 7), (5, 1), (5, 7), (7, 1), (7, 7),
        (9, 1), (9, 7), (11, 1), (11, 7), (15, 1), (15, 7),
        (17, 1), (17, 7), (19, 1), (19, 7), (21, 1), (21, 7),
        (23, 1), (23, 7), (25, 1), (25, 7)
    ]
    
    print("Running frequency-based attack with common affine parameters...")
    
    for a, b in common_affine_params:
        try:
            # Remove affine layer
            after_affine = affine_decrypt(c_clean, a, b)
            
            # Try to break Vigenere with frequency analysis
            # Simple approach: try common English words as potential keys
            common_keys = ['A', 'THE', 'KEY', 'SECRET', 'PASSWORD', 'CRYPTO', 'ENCRYPT']
            
            for test_key in common_keys:
                decrypted = vigenere_decrypt(after_affine, test_key)
                score = calculate_english_score(decrypted)
                
                if score > 50:  # Only keep reasonably good results
                    results.append({
                        'affine_a': a,
                        'affine_b': b,
                        'vigenere_key': test_key,
                        'plaintext': decrypted,
                        'score': score
                    })
                    
        except Exception:
            continue
    
    if not results:
        return "No valid decryptions found with frequency analysis."
    
    # Sort by score (higher is better)
    results.sort(key=lambda x: x['score'], reverse=True)
    
    # Format output
    output = [
        "FREQUENCY-BASED ATTACK RESULTS",
        "=" * 60,
        f"Found {len(results)} potential decryptions",
        "Top candidates:"
    ]
    
    for i, res in enumerate(results[:3]):
        output.extend([
            f"\nCANDIDATE {i+1}:",
            f"Affine: a={res['affine_a']}, b={res['affine_b']}",
            f"Vigenere key: '{res['vigenere_key']}'",
            f"English score: {res['score']:.2f}",
            f"Decrypted text preview:",
            f"{res['plaintext'][:80]}{'...' if len(res['plaintext']) > 80 else ''}",
            "-" * 60
        ])
    
    return "\n".join(output)