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
    
    for letter, expected_freq in ENGLISH_FREQ.items():
        observed_count = freq.get(letter, 0)
        observed_freq = (observed_count / total_chars) * 100
        # Higher score for closer match to English frequencies
        score += max(0, 10 - abs(observed_freq - expected_freq))
    
    return score

def known_plaintext_attack(ciphertext, known_plaintext):
    """
    WORKING KNOWN-PLAINTEXT ATTACK BASED ON C++ LOGIC
    
    Process:
    1. Clean both ciphertext and known plaintext (letters only)
    2. For each possible affine parameters (a, b)
    3. Remove affine layer from ciphertext
    4. Derive Vigenere key from known plaintext relationship
    5. Test the derived key on full ciphertext
    """
    # Clean inputs (letters only)
    c_clean = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())
    p_clean = ''.join(ch.upper() for ch in known_plaintext if ch.isalpha())
    
    if not c_clean or not p_clean:
        return "Need alphabetic characters for both ciphertext and known plaintext."
    
    if len(p_clean) < 4:
        return "Known plaintext should be at least 4 characters for reliable attack."
    
    if len(p_clean) > len(c_clean):
        return "Known plaintext is longer than ciphertext!"
    
    results = []
    attempts = 0
    
    # Valid affine 'a' values (coprime with 26)
    valid_as = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    
    print(f"Starting attack with {len(valid_as)} possible affine keys and 26 shifts...")
    
    # Try all possible affine parameters
    for a in valid_as:
        for b in range(26):
            attempts += 1
            
            try:
                # Remove affine layer from entire ciphertext
                after_affine_full = affine_decrypt(c_clean, a, b)
                
                # Try different starting positions for alignment
                for start_pos in range(min(5, len(c_clean) - len(p_clean) + 1)):
                    # Get the segment of affine-decrypted text that should correspond to known plaintext
                    affine_segment = after_affine_full[start_pos:start_pos + len(p_clean)]
                    
                    # Derive Vigenere key from the relationship
                    # Vigenere: cipher = (plain + key) mod 26
                    # So: key = (cipher - plain) mod 26
                    derived_key_chars = []
                    
                    for i in range(len(p_clean)):
                        if i < len(affine_segment):
                            vig_char = affine_segment[i]
                            plain_char = p_clean[i]
                            
                            vig_idx = ALPHABET.index(vig_char)
                            plain_idx = ALPHABET.index(plain_char)
                            
                            # Derive key character
                            key_idx = (vig_idx - plain_idx) % 26
                            derived_key_chars.append(ALPHABET[key_idx])
                    
                    if derived_key_chars:
                        derived_key = ''.join(derived_key_chars)
                        
                        # Try different key lengths based on the derived key
                        for key_len in range(10, min(20, len(derived_key) + 1)):
                            test_key = derived_key[:key_len]
                            
                            # Decrypt with this key
                            decrypted = vigenere_decrypt(after_affine_full, test_key)
                            
                            # Check if known plaintext appears in the result
                            if p_clean in decrypted:
                                english_score = calculate_english_score(decrypted)
                                
                                results.append({
                                    'affine_a': a,
                                    'affine_b': b,
                                    'vigenere_key': test_key,
                                    'plaintext': decrypted,
                                    'english_score': english_score,
                                    'position': start_pos,
                                    'attempts': attempts
                                })
                                
            except Exception as e:
                continue
    
    if not results:
        return f"Attack failed after {attempts} attempts. No valid decryption found.\nTry a longer known plaintext or different ciphertext."
    
    # Remove duplicates and sort by English score
    unique_results = []
    seen_keys = set()
    
    for res in results:
        key_tuple = (res['affine_a'], res['affine_b'], res['vigenere_key'])
        if key_tuple not in seen_keys:
            seen_keys.add(key_tuple)
            unique_results.append(res)
    
    # Sort by English score (higher is better)
    unique_results.sort(key=lambda x: x['english_score'], reverse=True)
    
    # Format results
    output = [
        "KNOWN-PLAINTEXT ATTACK - SUCCESS!",
        "=" * 70,
        f"Total attempts: {attempts}",
        f"Found {len(unique_results)} potential solution(s)",
        "=" * 70
    ]
    
    for i, res in enumerate(unique_results[:3]):  # Show top 3 results
        output.extend([
            f"\nSOLUTION {i+1}:",
            f"Affine parameters: a={res['affine_a']}, b={res['affine_b']}",
            f"Vigenere key: '{res['vigenere_key']}'",
            f"English similarity score: {res['english_score']:.2f}/260",
            f"Alignment position: {res['position']}",
            f"Full decrypted text:",
            f"{res['plaintext']}",
            "-" * 70
        ])
    
    return "\n".join(output)

def break_combined_frequency(ciphertext, max_vig_keylen=15, top_candidates=3):
    """
    Frequency-based attack without known plaintext
    Based on C++ advanced frequency analysis
    """
    c_clean = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())
    
    if not c_clean:
        return "No alphabetic characters in ciphertext."
    
    def break_vigenere_frequency(text, max_keylen):
        """Break Vigenere cipher using frequency analysis"""
        best_key = ""
        best_plaintext = ""
        best_score = -1
        
        for keylen in range(1, max_keylen + 1):
            key_chars = []
            
            # Analyze each position in the key
            for pos in range(keylen):
                # Extract every keylen-th character starting at pos
                segment = text[pos::keylen]
                
                if not segment:
                    continue
                
                # Try each possible shift for this position
                best_char = 'A'
                best_char_score = -1
                
                for shift in range(26):
                    # Decrypt this segment with current shift
                    decrypted_segment = ''.join(
                        ALPHABET[(ALPHABET.index(c) - shift) % 26] 
                        for c in segment
                    )
                    
                    score = calculate_english_score(decrypted_segment)
                    
                    if score > best_char_score:
                        best_char_score = score
                        best_char = ALPHABET[shift]
                
                key_chars.append(best_char)
            
            test_key = ''.join(key_chars)
            test_plain = vigenere_decrypt(text, test_key)
            test_score = calculate_english_score(test_plain)
            
            if test_score > best_score:
                best_score = test_score
                best_key = test_key
                best_plaintext = test_plain
        
        return best_key, best_plaintext, best_score
    
    results = []
    valid_as = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    
    print("Running frequency-based attack...")
    
    for a in valid_as:
        for b in range(26):
            try:
                # Remove affine layer
                after_affine = affine_decrypt(c_clean, a, b)
                
                # Break Vigenere
                vig_key, plaintext, score = break_vigenere_frequency(after_affine, max_vig_keylen)
                
                results.append({
                    'affine_a': a,
                    'affine_b': b,
                    'vigenere_key': vig_key,
                    'plaintext': plaintext,
                    'score': score
                })
                
            except Exception:
                continue
    
    if not results:
        return "No valid decryptions found."
    
    # Sort by score (higher is better)
    results.sort(key=lambda x: x['score'], reverse=True)
    
    # Format output
    output = [
        "FREQUENCY-BASED ATTACK RESULTS",
        "=" * 70,
        f"Analyzed {len(results)} combinations"
    ]
    
    for i, res in enumerate(results[:top_candidates]):
        output.extend([
            f"\nCANDIDATE {i+1}:",
            f"Affine: a={res['affine_a']}, b={res['affine_b']}",
            f"Vigenere key: '{res['vigenere_key']}'",
            f"English score: {res['score']:.2f}/260",
            f"Decrypted text preview:",
            f"{res['plaintext'][:100]}{'...' if len(res['plaintext']) > 100 else ''}",
            "-" * 70
        ])
    
    return "\n".join(output)

def brute_force_affine_only(ciphertext):
    """
    Quick attack that only tries to break the affine layer
    Useful for testing or partial breaks
    """
    c_clean = ''.join(ch.upper() for ch in ciphertext if ch.isalpha())
    
    if not c_clean:
        return "No alphabetic characters in ciphertext."
    
    results = []
    valid_as = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    
    for a in valid_as:
        for b in range(26):
            try:
                decrypted = affine_decrypt(c_clean, a, b)
                score = calculate_english_score(decrypted)
                
                results.append({
                    'affine_a': a,
                    'affine_b': b,
                    'plaintext': decrypted,
                    'score': score
                })
                
            except Exception:
                continue
    
    if not results:
        return "No valid affine decryptions found."
    
    # Sort by score
    results.sort(key=lambda x: x['score'], reverse=True)
    
    output = [
        "BRUTE FORCE AFFINE (PARTIAL DECRYPTION)",
        "=" * 70
    ]
    
    for i, res in enumerate(results[:3]):
        output.extend([
            f"\nCandidate {i+1}:",
            f"Affine: a={res['affine_a']}, b={res['affine_b']}",
            f"English score: {res['score']:.2f}/260",
            f"Partially decrypted:",
            f"{res['plaintext'][:100]}{'...' if len(res['plaintext']) > 100 else ''}",
            "-" * 70
        ])
    
    return "\n".join(output)