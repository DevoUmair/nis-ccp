from collections import Counter
import math
from cipher_core import affine_decrypt, vigenere_decrypt, ALPHABET, derive_affine_params_from_key, vigenere_encrypt

ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702, 'F': 2.228,
    'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153, 'K': 0.772, 'L': 4.025,
    'M': 2.406, 'N': 6.749, 'O': 7.507, 'P': 1.929, 'Q': 0.095, 'R': 5.987,
    'S': 6.327, 'T': 9.056, 'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150,
    'Y': 1.974, 'Z': 0.074
}

def frequency_analysis(ciphertext):
    """
    Return formatted frequency analysis string (percentages) for A-Z from ciphertext.
    """
    filtered = ''.join(ch for ch in ciphertext.upper() if ch.isalpha())
    if not filtered:
        return "No alphabetic characters in ciphertext."
    freq = Counter(filtered)
    total = sum(freq.values())
    lines = ["Letter : Count (Percent)"]
    for ch, count in freq.most_common():
        lines.append(f"{ch:>2} : {count:>4} ({count/total*100:6.2f}%)")
    # Add chi-squared against English
    chi2 = 0.0
    for ch in ALPHABET:
        observed = freq.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * total / 100.0
        chi2 += ((observed - expected) ** 2) / (expected + 1e-9)
    lines.append("")
    lines.append(f"Chi-squared statistic (vs English): {chi2:.2f} (lower suggests English-like)")
    return "\n".join(lines)

def known_plaintext_attack(ciphertext, known_plain, allow_overlap=True):
    """
    Known-plaintext attack attempt:
    - Search occurrences of known_plain (letters only) in ciphertext (letters only),
      then for each candidate location brute-force affine params (a,b) and derive a
      Vigenere key fragment from the mapping.
    - Then try to decrypt full ciphertext with the derived key fragment (repeating).
    Returns a formatted multi-line string with candidate successes.
    """
    c_filtered = ''.join(ch for ch in ciphertext.upper() if ch.isalpha())
    p_filtered = ''.join(ch for ch in known_plain.upper() if ch.isalpha())
    if not c_filtered or not p_filtered:
        return "Need alphabetic characters for both ciphertext and known plaintext."
    results = []
    # find all positions where we can align known_plain within ciphertext
    positions = []
    # naive substring search
    start = 0
    while True:
        idx = c_filtered.find(p_filtered, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1 if allow_overlap else idx + len(p_filtered)
    if not positions:
        # It may be that known_plain is plaintext mapping to ciphertext via affine+vigenere
        # so direct substring match may not occur. We'll still try sliding windows of same length.
        positions = list(range(0, max(1, len(c_filtered) - len(p_filtered) + 1)))
    # coprime 'a' candidates
    coprime_as = [a for a in range(1, 26) if math.gcd(a, 26) == 1]
    for pos in positions:
        c_segment = c_filtered[pos:pos+len(p_filtered)]
        for a in coprime_as:
            for b in range(26):
                try:
                    # remove affine: this yields the Vigenere stage output for segment
                    v_segment = affine_decrypt(c_segment, a, b)
                except Exception:
                    continue
                # derive per-letter key shifts: key_shift = (v_segment_letter - plaintext_letter) mod26
                key_shifts = []
                for vc, pc in zip(v_segment, p_filtered):
                    kshift = (ALPHABET.index(vc) - ALPHABET.index(pc)) % 26
                    key_shifts.append(ALPHABET[kshift])
                # candidate key fragment
                key_fragment = ''.join(key_shifts)
                # try decrypting full ciphertext using this key fragment as repeating key
                candidate_plain = vigenere_decrypt( affine_decrypt(c_filtered, a, b), key_fragment )
                if p_filtered in candidate_plain:
                    # Format candidate
                    b64 = f"pos={pos}, a={a}, b={b}, key_fragment='{key_fragment}'"
                    results.append((b64, candidate_plain))
    if not results:
        return "No successful candidates found with the provided known-plaintext."
    # Format top results (deduplicate first)
    out_lines = ["Found candidate(s):", "-"*60]
    seen = set()
    for meta, plaintext in results:
        if meta in seen: 
            continue
        seen.add(meta)
        out_lines.append(meta)
        # show a short snippet of plaintext
        preview = plaintext[:200]
        out_lines.append("Decrypted snippet:")
        out_lines.append(preview)
        out_lines.append("-"*60)
    return "\n".join(out_lines)

# Frequency-based combined breaker (brute-force affine then vigenere-find via chi-sq)
def break_combined_frequency(ciphertext, max_vig_keylen=12, top_candidates=3):
    """
    Try all affine (a,b). For each, run a simple Vigenere break by per-position chi-square.
    Return a formatted string of top candidate plaintexts/keys.
    """
    filtered = ''.join(ch for ch in ciphertext.upper() if ch.isalpha())
    if not filtered:
        return "No alphabetic characters in ciphertext."

    # helper to compute chi-sq for assumed keylength and shift
    def score_shifts_for_keylen(text, keylen):
        key_chars = []
        for i in range(keylen):
            seq = text[i::keylen]
            best_shift = 0
            best_score = float('inf')
            for shift in range(26):
                shifted = ''.join(ALPHABET[(ALPHABET.index(c) - shift) % 26] for c in seq)
                # compute simple chi2
                cnt = Counter(shifted)
                total = len(shifted)
                chi2 = 0.0
                for ch in ALPHABET:
                    observed = cnt.get(ch, 0)
                    expected = ENGLISH_FREQ[ch] * total / 100.0
                    chi2 += ((observed - expected)**2) / (expected + 1e-9)
                if chi2 < best_score:
                    best_score = chi2
                    best_shift = shift
            key_chars.append(ALPHABET[best_shift])
        return ''.join(key_chars), best_score

    candidates = []
    coprime_as = [a for a in range(1, 26) if math.gcd(a, 26) == 1]
    for a in coprime_as:
        for b in range(26):
            try:
                after_affine = affine_decrypt(filtered, a, b)
            except Exception:
                continue
            # try different vigenere key lengths
            for klen in range(1, max_vig_keylen+1):
                key_guess, score = score_shifts_for_keylen(after_affine, klen)
                # decrypt with guessed key
                plain_guess = vigenere_decrypt(after_affine, key_guess)
                candidates.append( (score, a, b, key_guess, plain_guess) )
    # select top candidates by score
    candidates.sort(key=lambda x: x[0])
    if not candidates:
        return "No candidates found."
    out_lines = ["Top candidate decryptions (lower score = closer to English):", "-"*80]
    for score, a, b, kguess, plain in candidates[:top_candidates]:
        out_lines.append(f"a={a}, b={b}, vigenere_key_guess='{kguess}', score={score:.2f}")
        out_lines.append("Plaintext preview:")
        out_lines.append(plain[:300])
        out_lines.append("-"*80)
    return "\n".join(out_lines)
