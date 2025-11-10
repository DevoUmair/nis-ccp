import time
from cipher_core import combined_encrypt, combined_decrypt, vigenere_encrypt, vigenere_decrypt

def time_function(fn, *args, repeats=3):
    # time small function with repeats and return average
    times = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn(*args)
        times.append(time.perf_counter() - t0)
    return sum(times) / len(times)

def run_efficiency_tests(key, sizes=(100, 1000, 5000, 10000)):
    """
    Run timed tests for combined cipher vs Vigenere-only.
    Returns a formatted result string with timings.
    """
    results = []
    for n in sizes:
        sample_text = ("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * ((n // 43) + 1))[:n]
        # combined
        t_comb_enc = time_function(combined_encrypt, sample_text, key)
        # for decryption, need ciphertext
        ciph = combined_encrypt(sample_text, key)
        t_comb_dec = time_function(combined_decrypt, ciph, key)

        # vigenere only
        t_vig_enc = time_function(vigenere_encrypt, sample_text, key)
        c_vig = vigenere_encrypt(sample_text, key)
        t_vig_dec = time_function(vigenere_decrypt, c_vig, key)

        results.append( (n, t_comb_enc, t_comb_dec, t_vig_enc, t_vig_dec) )

    # format results
    out_lines = ["Efficiency test results (average of several runs):", "-"*80]
    out_lines.append(f"{'N':>7} | {'C_enc(s)':>8} {'C_dec(s)':>9} | {'V_enc(s)':>8} {'V_dec(s)':>9}")
    out_lines.append("-"*80)
    for row in results:
        n, ce, cd, ve, vd = row
        out_lines.append(f"{n:7d} | {ce:8.5f} {cd:9.5f} | {ve:8.5f} {vd:9.5f}")
    out_lines.append("-"*80)
    out_lines.append("Time complexity:\n - Vigenere: O(n) for encryption and decryption (single letter ops).\n - Affine: O(n) for encryption and decryption (single letter ops).\n - Combined (Vigenere + Affine): O(n) (two linear passes) — roughly ~2x cost of single stage.\n")
    return "\n".join(out_lines)