from cipher_core import combined_encrypt
import attack_tools

# Simple test to validate known_plaintext_attack
plaintext = "THIS IS A SECRET MESSAGE THAT MUST REMAIN CONFIDENTIAL"
key = "TESTKEYXYZ"

# Produce combined cipher (combined_encrypt cleans text by default)
cipher = combined_encrypt(plaintext, key, keep_nonletters=False)
print('Full ciphertext:', cipher)

# Choose a known substring from plaintext and its corresponding ciphertext substring
# We'll pick the word "SECRET" which appears in plaintext; find its index in cleaned plaintext
from cipher_core import clean_text
clean_plain = clean_text(plaintext)
start = clean_plain.find('SECRET')
if start == -1:
    raise SystemExit('Could not find substring in cleaned plaintext')
known_plain = clean_plain[start:start+6]
known_cipher = cipher[start:start+6]

print('\nKnown plain fragment:', known_plain)
print('Known cipher fragment:', known_cipher)

# Run attack
res = attack_tools.known_plaintext_attack(cipher, known_plain, known_cipher)
print('\nAttack result:\n')
print(res)
