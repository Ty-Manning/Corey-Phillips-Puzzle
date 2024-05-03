import time
import ecdsa
import hashlib
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44Coins

# Function to generate mnemonic phrase from SHA256 hash
def generate_mnemonic(sha256_hash, word_list):
    entropy = int.from_bytes(bytes.fromhex(sha256_hash), byteorder='big')
    mnemonic_indices = [entropy >> 11 * i & 2047 for i in range(24)]
    mnemonic = ' '.join(word_list[idx] for idx in mnemonic_indices)
    return mnemonic

# Function to generate private key from mnemonic and passphrase
def generate_private_key(mnemonic, passphrase):
    seed = hashlib.pbkdf2_hmac('sha512', mnemonic.encode(), passphrase.encode(), 2048)
    key = ecdsa.SigningKey.from_string(seed[:32], curve=ecdsa.SECP256k1)
    return key.to_string().hex()

# Function to convert private key to bech32 Bitcoin address
def private_key_to_address(private_key):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = vk.to_string().hex()
    pubkey_bytes = bytes.fromhex('04' + pubkey)
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(pubkey_bytes).digest())
    return ripemd160.hexdigest()

# Bitcoin address for testing
known_address = "bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r"

# SHA256 hash
sha256_hash = "1808d35318ac7cb98b69ff9779b699d6a631f15e0b353ac89b7c4020774832ed"

# Read word list
with open("english.txt", "r") as f:
    word_list = [line.strip() for line in f]

# Generate mnemonic phrase from SHA256 hash
mnemonic = generate_mnemonic(sha256_hash, word_list)

print("Generated Mnemonic:", mnemonic)

# Read potential passphrases from text file
passphrases_file = "passphrases.txt"
potential_passphrases = []
with open(passphrases_file, "r", encoding="utf-8", errors="ignore") as file:
    for line in file:
        potential_passphrases.append(line.strip())

print("Number of passphrases to test:", len(potential_passphrases))

# Track the number of passphrases tested within a certain time frame
passphrases_tested = 0
start_time = time.time()

# Iterate through passphrases and test them sequentially
for passphrase in potential_passphrases:
    mnemonic = generate_mnemonic(sha256_hash, word_list)
    private_key = generate_private_key(mnemonic, passphrase)
    generated_address = private_key_to_address(private_key)
    #print(f"Testing passphrase: {passphrase}, Address: {generated_address}")
    if generated_address == known_address:
        print("Success! Found passphrase:", passphrase)
        print("Private Key:", private_key)
        with open("found.txt", "w") as found_file:
            found_file.write(f"Passphrase: {passphrase}\nPrivate Key: {private_key}")
        break
    passphrases_tested += 1
    if time.time() - start_time >= 10:  # print speed
        elapsed_time = time.time() - start_time
        passphrases_per_second = passphrases_tested / elapsed_time
        print(f"Passphrases tested per second: {passphrases_per_second:.2f}")
        passphrases_tested = 0
        start_time = time.time()
else:
    print("Failed! None of the passphrases produced the  address.")
