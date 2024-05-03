import time
import ecdsa
import hashlib
import os
from bech32 import bech32_encode, convertbits
from multiprocessing import Pool

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
    # Convert the private key to a public key
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = vk.to_string("uncompressed")

    # Hash the public key
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    pubkey_hash = ripemd160.digest()

    # Get Bech32 address
    witness_program = bytes([0x00, 0x14]) + pubkey_hash
    bech32_address = bech32_encode('bc', convertbits(witness_program, 8, 5))
    return bech32_address

# Function to load checkpoint
def load_checkpoint():
    if os.path.exists("checkpoint.txt"):
        with open("checkpoint.txt", "r") as checkpoint_file:
            return int(checkpoint_file.read())
    else:
        return 0

# Function to save checkpoint
def save_checkpoint(index):
    with open("checkpoint.txt", "w") as checkpoint_file:
        checkpoint_file.write(str(index))

# Function to test passphrase
def test_passphrase(passphrase, sha256_hash, word_list, known_address):
    try:
        mnemonic = generate_mnemonic(sha256_hash, word_list)
        private_key = generate_private_key(mnemonic, passphrase)
        generated_address = private_key_to_address(private_key)
        if generated_address == known_address:
            print("Success! Found passphrase:", passphrase)
            print("Private Key:", private_key)
            with open("found.txt", "w") as found_file:
                found_file.write(f"Passphrase: {passphrase}\nPrivate Key: {private_key}")
    except Exception as e:
        print(f"Error while testing passphrase: {passphrase}, {e}")

def load_passphrases_in_batches(passphrases_file, batch_size, start_index=0):
    with open(passphrases_file, "r", encoding="utf-8", errors="ignore") as file:
        # Set the file pointer to the start index
        for _ in range(start_index):
            next(file)
        
        # Track the current index
        current_index = start_index

        while True:
            batch_passphrases = [next(file).strip() for _ in range(batch_size)]
            if not batch_passphrases:
                break
            yield batch_passphrases, current_index  # Yield the batch and the current index
            current_index += batch_size  # Increment the current index

            # Save the current index to the checkpoint file
            save_checkpoint(current_index)

if __name__ == '__main__':
    print("Start of main")

    # Known Bitcoin address for testing
    known_address = "bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r"
    print("Known Bitcoin address:", known_address)

    # SHA256 hash for entropy
    sha256_hash = "1808d35318ac7cb98b69ff9779b699d6a631f15e0b353ac89b7c4020774832ed"
    print("SHA256 hash for entropy:", sha256_hash)

    # Read word list
    with open("english.txt", "r") as f:
        word_list = [line.strip() for line in f]


    # Load checkpoint
    index = load_checkpoint()
    print("Loaded checkpoint:", index)

    # Read potential passphrases from a text file in batches
    passphrases_file = "rockyou2021.txt"
    batch_size = 1000000  # Adjust as needed
    batch_generator = load_passphrases_in_batches(passphrases_file, batch_size, start_index=index)

    # Track the number of passphrases tested within a certain time frame
    passphrases_tested = 0
    start_time = time.time()
    measure_time = time.time()

    # Create a process pool with 6 cores
    with Pool(processes=6) as pool:
        print("Pool created")

        # Loop through passphrases in batches
        for batch_passphrases, current_index in batch_generator:
            # Submit passphrase testing tasks to the pool
            results = []
            for passphrase in batch_passphrases:
                try:
                    result = pool.apply_async(test_passphrase, (passphrase, sha256_hash, word_list, known_address))
                    results.append(result)
                except Exception as e:
                    print(f"Error submitting passphrase '{passphrase}' to the pool: {e}")

            # Wait for all tasks in the batch to complete
            for result in results:
                try:
                    result.get()
                    passphrases_tested += 1
                except Exception as e:
                    print(f"Error getting result from task: {e}")

                if time.time() - measure_time >= 30:  # Check if 30 seconds have elapsed
                    elapsed_time = time.time() - start_time
                    passphrases_per_second = passphrases_tested / elapsed_time
                    print(f"Passphrases tested per second: {passphrases_per_second:.2f}")
                    # Save checkpoint
                    save_checkpoint(current_index + passphrases_tested)
                    measure_time = time.time()  # Reset measure_time

    print("All passphrases tested.")






