import hashlib
import hmac
import os
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# Load wordlist
try:
    with open("bip39_english.txt", "r") as f:
        WORDLIST = [line.strip() for line in f.readlines()]
except FileNotFoundError:
    print("Error: bip39_english.txt not found.")
    WORDLIST = []

def generate_safe_entropy(bits=128):
    """Generate a random integer and return it as bytes."""
    # Using secrets.randbits for a "random integer" as requested
    rand_int = secrets.randbits(bits)
    return rand_int.to_bytes(bits // 8, byteorder='big')

def entropy_to_mnemonic_with_details(entropy):
    """Detailed conversion for report/display purposes."""
    entropy_hex = entropy.hex()
    entropy_bits = bin(int.from_bytes(entropy, byteorder='big'))[2:].zfill(len(entropy) * 8)
    
    # Checksum
    hash_entropy = hashlib.sha256(entropy).digest()
    checksum_length = len(entropy) * 8 // 32
    checksum_bits = bin(hash_entropy[0])[2:].zfill(8)[:checksum_length]
    
    total_bits = entropy_bits + checksum_bits
    
    print(f"\n[BIP39 Logic]")
    print(f"Entropy (Hex): {entropy_hex}")
    print(f"Entropy (Binary): {entropy_bits}")
    print(f"Checksum ({checksum_length} bits): {checksum_bits}")
    print(f"Total bits (Entropy + Checksum): {len(total_bits)}")
    
    mnemonic = []
    print("\nDividing into lots of 11 bits:")
    for i in range(0, len(total_bits), 11):
        chunk = total_bits[i:i+11]
        index = int(chunk, 2)
        word = WORDLIST[index]
        mnemonic.append(word)
        print(f"Lot {i//11 + 1:2}: {chunk} -> Index {index:4} -> Word: {word}")
    
    return " ".join(mnemonic)

def mnemonic_to_seed(mnemonic, passphrase=""):
    salt = "mnemonic" + passphrase
    seed = hashlib.pbkdf2_hmac(
        'sha512',
        mnemonic.encode('utf-8'),
        salt.encode('utf-8'),
        2048,
        64
    )
    return seed

def mnemonic_to_entropy(mnemonic):
    words = mnemonic.split()
    if len(words) not in [12, 15, 18, 21, 24]:
        raise ValueError("Invalid mnemonic length. Must be 12, 15, 18, 21, or 24 words.")
    
    bits = ""
    for word in words:
        if word not in WORDLIST:
            raise ValueError(f"Word '{word}' not in BIP39 wordlist.")
        index = WORDLIST.index(word)
        bits += bin(index)[2:].zfill(11)
    
    checksum_length = len(bits) // 33
    entropy_bits = bits[:-checksum_length]
    checksum_bits = bits[-checksum_length:]
    
    entropy_bytes = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, byteorder='big')
    
    # Verify checksum
    hash_entropy = hashlib.sha256(entropy_bytes).digest()
    calculated_checksum = bin(hash_entropy[0])[2:].zfill(8)[:checksum_length]
    
    if checksum_bits != calculated_checksum:
        raise ValueError("Checksum verification failed.")
    
    return entropy_bytes

def get_master_key(seed):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_private_key = I[:32]
    chain_code = I[32:]
    return master_private_key, chain_code

from cryptography.hazmat.primitives import serialization

def priv_to_pub(priv_key):
    pk = ec.derive_private_key(int.from_bytes(priv_key, 'big'), ec.SECP256K1(), default_backend())
    pub_bytes = pk.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    return pub_bytes

def CKDpriv(k_parent, c_parent, i):
    is_hardened = i >= 0x80000000
    if is_hardened:
        data = b"\x00" + k_parent + i.to_bytes(4, byteorder='big')
    else:
        data = priv_to_pub(k_parent) + i.to_bytes(4, byteorder='big')
    
    I = hmac.new(c_parent, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    
    il_int = int.from_bytes(IL, 'big')
    k_parent_int = int.from_bytes(k_parent, 'big')
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    ki_int = (il_int + k_parent_int) % n
    ki = ki_int.to_bytes(32, byteorder='big')
    ci = IR
    return ki, ci

def main():
    print("==========================================")
    print("      CRYPTO MOUETTE WALLET TOOL          ")
    print("==========================================")
    print("1. Create New Wallet (Random Seed)")
    print("2. Import Mnemonic Seed")
    
    choice = input("\nSelect an option (1-2): ")
    
    mnemonic = ""
    if choice == "1":
        strength = input("Enter entropy bits (128, 160, 192, 224, 256) [default 128]: ") or "128"
        entropy = generate_safe_entropy(int(strength))
        mnemonic = entropy_to_mnemonic_with_details(entropy)
        print(f"\nGenerated Mnemonic: \033[92m{mnemonic}\033[0m")
    elif choice == "2":
        mnemonic = input("Paste your mnemonic phrase: ").strip()
        try:
            entropy = mnemonic_to_entropy(mnemonic)
            print(f"Mnemonic imported successfully. Entropy verified.")
        except Exception as e:
            print(f"\033[91mError:\033[0m {e}")
            return
    else:
        print("Invalid choice.")
        return

    seed = mnemonic_to_seed(mnemonic)
    print(f"\nFull 512-bit Seed (Hex): {seed.hex()}")
    
    m_priv, m_chain = get_master_key(seed)
    m_pub = priv_to_pub(m_priv)
    
    print("\n--- MASTER KEYS ---")
    print(f"Master Private Key: {m_priv.hex()}")
    print(f"Master Chain Code:   {m_chain.hex()}")
    print(f"Master Public Key:  {m_pub.hex()}")
    
    while True:
        print("\n--- DERIVATION OPTIONS ---")
        print("1. Derivation Level 1 (Child at index N)")
        print("2. Custom Path (e.g., m/44'/0'/0'/0/0)")
        print("3. Exit")
        
        opt = input("\nChoice: ")
        
        if opt == "1":
            try:
                idx = int(input("Enter child index N: "))
                is_hardened = input("Hardened? (y/n): ").lower() == 'y'
                real_idx = idx + 0x80000000 if is_hardened else idx
                
                k, c = CKDpriv(m_priv, m_chain, real_idx)
                print(f"\nResulting Child Key (Index {idx}{'h' if is_hardened else ''}):")
                print(f"Private Key: {k.hex()}")
                print(f"Public Key:  {priv_to_pub(k).hex()}")
                print(f"Chain Code:  {c.hex()}")
            except ValueError:
                print("Invalid index.")
        
        elif opt == "2":
            path = input("Enter path (e.g. m/0'/1/2): ")
            try:
                segments = path.split("/")
                if segments[0] == 'm': segments = segments[1:]
                
                k, c = m_priv, m_chain
                current_path = "m"
                for seg in segments:
                    if seg.endswith("'" ) or seg.endswith("h"):
                        idx = int(seg[:-1]) + 0x80000000
                    else:
                        idx = int(seg)
                    k, c = CKDpriv(k, c, idx)
                    current_path += f"/{seg}"
                
                print(f"\nResult for {path}:")
                print(f"Private Key: {k.hex()}")
                print(f"Public Key:  {priv_to_pub(k).hex()}")
                print(f"Chain Code:  {c.hex()}")
            except Exception as e:
                print(f"Derivation error: {e}")
        
        elif opt == "3":
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()