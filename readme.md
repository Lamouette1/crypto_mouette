# Crypto Mouette - BIP39/BIP32 Wallet Implementation

This project is a command-line tool implemented in Python that follows the BIP39 and BIP32 standards for Hierarchical Deterministic (HD) wallets.

## Requirements Mapping
- [x] **Python CLI Program**: `wallet.py`.
- [x] **Safe Seed Generation**: Uses `secrets.randbits`.
- [x] **11-bit Lot Division**: Visualized in the output when creating a new wallet.
- [x] **BIP39 Mnemonic**: Correct mapping and checksum implementation.
- [x] **Mnemonic Import**: Verified with checksum validation.
- [x] **Master Private Key & Chain Code**: Extracted and displayed in hex.
- [x] **Master Public Key**: Derived from the private key and displayed (compressed).
- [x] **Child Key at Index N**: Available in the derivation menu.
- [x] **Child Key at Level M**: Available via the "Custom Path" option (e.g., `m/0/1/2`).
- [x] **External Verification**: Compatible with iancoleman.io.

## Prerequisites
- Python 3.x
- `cryptography` library (used only for Secp256k1 elliptic curve math)

To install dependencies:
```bash
pip install cryptography
```

## How to Run
1. Ensure `wallet.py` and `bip39_english.txt` are in the same directory.
2. Run the program:
```bash
python3 wallet.py
```

## Implementation Details (Report)

### 1. Entropy & Randomness
The program uses `secrets.randbits` (and `secrets.token_bytes`) to generate cryptographically strong random integers. This serves as the "safe seed" or entropy.

### 2. BIP39 Logic
- **Entropy to Bits**: The entropy is converted to a bitstream.
- **Checksum**: A checksum is calculated by taking the first `ENT/32` bits of the SHA256 hash of the entropy.
- **11-bit Lots**: The bits (Entropy + Checksum) are divided into groups of 11 bits. Each group represents an index (0-2047) in the wordlist.
- **Mnemonic**: The indices are mapped to words from `bip39_english.txt`.

### 3. Seed Derivation
The mnemonic is converted into a 64-byte (512-bit) seed using `hashlib.pbkdf2_hmac` with:
- PRF: SHA512
- Password: The mnemonic string.
- Salt: "mnemonic" + optional passphrase.
- Iterations: 2048.

### 4. BIP32 HD Wallet
- **Master Key**: Derived by HMAC-SHA512 with key `"Bitcoin seed"` and the seed as data.
- **Child Key Derivation (CKDpriv)**:
  - **Hardened**: Data = `0x00 || parent_private_key || index`.
  - **Non-Hardened**: Data = `parent_public_key || index`.
  - The HMAC-SHA512 result is split into `IL` (used to tweak the private key) and `IR` (new chain code).
  - The Elliptic Curve math (adding `IL` to the parent private key modulo `n`) is handled manually in Python.

## Verification
You can verify the outputs of this tool by using [Ian Coleman's BIP39 Tool](https://iancoleman.io/bip39/):
1. Generate a mnemonic in this tool.
2. Paste it into the "BIP39 Mnemonic" field on the website.
3. Compare the **Seed**, **Master Private Key**, and derived addresses/keys.
4. Note: This tool displays raw hex keys. Public keys are shown in **compressed** format (starting with `02` or `03`).

### Example Test Case:
- **Entropy**: `00000000000000000000000000000000` (128 bits of zeros)
- **Mnemonic**: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
- **Seed**: `c55257c0d129294011c6f8ef2f1341c7...`
- **Master Private Key**: `e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01f1494b917c8436b35`
