import os
import secrets
import hashlib
import hmac
from flask import Flask, render_template, request, jsonify
from wallet import generate_safe_entropy, mnemonic_to_seed, get_master_key, priv_to_pub, CKDpriv, WORDLIST, mnemonic_to_entropy

app = Flask(__name__)

# --- Helper to reconstruct the detailed 11-bit breakdown for the UI ---
def get_mnemonic_details(entropy_bytes):
    # This logic mimics 'entropy_to_mnemonic_with_details' from wallet.py
    # but returns a structured dictionary instead of printing.
    
    entropy_hex = entropy_bytes.hex()
    entropy_int = int.from_bytes(entropy_bytes, byteorder='big')
    entropy_bits = bin(entropy_int)[2:].zfill(len(entropy_bytes) * 8)
    
    # Checksum
    hash_entropy = hashlib.sha256(entropy_bytes).digest()
    checksum_length = len(entropy_bytes) * 8 // 32
    checksum_bits = bin(hash_entropy[0])[2:].zfill(8)[:checksum_length]
    
    total_bits = entropy_bits + checksum_bits
    
    lots = []
    mnemonic_words = []
    
    for i in range(0, len(total_bits), 11):
        chunk = total_bits[i:i+11]
        index = int(chunk, 2)
        word = WORDLIST[index]
        mnemonic_words.append(word)
        lots.append({
            "id": i//11 + 1,
            "bits": chunk,
            "index": index,
            "word": word
        })
        
    return {
        "entropy_hex": entropy_hex,
        "entropy_bits": entropy_bits,
        "checksum_bits": checksum_bits,
        "total_bits_len": len(total_bits),
        "lots": lots,
        "mnemonic": " ".join(mnemonic_words)
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/generate', methods=['POST'])
def generate():
    data = request.json
    bits = int(data.get('bits', 128))
    
    entropy = generate_safe_entropy(bits)
    details = get_mnemonic_details(entropy)
    
    # Generate keys
    seed = mnemonic_to_seed(details['mnemonic'])
    m_priv, m_chain = get_master_key(seed)
    m_pub = priv_to_pub(m_priv)
    
    return jsonify({
        "success": True,
        "details": details,
        "keys": {
            "seed_hex": seed.hex(),
            "master_private": m_priv.hex(),
            "master_chain": m_chain.hex(),
            "master_public": m_pub.hex()
        }
    })

@app.route('/api/import', methods=['POST'])
def import_mnemonic():
    data = request.json
    mnemonic = data.get('mnemonic', '').strip()
    
    try:
        # Verify and get entropy
        entropy = mnemonic_to_entropy(mnemonic)
        details = get_mnemonic_details(entropy)
        
        # Generate keys
        seed = mnemonic_to_seed(mnemonic)
        m_priv, m_chain = get_master_key(seed)
        m_pub = priv_to_pub(m_priv)
        
        return jsonify({
            "success": True,
            "details": details,
            "keys": {
                "seed_hex": seed.hex(),
                "master_private": m_priv.hex(),
                "master_chain": m_chain.hex(),
                "master_public": m_pub.hex()
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/derive', methods=['POST'])
def derive():
    data = request.json
    try:
        master_priv = bytes.fromhex(data.get('master_private'))
        master_chain = bytes.fromhex(data.get('master_chain'))
        path = data.get('path', 'm/0')
        
        segments = path.split("/")
        if segments[0] == 'm': segments = segments[1:]
        
        k, c = master_priv, master_chain
        
        for seg in segments:
            if not seg: continue
            if seg.endswith("'") or seg.endswith("h"):
                idx = int(seg.rstrip("'h")) + 0x80000000
            else:
                idx = int(seg)
            k, c = CKDpriv(k, c, idx)
            
        pub = priv_to_pub(k)
        
        return jsonify({
            "success": True,
            "path": path,
            "private_key": k.hex(),
            "public_key": pub.hex(),
            "chain_code": c.hex()
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
