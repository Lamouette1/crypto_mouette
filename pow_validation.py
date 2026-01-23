import hashlib
import json
import time

def compute_hash(block, hash_func="sha256"):
    block_string = json.dumps(block, sort_keys=True).encode()
    if hash_func == "sha256":
        return hashlib.sha256(block_string).hexdigest()
    elif hash_func == "scrypt":
        # Scrypt is a memory-hard function, much slower by design
        return hashlib.scrypt(block_string, salt=b'salt', n=16384, r=8, p=1).hex()
    return None

def proof_of_work(block, difficulty, hash_func="sha256"):
    target = '0' * difficulty
    block['nonce'] = 0
    start_time = time.time()
    
    while True:
        hash_result = compute_hash(block, hash_func)
        if hash_result.startswith(target):
            end_time = time.time()
            return block['nonce'], hash_result, end_time - start_time
        block['nonce'] += 1

def run_benchmarks():
    print("==========================================")
    print("      PROOF OF WORK BENCHMARKS            ")
    print("==========================================")
    
    template = {
        "index": 1,
        "timestamp": time.time(),
        "data": "Learning Proof of Work",
        "previous_hash": "0000000000000000000000000000000000000000000000000000000000000b0b",
        "nonce": 0
    }
    
    # 6 might take a while, but let's try.
    difficulties = [1, 2, 3, 4, 5, 6]
    
    print(f"{ 'Diff':<5} | { 'Nonces':<12} | { 'Time (s)':<12} | {'Hash'}")
    print("-" * 80)
    
    for d in difficulties:
        block = template.copy()
        nonces, h, duration = proof_of_work(block, d)
        print(f"{d:<5} | {nonces:<12} | {duration:<12.5f} | {h[:20]}...")

    print("\n--- Scrypt Comparison (Difficulty 1) ---")
    block = template.copy()
    nonces, h, duration = proof_of_work(block, 1, hash_func="scrypt")
    print(f"Scrypt (n=16384) Diff 1: Nonces={nonces}, Time={duration:.5f}s")

if __name__ == "__main__":
    run_benchmarks()