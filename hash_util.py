import hashlib
import json
import os


def calculate_hashes(file_path):
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

        return {
            "filename": file_path,
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "md5": md5.hexdigest()
        }
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None


def save_hashes_to_json(hash_dict, json_filename="hashes.json"):
    with open(json_filename, "w") as f:
        json.dump(hash_dict, f, indent=4)
    print(f"[Log] Baseline hashes saved to '{json_filename}'.")


def verify_integrity(target_file, json_record):
    print(f"\n--- Verifying Integrity of '{target_file}' ---")

    try:
        with open(json_record, "r") as f:
            stored_data = json.load(f)
    except FileNotFoundError:
        print("Error: Hash record (JSON) not found.")
        return

    current_hashes = calculate_hashes(target_file)
    if not current_hashes:
        return

    print(f"Stored SHA-256:  {stored_data['sha256']}")
    print(f"Current SHA-256: {current_hashes['sha256']}")

    if current_hashes['sha256'] == stored_data['sha256']:
        print("RESULT: ✅ PASS. Integrity Verified.")
    else:
        print("RESULT: ❌ FAIL! WARNING: File tampering detected!")
        print("Detailed Algorithm Check:")
        if current_hashes['md5'] != stored_data['md5']:
            print(f" - MD5 Mismatch")
        if current_hashes['sha1'] != stored_data['sha1']:
            print(f" - SHA-1 Mismatch")