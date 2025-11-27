import hash_util


def run_step_2():
    print("--- Step 2: Simulating Tampering Attack ---")

    filename = "tampered.txt"
    malicious_content = "This is the original, secure financial data. Send money to Hacker."

    with open(filename, "w") as f:
        f.write(malicious_content)
    print(f"[Log] Attack simulation: Created '{filename}' with modified content.")

    hash_util.verify_integrity(filename, "hashes.json")

    hash_util.verify_integrity("original.txt", "hashes.json")


if __name__ == "__main__":
    run_step_2()