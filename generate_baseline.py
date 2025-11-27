import hash_util


def run_step_1():
    print("--- Step 1: Creating Baseline Data ---")

    filename = "original.txt"
    content = "This is the original, secure financial data. Do not alter."

    with open(filename, "w") as f:
        f.write(content)
    print(f"[Log] Created '{filename}'.")

    file_hashes = hash_util.calculate_hashes(filename)

    hash_util.save_hashes_to_json(file_hashes, "hashes.json")


if __name__ == "__main__":
    run_step_1()