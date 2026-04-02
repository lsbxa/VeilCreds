#!/usr/bin/env python3
import sys

EMBED_KEY = [0xC3, 0x87, 0x2E, 0xF5, 0x61, 0xB9, 0x0D, 0x4A]

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input> <var_name> <output>")
        sys.exit(1)

    input_file = sys.argv[1]
    var_name = sys.argv[2]
    output_file = sys.argv[3]

    with open(input_file, "rb") as f:
        data = f.read()

    encrypted = bytes(b ^ EMBED_KEY[i % len(EMBED_KEY)] for i, b in enumerate(data))

    with open(output_file, "w") as f:
        f.write(f"unsigned char {var_name}[] = {{\n")
        for i in range(0, len(encrypted), 12):
            chunk = encrypted[i:i+12]
            f.write("  " + ", ".join(f"0x{b:02x}" for b in chunk))
            if i + 12 < len(encrypted):
                f.write(",")
            f.write("\n")
        f.write("};\n")
        f.write(f"unsigned int {var_name}_len = {len(encrypted)};\n")

    print(f"[+] Encrypted {len(data)} bytes -> {output_file}")

if __name__ == "__main__":
    main()
