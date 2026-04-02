#!/usr/bin/env python3
import sys

PAYLOAD_KEY = [0xA7, 0x3D, 0x8B, 0x52, 0xF1, 0x6C, 0xE4, 0x19]

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_binary> <output_header>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    encrypted = bytes(b ^ PAYLOAD_KEY[i % len(PAYLOAD_KEY)] for i, b in enumerate(data))

    with open(sys.argv[2], "w") as f:
        f.write("static const unsigned char payload_data[] = {\n")
        for i in range(0, len(encrypted), 16):
            chunk = encrypted[i:i+16]
            f.write("  " + ", ".join(f"0x{b:02x}" for b in chunk))
            if i + 16 < len(encrypted):
                f.write(",")
            f.write("\n")
        f.write("};\n")
        f.write(f"static const unsigned int payload_data_len = {len(encrypted)};\n")

    print(f"[+] Encrypted {len(data)} bytes -> {sys.argv[2]}")

if __name__ == "__main__":
    main()
