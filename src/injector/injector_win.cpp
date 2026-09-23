#define NOMINMAX
#include "injector.h"

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "bcrypt.lib")
#endif
#include <vector>
#include <string>
#include <set>
#include <cstdio>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstring>
#include <cctype>
#include <stdexcept>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Grace period granted to a remote thread that overran its wait before the
// injector gives up on it.  Remote threads are never terminated: the routines
// they run (LoadLibraryW, qt_commander_init, FreeLibrary) take the process
// loader lock, and TerminateThread does not release a critical section owned
// by the dying thread -- the lock would stay held forever and every later
// loader operation in the host process would block.
static const DWORD kExitGraceMs = 2000;

static std::string lastErrorString() {
    DWORD err = GetLastError();
    if (err == 0)
        return "success";

    LPWSTR buf = nullptr;
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buf), 0, nullptr);

    std::string msg;
    if (buf) {
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, buf,
                                           static_cast<int>(len),
                                           nullptr, 0, nullptr, nullptr);
        msg.resize(static_cast<size_t>(utf8Len));
        WideCharToMultiByte(CP_UTF8, 0, buf, static_cast<int>(len),
                             msg.data(), utf8Len, nullptr, nullptr);
        LocalFree(buf);
    }

    // Trim trailing whitespace / \r\n / '.'
    while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n' ||
                            msg.back() == ' ' || msg.back() == '.'))
        msg.pop_back();

    return "error " + std::to_string(err) + ": " + msg;
}

// ---------------------------------------------------------------------------
// PE export directory parser -- locate an exported function's RVA from a DLL
// file image loaded into memory.
// ---------------------------------------------------------------------------

static bool readFileBytes(const fs::path& path, std::vector<uint8_t>& out) {
    out.clear();
    HANDLE hFile = CreateFileW(path.wstring().c_str(), GENERIC_READ,
                                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    DWORD sizeHigh = 0;
    DWORD sizeLow = GetFileSize(hFile, &sizeHigh);
    if (sizeLow == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    out.resize(static_cast<size_t>(sizeLow) +
               (static_cast<size_t>(sizeHigh) << 32));

    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, out.data(), sizeLow, &bytesRead, nullptr);
    CloseHandle(hFile);
    return ok && bytesRead == sizeLow;
}

// Walk section headers to map a PE relative virtual address (RVA) to a file
// offset.  Returns `rva` as fallback when no section covers it.
static DWORD rvaToOffset(const IMAGE_NT_HEADERS* nt, DWORD rva) {
    const IMAGE_SECTION_HEADER* sect = IMAGE_FIRST_SECTION(nt);
    WORD count = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < count; ++i) {
        if (rva >= sect[i].VirtualAddress &&
            rva < sect[i].VirtualAddress + sect[i].Misc.VirtualSize) {
            return sect[i].PointerToRawData + (rva - sect[i].VirtualAddress);
        }
    }
    return rva; // fallback (flat layout or misaligned)
}

// Read a 2-byte or 4-byte value at a file offset.
static WORD readWord(const uint8_t* base, DWORD offset) {
    WORD v;
    memcpy(&v, base + offset, 2);
    return v;
}

static DWORD readDword(const uint8_t* base, DWORD offset) {
    DWORD v;
    memcpy(&v, base + offset, 4);
    return v;
}

// Find the RVA of an exported function by name.  Returns 0 if not found.
static DWORD findExportRva(const std::vector<uint8_t>& dllBytes,
                           const std::string& exportName) {
    if (dllBytes.size() < sizeof(IMAGE_DOS_HEADER))
        return 0;

    const auto* dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(dllBytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    DWORD ntOffset = dos->e_lfanew;
    if (dllBytes.size() < static_cast<size_t>(ntOffset) + sizeof(IMAGE_NT_HEADERS))
        return 0;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        dllBytes.data() + ntOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    // Export directory
    const IMAGE_DATA_DIRECTORY& expDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.Size == 0 || expDir.VirtualAddress == 0)
        return 0;

    const uint8_t* base = dllBytes.data();
    DWORD expDirOffset = rvaToOffset(nt, expDir.VirtualAddress);
    const auto* exp =
        reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + expDirOffset);

    DWORD namesOffset = rvaToOffset(nt, exp->AddressOfNames);
    DWORD ordinalsOffset = rvaToOffset(nt, exp->AddressOfNameOrdinals);
    DWORD functionsOffset = rvaToOffset(nt, exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        DWORD nameRva = readDword(base, namesOffset + i * 4);
        DWORD nameOffset = rvaToOffset(nt, nameRva);
        const char* namePtr =
            reinterpret_cast<const char*>(base + nameOffset);

        if (exportName == namePtr) {
            WORD ordinal = readWord(base, ordinalsOffset + i * 2);
            DWORD funcRva = readDword(
                base, functionsOffset + static_cast<DWORD>(ordinal) * 4);
            return funcRva;
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// PE import directory parser -- list a DLL's direct dependencies.
// ---------------------------------------------------------------------------

// Parse the import table of a PE image and return the imported DLL names
// (e.g. "Qt5Widgets.dll") in file order, de-duplicated.
static std::vector<std::string> parseImportDependencies(
    const std::vector<uint8_t>& dllBytes)
{
    std::vector<std::string> deps;
    if (dllBytes.size() < sizeof(IMAGE_DOS_HEADER))
        return deps;

    const auto* dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(dllBytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return deps;

    DWORD ntOffset = dos->e_lfanew;
    if (dllBytes.size() < static_cast<size_t>(ntOffset) + sizeof(IMAGE_NT_HEADERS))
        return deps;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        dllBytes.data() + ntOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return deps;

    const IMAGE_DATA_DIRECTORY& impDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size == 0 || impDir.VirtualAddress == 0)
        return deps;

    const uint8_t* base = dllBytes.data();
    DWORD impOffset = rvaToOffset(nt, impDir.VirtualAddress);

    // The import descriptor array is terminated by an all-zero entry.
    for (DWORD i = 0; ; ++i) {
        const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            base + impOffset + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (desc->Name == 0)
            break;
        DWORD nameOffset = rvaToOffset(nt, desc->Name);
        if (nameOffset >= dllBytes.size())
            continue;
        const char* name =
            reinterpret_cast<const char*>(base + nameOffset);
        if (std::find(deps.begin(), deps.end(), std::string(name)) ==
            deps.end())
            deps.emplace_back(name);
    }
    return deps;
}

// Resolve the transitive dependency closure of a DLL: every dependency
// found in the search directories is resolved to a path (their own
// dependencies are resolved recursively); dependencies not found are
// skipped -- they are either already loaded in the target process or
// resolvable from the system search path.  Result order is breadth-first;
// the DLL itself is not included.
std::vector<fs::path> resolveDependencyClosure(
    const fs::path& dllPath,
    const std::vector<fs::path>& searchDirs)
{
    std::vector<fs::path> result;
    std::vector<fs::path> queue;
    std::vector<std::string> seen;  // lowercase base names already handled

    auto lowerName = [](const std::string& s) {
        std::string t = s;
        std::transform(t.begin(), t.end(), t.begin(),
                       [](unsigned char c) { return static_cast<char>(
                           std::tolower(c)); });
        return t;
    };
    auto isSeen = [&](const std::string& key) {
        return std::find(seen.begin(), seen.end(), key) != seen.end();
    };

    seen.push_back(lowerName(dllPath.filename().string()));
    queue.push_back(dllPath);

    while (!queue.empty()) {
        const fs::path cur = queue.back();
        queue.pop_back();

        std::vector<uint8_t> bytes;
        if (!readFileBytes(cur, bytes))
            continue;
        for (const std::string& dep : parseImportDependencies(bytes)) {
            const std::string key = lowerName(dep);
            if (isSeen(key))
                continue;
            seen.push_back(key);

            fs::path found;
            for (const fs::path& dir : searchDirs) {
                const fs::path cand = dir / dep;
                if (fs::exists(cand)) {
                    found = cand;
                    break;
                }
            }
            if (found.empty())
                continue;  // not in search dirs -- process/system resolves it
            result.push_back(found);
            queue.push_back(found);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// InitParams -- must match src/library/api.h exactly (1024-byte fixed layout)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct InitParams {
    uint32_t version;           // offset 0
    uint32_t total_size;        // offset 4
    char workspace_path[256];   // offset 8
    char session_id[13];        // offset 264
    char token[65];             // offset 277
    char port_file_path[256];   // offset 342
    uint8_t reserved[426];      // offset 598 -> total 1024
};
#pragma pack(pop)
static_assert(sizeof(InitParams) == 1024, "InitParams size must be 1024 bytes");

// ---------------------------------------------------------------------------
// injectDll  --  load a single DLL into the target via CreateRemoteThread
//
// Reports the module base the target's loader returned (via *outBase).
// Callers that must call into the injected module need that base: deriving it
// by matching the module NAME can pick a different, already-loaded module.
// ---------------------------------------------------------------------------
static InjectResult injectDll(int pid, const fs::path& dllPath,
                              HMODULE* outBase = nullptr) {
    if (outBase)
        *outBase = nullptr;

    // 1. Open target process with minimal required rights
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION,
        FALSE, static_cast<DWORD>(pid));
    if (!hProcess) {
        return {false, "OpenProcess failed for PID " +
                           std::to_string(pid) + ": " + lastErrorString()};
    }

    // 2. Convert DLL path to wide string
    std::wstring libPathW = dllPath.wstring();
    size_t pathBytes = (libPathW.size() + 1) * sizeof(wchar_t);

    // 3. Allocate memory in target for the path string
    void* remotePath = VirtualAllocEx(hProcess, nullptr, pathBytes,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (!remotePath) {
        CloseHandle(hProcess);
        return {false, "VirtualAllocEx failed: " + lastErrorString()};
    }

    // 4. Write DLL path into target memory
    if (!WriteProcessMemory(hProcess, remotePath, libPathW.c_str(), pathBytes,
                            nullptr)) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return {false, "WriteProcessMemory failed: " + lastErrorString()};
    }

    // 5. Get address of LoadLibraryW in kernel32
    HMODULE kernel32 = GetModuleHandleW(L"kernel32");
    if (!kernel32) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return {false, "GetModuleHandle(kernel32) failed: " +
                           lastErrorString()};
    }

    FARPROC loadLibAddr = GetProcAddress(kernel32, "LoadLibraryW");
    if (!loadLibAddr) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return {false, "GetProcAddress(LoadLibraryW) failed: " +
                           lastErrorString()};
    }

    // 6. Create remote thread that calls LoadLibraryW(path)
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibAddr),
        remotePath, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return {false, "CreateRemoteThread failed: " + lastErrorString()};
    }

    // 7. Wait for thread to finish.  On timeout, grant one short grace period
    //    instead of calling TerminateThread: the remote routine is
    //    LoadLibraryW, which holds the process loader lock for its whole
    //    duration, and a terminated thread never releases a lock it owns --
    //    every later loader operation in the target would block forever.
    DWORD waitResult = WaitForSingleObject(hThread, 30000);
    if (waitResult == WAIT_TIMEOUT) {
        waitResult = WaitForSingleObject(hThread, kExitGraceMs);
        if (waitResult != WAIT_OBJECT_0) {
            // Still inside LoadLibraryW, which may be reading the path right
            // now: the remote allocation is deliberately leaked (the target
            // reclaims it at process exit) rather than freed under a live
            // thread, which would be a use-after-free.
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return {false, "remote LoadLibraryW is still running after 30 s + "
                           "grace; the load may still complete -- do not "
                           "retry blindly"};
        }
    } else if (waitResult == WAIT_FAILED) {
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return {false, "WaitForSingleObject failed: " + lastErrorString()};
    }

    // 8. Get the HMODULE (DLL base) from the thread exit code
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode) || exitCode == 0) {
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return {false, "LoadLibraryW returned NULL in target process"};
    }

    // 9. Resolve the FULL 64-bit base while the process handles are open.
    //    LoadLibraryW's HMODULE comes back through the thread exit code, and
    //    that is a DWORD: a 64-bit target maps DLLs above 4 GB (typically
    //    0x7FF...), so the exit code keeps only the low 32 bits and must never
    //    be used as an address.  Those bits still identify the module exactly,
    //    so find the module that carries them and report its real address.
    //    A second, read-only handle is used because EnumProcessModules needs
    //    PROCESS_VM_READ, which the injection handle deliberately omits.
    HMODULE fullBase = nullptr;
    if (outBase) {
        HANDLE hQuery = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
            static_cast<DWORD>(pid));
        if (hQuery) {
            DWORD needed = 0;
            EnumProcessModules(hQuery, nullptr, 0, &needed);
            std::vector<HMODULE> modules(needed / sizeof(HMODULE));
            if (EnumProcessModules(
                    hQuery, modules.data(),
                    static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                    &needed)) {
                for (HMODULE hMod : modules) {
                    if ((reinterpret_cast<uintptr_t>(hMod) & 0xFFFFFFFFu) ==
                        static_cast<uintptr_t>(exitCode)) {
                        fullBase = hMod;
                        break;
                    }
                }
            }
            CloseHandle(hQuery);
        }
    }

    // 10. Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    // Unknown base stays null: the caller falls back to its own lookup rather
    // than being handed a truncated address.
    if (outBase)
        *outBase = fullBase;

    return {true, ""};
}

// ---------------------------------------------------------------------------
// injectLibrary  --  preload dependencies, then inject the library
//
// LoadLibraryW resolves the library's imports against modules already
// loaded in the target process.  Every dependency found next to the library
// that is NOT yet loaded in the target is loaded up front (transitively --
// the loader does not search the parent DLL's directory for ITS
// dependencies, so the whole closure must be preloaded).  This keeps
// deployed app directories clean: no manual Qt DLL copies next to the
// target executable.
//
// Modules already loaded in the target are skipped: re-loading them would
// re-run their static initializers (Qt5Quick re-registers the "QtQuick 2"
// QML module and qFatal's on the duplicate registration, killing the
// target process), and the main library's implicit imports reuse the
// already-loaded instances anyway.
// ---------------------------------------------------------------------------
// Recursively preload the dependencies of `dll` (in topological order:
// a dependency is loaded before the DLL that imports it, because the
// loader resolves imports from the target's search path, not from the
// preloaded DLL's own directory).  `loaded` tracks modules already in the
// target OR preloaded by us; `handled` guards against cycles.
// Returns false with `err` set on failure.
static bool preloadDepsRecursive(int pid,
                                 const fs::path& dll,
                                 const std::vector<fs::path>& searchDirs,
                                 std::set<std::wstring>& loaded,
                                 std::set<std::wstring>& handled,
                                 std::string& err)
{
    std::vector<uint8_t> bytes;
    if (!readFileBytes(dll, bytes))
        return true;  // unreadable -- skip (unexpected; closure is pre-validated)

    for (const std::string& depName : parseImportDependencies(bytes)) {
        fs::path depPath;
        for (const fs::path& dir : searchDirs) {
            const fs::path cand = dir / depName;
            if (fs::exists(cand)) {
                depPath = cand;
                break;
            }
        }
        if (depPath.empty())
            continue;  // system DLL or already-resolvable -- skip

        const std::wstring key = depPath.filename().wstring();
        if (handled.count(key))
            continue;
        handled.insert(key);
        if (loaded.count(key))
            continue;  // already in the target -- implicit reuse is enough

        if (!preloadDepsRecursive(pid, depPath, searchDirs,
                                  loaded, handled, err))
            return false;  // a transitive dependency failed
        if (!loaded.count(key)) {
            InjectResult r = injectDll(pid, depPath);
            if (!r.ok) {
                err = "preload dependency " + depPath.filename().string() +
                      " (" + depPath.string() + "): " + r.error;
                return false;
            }
            loaded.insert(key);
        }
    }
    return true;
}

InjectResult injectLibrary(int pid, const fs::path& lib_path) {
    // The remote thread's LoadLibraryW resolves relative paths against the
    // TARGET process's current directory -- not ours -- so preload and
    // library paths must be absolute.
    const fs::path absLib = fs::absolute(lib_path).lexically_normal();

    // Base names of modules already loaded in the target process.
    std::set<std::wstring> loaded;
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                          PROCESS_VM_READ,
                                      FALSE, static_cast<DWORD>(pid));
        if (hProcess) {
            DWORD needed = 0;
            EnumProcessModules(hProcess, nullptr, 0, &needed);
            std::vector<HMODULE> modules(needed / sizeof(HMODULE));
            if (EnumProcessModules(hProcess, modules.data(),
                                   static_cast<DWORD>(
                                       modules.size() * sizeof(HMODULE)),
                                   &needed)) {
                for (HMODULE hMod : modules) {
                    wchar_t modName[MAX_PATH]{};
                    if (GetModuleBaseNameW(hProcess, hMod, modName, MAX_PATH))
                        loaded.insert(std::wstring(modName));
                }
            }
            CloseHandle(hProcess);
        }
    }

    std::set<std::wstring> handled;
    std::string err;
    if (!preloadDepsRecursive(pid, absLib, {absLib.parent_path()},
                              loaded, handled, err))
        return {false, err};

    // Report the main library's own base: the init handshake must compute the
    // exported entry point from the image the target actually loaded.
    HMODULE libBase = nullptr;
    InjectResult r = injectDll(pid, absLib, &libBase);
    r.remote_base = reinterpret_cast<uint64_t>(libBase);
    return r;
}

// ---------------------------------------------------------------------------
// performInitHandshake
// ---------------------------------------------------------------------------
uint16_t performInitHandshake(int pid, const fs::path& lib_path,
                              const std::string& workspace_path,
                              const std::string& session_id,
                              const std::string& token,
                              const fs::path& port_file_path,
                              uint64_t remote_module_base) {
    // 1. Read DLL from disk and find the RVA of qt_commander_init
    std::vector<uint8_t> dllBytes;
    if (!readFileBytes(lib_path, dllBytes)) {
        return 0;
    }

    DWORD initRva = findExportRva(dllBytes, "qt_commander_init");
    if (initRva == 0) {
        return 0;
    }

    // 2. Open the target process
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, static_cast<DWORD>(pid));
    if (!hProcess) {
        return 0;
    }

    // 3. Determine the module base the entry-point RVA is relative to.
    //    Preferred: the base of the image LoadLibraryW mapped inside the
    //    target (reported by injectDll).  Fallback only when the caller has no
    //    base: match the base name against the target's module list.  Windows
    //    hands back the already-loaded module for any same-base-name match,
    //    so the name lookup can silently pick a different image, and the RVA
    //    would then be applied to the wrong base.
    HMODULE dllBase = reinterpret_cast<HMODULE>(
        static_cast<uintptr_t>(remote_module_base));
    if (!dllBase) {
        std::wstring libNameW = lib_path.filename().wstring();

        DWORD needed = 0;
        EnumProcessModules(hProcess, nullptr, 0, &needed);
        std::vector<HMODULE> modules(needed / sizeof(HMODULE));
        if (!EnumProcessModules(
                hProcess, modules.data(),
                static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                &needed)) {
            CloseHandle(hProcess);
            return 0;
        }

        for (const auto& hMod : modules) {
            wchar_t modName[MAX_PATH]{};
            if (GetModuleBaseNameW(hProcess, hMod, modName, MAX_PATH) == 0)
                continue;
            if (_wcsicmp(modName, libNameW.c_str()) == 0) {
                dllBase = hMod;
                break;
            }
        }

        if (!dllBase) {
            CloseHandle(hProcess);
            return 0;
        }
    }

    // 4. Compute entry-point address in the target
    void* initAddr = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(dllBase) +
        static_cast<uintptr_t>(initRva));

    // 5. Fill InitParams
    InitParams params{};
    params.version = 1;
    params.total_size = 1024;

    auto safeCopy = [](char* dst, size_t dstLen, const std::string& src) {
        size_t n = (std::min)(src.size(), dstLen - 1);
        memcpy(dst, src.data(), n);
        dst[n] = '\0';
    };

    safeCopy(params.workspace_path, sizeof(params.workspace_path),
             workspace_path);
    safeCopy(params.session_id, sizeof(params.session_id), session_id);
    safeCopy(params.token, sizeof(params.token), token);
    safeCopy(params.port_file_path, sizeof(params.port_file_path),
             port_file_path.string());

    // 6. Allocate memory in target for InitParams
    void* remoteParams = VirtualAllocEx(hProcess, nullptr, sizeof(InitParams),
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    if (!remoteParams) {
        CloseHandle(hProcess);
        return 0;
    }

    // 7. Write InitParams into target
    if (!WriteProcessMemory(hProcess, remoteParams, &params,
                            sizeof(InitParams), nullptr)) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    // 8. Create remote thread calling qt_commander_init(params)
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(initAddr),
        remoteParams, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    // 9. Wait for the init call to finish (it copies the params and returns
    //    quickly).  On timeout, grant one short grace period instead of
    //    terminating the thread: qt_commander_init starts the RPC thread and
    //    touches the loader, and a thread killed inside the loader leaves the
    //    process loader lock held forever.
    DWORD waitResult = WaitForSingleObject(hThread, 10000);
    if (waitResult == WAIT_TIMEOUT)
        waitResult = WaitForSingleObject(hThread, kExitGraceMs);
    if (waitResult != WAIT_OBJECT_0) {
        // Still running (or unqueryable): it may still be reading the params
        // it was handed, so that allocation is deliberately leaked -- the
        // target reclaims it at process exit -- instead of being freed under
        // a live thread.
        CloseHandle(hThread);
        CloseHandle(hProcess);
        std::fprintf(stderr,
                     "[initHandshake] qt_commander_init is still running after "
                     "10 s + grace; the injection may yet complete -- do not "
                     "retry blindly\n");
        return 0;
    }
    CloseHandle(hThread);

    // 10. Free the remote params allocation
    VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    // 11. Poll the port file with exponential backoff until it carries OUR
    //     token.  A file left behind by a killed or timed-out run parses
    //     perfectly well, so breaking on the first parseable file made every
    //     later injection into that PID fail on the token comparison that
    //     used to happen afterwards.  Unreadable, partial and foreign files
    //     are simply "not ours yet" and keep the loop going.
    int delayMs = 50;
    uint16_t port = 0;

    for (int attempt = 0; attempt < 10; ++attempt) {
        if (attempt > 0) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(delayMs));
            delayMs = (std::min)(delayMs * 2, 3200);
        }

        std::ifstream inFile(port_file_path);
        if (!inFile.is_open())
            continue;

        std::string line;
        if (!std::getline(inFile, line))
            continue;

        uint16_t candidate = 0;
        try {
            candidate = static_cast<uint16_t>(std::stoi(line));
        } catch (...) {
            continue;  // not a port line we can use
        }
        if (candidate == 0)
            continue;

        std::string fileToken;
        if (!std::getline(inFile, fileToken))
            continue;

        // Trim whitespace
        auto trim = [](std::string& s) {
            s.erase(0, s.find_first_not_of(" \t\r\n"));
            s.erase(s.find_last_not_of(" \t\r\n") + 1);
        };
        trim(fileToken);

        if (fileToken != token)
            continue;  // foreign or half-written file -- keep polling

        port = candidate;
        break;
    }

    return port;
}

// ---------------------------------------------------------------------------
// Remote-image helpers (eject path)
// ---------------------------------------------------------------------------

// Read `size` bytes from the target.  False on a short or unreadable read.
static bool readRemoteBytes(HANDLE hProcess, uintptr_t addr, void* buf,
                            size_t size) {
    SIZE_T got = 0;
    return ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), buf,
                             size, &got) != 0 && got == size;
}

// Resolve an exported function inside the module AS LOADED IN THE TARGET.
// Returns 0 when the loaded image does not export the name or its headers
// cannot be read.
//
// The address must not be derived from the file on disk: the eject path jumps
// straight to whatever this returns, so an RVA taken from a rebuilt (or just
// older) file would be a call to an arbitrary address inside the host process.
static uintptr_t findRemoteExport(HANDLE hProcess, HMODULE base,
                                  const char* name) {
    const uintptr_t modBase = reinterpret_cast<uintptr_t>(base);

    IMAGE_DOS_HEADER dos{};
    if (!readRemoteBytes(hProcess, modBase, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    // Read the NT headers as raw bytes and locate the export directory from
    // the optional-header magic: PE32 and PE32+ place DataDirectory at
    // different offsets, and a 64-bit injector may be looking at a 32-bit
    // (WOW64) target.
    uint8_t nt[sizeof(IMAGE_NT_HEADERS)]{};
    if (!readRemoteBytes(hProcess, modBase + static_cast<DWORD>(dos.e_lfanew),
                         nt, sizeof(nt)))
        return 0;

    DWORD signature = 0;
    memcpy(&signature, nt, sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE)
        return 0;

    WORD magic = 0;
    memcpy(&magic, nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER),
           sizeof(magic));
    const size_t ddOffset =
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        (magic == 0x20B ? 112 : 96) +
        IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof(IMAGE_DATA_DIRECTORY);
    if (ddOffset + sizeof(IMAGE_DATA_DIRECTORY) > sizeof(nt))
        return 0;

    DWORD expRva = 0;
    DWORD expSize = 0;
    memcpy(&expRva, nt + ddOffset, sizeof(expRva));
    memcpy(&expSize, nt + ddOffset + sizeof(expRva), sizeof(expSize));
    if (expRva == 0 || expSize == 0)
        return 0;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!readRemoteBytes(hProcess, modBase + expRva, &exp, sizeof(exp)))
        return 0;

    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        DWORD nameRva = 0;
        if (!readRemoteBytes(hProcess, modBase + exp.AddressOfNames + i * 4,
                             &nameRva, sizeof(nameRva)))
            return 0;

        char remoteName[64]{};
        if (!readRemoteBytes(hProcess, modBase + nameRva, remoteName,
                             sizeof(remoteName) - 1))
            continue;
        if (strcmp(remoteName, name) != 0)
            continue;

        WORD ordinal = 0;
        if (!readRemoteBytes(hProcess,
                             modBase + exp.AddressOfNameOrdinals + i * 2,
                             &ordinal, sizeof(ordinal)))
            return 0;

        DWORD funcRva = 0;
        if (!readRemoteBytes(hProcess,
                             modBase + exp.AddressOfFunctions +
                                 static_cast<DWORD>(ordinal) * 4,
                             &funcRva, sizeof(funcRva)))
            return 0;

        // A forwarded export holds a name string inside the export directory
        // instead of code -- there is nothing callable here.
        if (funcRva >= expRva && funcRva < expRva + expSize)
            return 0;

        return modBase + funcRva;
    }

    return 0;
}

// Call a parameter-less routine in the target and wait for it.  False means
// the call could not be started or did not finish in time -- the caller must
// not assume the routine did nothing.
static bool callRemoteNoArg(HANDLE hProcess, uintptr_t addr, DWORD timeoutMs,
                            DWORD& exitCode) {
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(addr), nullptr, 0, nullptr);
    if (!hThread)
        return false;

    // Never TerminateThread: the routine may hold a lock (loader or the
    // library's session mutex) that the target process still needs.
    const DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);
    if (waitResult != WAIT_OBJECT_0) {
        CloseHandle(hThread);
        return false;
    }

    const bool ok = GetExitCodeThread(hThread, &exitCode) != 0;
    CloseHandle(hThread);
    return ok;
}

// ---------------------------------------------------------------------------
// ejectLibrary
// ---------------------------------------------------------------------------
InjectResult ejectLibrary(int pid, const fs::path& lib_path) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, static_cast<DWORD>(pid));
    if (!hProcess) {
        return {false, "ejectLibrary: OpenProcess failed: " + lastErrorString()};
    }

    const std::wstring libNameW = lib_path.filename().wstring();
    auto findModule = [&](HMODULE& out) {
        DWORD needed = 0;
        EnumProcessModules(hProcess, nullptr, 0, &needed);
        std::vector<HMODULE> modules(needed / sizeof(HMODULE));
        if (!EnumProcessModules(hProcess, modules.data(),
                                static_cast<DWORD>(
                                    modules.size() * sizeof(HMODULE)),
                                &needed))
            return false;

        out = nullptr;
        for (const auto& hMod : modules) {
            wchar_t modName[MAX_PATH]{};
            if (GetModuleBaseNameW(hProcess, hMod, modName, MAX_PATH) &&
                _wcsicmp(modName, libNameW.c_str()) == 0) {
                out = hMod;
                break;
            }
        }
        return true;
    };

    // 1. Resolve the module in the target.
    HMODULE dllBase = nullptr;
    if (!findModule(dllBase)) {
        CloseHandle(hProcess);
        return {false, "ejectLibrary: EnumProcessModules failed: " +
                           lastErrorString()};
    }
    if (!dllBase) {
        CloseHandle(hProcess);
        return {true, ""};  // never loaded (or already unloaded)
    }

    // 2. Ask the library to end its session.  FreeLibrary alone would drop the
    //    reference count while the RPC thread is still blocked inside the
    //    module; the library pins itself for that thread's lifetime, so the
    //    unload would silently not happen and this command would report
    //    success for an eject that never took effect.
    const uintptr_t shutdownFn =
        findRemoteExport(hProcess, dllBase, "qt_commander_request_shutdown");
    if (shutdownFn) {
        DWORD ignored = 0;
        callRemoteNoArg(hProcess, shutdownFn, 2000, ignored);
    }

    // 3. Wait (bounded) for the session slot to be released.  Poll the state
    //    instead of guessing a fixed delay: the RPC thread only clears it
    //    after its accept loop and connection teardown have finished.
    const uintptr_t stateFn =
        findRemoteExport(hProcess, dllBase, "qt_commander_session_state");
    if (stateFn) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(3000);
        bool active = true;  // "unknown" counts as active: never unload blind
        while (true) {
            DWORD state = 0;
            if (callRemoteNoArg(hProcess, stateFn, 1000, state)) {
                active = (state != 0);
                if (!active)
                    break;
            }
            if (std::chrono::steady_clock::now() >= deadline)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (active) {
            CloseHandle(hProcess);
            return {false, "refusing to unload: a library session is still "
                           "active (reconnect and shut down the client first)"};
        }
    }

    // 4. Unload: exactly ONE FreeLibrary for the one reference this injector
    //    added with LoadLibraryW.  The old loop kept calling FreeLibrary until
    //    the module disappeared, which necessarily dropped references the
    //    injector never held -- it could unload a module the host still uses.
    FARPROC freeLibAddr = GetProcAddress(
        GetModuleHandleW(L"kernel32"), "FreeLibrary");
    if (!freeLibAddr) {
        CloseHandle(hProcess);
        return {false, "ejectLibrary: GetProcAddress(FreeLibrary) failed"};
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(freeLibAddr),
        dllBase, 0, nullptr);
    if (!hThread) {
        CloseHandle(hProcess);
        return {false, "ejectLibrary: CreateRemoteThread failed: " +
                           lastErrorString()};
    }

    DWORD waitResult = WaitForSingleObject(hThread, 15000);
    if (waitResult == WAIT_TIMEOUT)
        waitResult = WaitForSingleObject(hThread, kExitGraceMs);
    if (waitResult != WAIT_OBJECT_0) {
        // FreeLibrary never takes the loader lock for long, but a thread
        // killed inside the loader would leave that lock held forever.
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return {false, "ejectLibrary: remote FreeLibrary is still running "
                       "after 15 s + grace; the unload may still complete -- "
                       "do not retry blindly"};
    }

    // FreeLibrary returns nonzero on success; zero means the reference count
    // did not drop (e.g. a bad handle).
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode) || exitCode == 0) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return {false, "ejectLibrary: FreeLibrary returned FALSE "
                       "in target process"};
    }
    CloseHandle(hThread);

    // 5. Report honestly: the module is only really gone if it is no longer in
    //    the target's module list.  FreeLibrary can succeed while another
    //    reference (a pin, or the host's own LoadLibrary) keeps it mapped.
    HMODULE after = nullptr;
    if (!findModule(after)) {
        CloseHandle(hProcess);
        return {false, "ejectLibrary: EnumProcessModules failed: " +
                           lastErrorString()};
    }
    CloseHandle(hProcess);

    if (after) {
        return {false, "ejectLibrary: module still loaded after FreeLibrary "
                       "(reference held elsewhere)"};
    }
    return {true, ""};
}

// ---------------------------------------------------------------------------
// isQtProcess
// ---------------------------------------------------------------------------
bool isQtProcess(int pid) {
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
    if (!hProcess) return false;

    HMODULE mods[1024];
    DWORD needed = 0;
    bool found = false;
    if (EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) {
        int count = needed / sizeof(HMODULE);
        for (int i = 0; i < count && !found; ++i) {
            wchar_t name[MAX_PATH]{};
            if (GetModuleBaseNameW(hProcess, mods[i], name, MAX_PATH)) {
                std::wstring wn(name);
                found = (wn.find(L"Qt5Core") != std::wstring::npos ||
                         wn.find(L"Qt6Core") != std::wstring::npos);
            }
        }
    }
    CloseHandle(hProcess);
    return found;
}

// ---------------------------------------------------------------------------
// generateToken
// ---------------------------------------------------------------------------
std::string generateToken() {
    uint8_t bytes[32];  // 32 bytes -> 64 hex chars
    NTSTATUS status = BCryptGenRandom(
        nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
    static const char hex[] = "0123456789abcdef";
    std::string token;
    token.reserve(64);
    for (int i = 0; i < 32; ++i) {
        token += hex[bytes[i] >> 4];
        token += hex[bytes[i] & 0x0F];
    }
    // Zero the raw bytes after use
    SecureZeroMemory(bytes, sizeof(bytes));
    return token;
}
