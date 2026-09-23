#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>

namespace fs = std::filesystem;

struct InjectResult {
    bool ok;
    std::string error;
    // Base address of the image the target's loader mapped for LoadLibraryW,
    // or 0 when it could not be determined.  The init handshake needs it:
    // deriving the base by matching the module NAME returns whatever
    // same-named module is already loaded, so the exported entry point could
    // be computed against the wrong image.
    uint64_t remote_base = 0;
};

// Inject a shared library into a running process using CreateRemoteThread + LoadLibrary.
InjectResult injectLibrary(int pid, const fs::path& lib_path);

// Resolve the transitive dependency closure of a DLL: every dependency
// found in the search directories (recursively).  Dependencies not found
// in any search dir are skipped (already loaded in the target or resolvable
// from the system search path).  The DLL itself is not included.
std::vector<fs::path> resolveDependencyClosure(
    const fs::path& dllPath,
    const std::vector<fs::path>& searchDirs);

// Eject (unload) a shared library from a process via EnumProcessModules + FreeLibrary.
InjectResult ejectLibrary(int pid, const fs::path& lib_path);

// Write InitParams into target process memory and call qt_commander_init.
// `remote_module_base` is the module base the target's loader returned for the
// library (InjectResult::remote_base).  Pass 0 only when it is unknown: the
// handshake then has to match the module by base name, which can pick a
// different, already-loaded image.
// Returns the TCP port the library is listening on, or 0 on error.
uint16_t performInitHandshake(
    int pid,
    const fs::path& lib_path,
    const std::string& workspace_path,
    const std::string& session_id,
    const std::string& token,
    const fs::path& port_file_path,
    uint64_t remote_module_base = 0
);

// Generate a cryptographically random 64-hex-character token.
std::string generateToken();
std::string generateToken(class IProcessOps& ops);

// Validate that the target PID is a Qt process by checking loaded modules.
bool isQtProcess(int pid);
bool isQtProcess(class IProcessOps& ops, int pid);

// Dependency-injected variants (accept IProcessOps for testability).
InjectResult injectLibrary(class IProcessOps& ops, int pid, const fs::path& lib_path);
InjectResult ejectLibrary(class IProcessOps& ops, int pid, const fs::path& lib_path);
uint16_t performInitHandshake(
    class IProcessOps& ops,
    int pid, const fs::path& lib_path,
    const std::string& workspace_path,
    const std::string& session_id,
    const std::string& token,
    const fs::path& port_file_path
);
