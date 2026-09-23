// Port-file tamper resistance AFTER a successful handshake.
//
// History: this file used to assert exit codes 4 and 5 ("port file not found",
// "token mismatch").  Both were produced by main.cpp re-reading the port file
// AFTER performInitHandshake had already succeeded -- a pure TOCTOU that could
// only ever turn a good injection into a reported failure.  That re-read is
// gone: the handshake deletes any stale file before injecting and then polls
// until it sees *our* token, so nothing downstream may depend on the file
// again.  Exit 4 and 5 therefore no longer exist (a failed handshake is 3).
//
// What is still worth testing is the property the re-read was breaking:
// tampering with the port file after a successful handshake must NOT be
// reported as a failure.  The file keeps its historical name so
// tests/CMakeLists.txt needs no change.
#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <thread>
#include <chrono>
#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include "test_util.h"

static int passed = 0, total = 0;
#define CHECK(cond, msg) do { total++; if (cond) { passed++; } else { printf("FAIL %s:%d — %s\n", __FILE__, __LINE__, msg); } } while(0)

// Auto-discover binary paths (same logic as test_e2e.cpp)
static std::string find_binary(const char* name) {
    const char* bases[] = {
        ".", "..",                           // binary-dir or parent (ctest)
        "build", "build/msvc",
        "tests/test-apps/widget", "tests",
        "../src/library", "../tests/test-apps/widget",
        "build/msvc/tests/test-apps/widget",
        "build/msvc/src/library", "src/library",
        "build/msvc/src/injector/Release",
        "../build/msvc", nullptr
    };
    for (int i = 0; bases[i]; i++) {
        std::string p = std::string(bases[i]) + "/" + name;
        if (GetFileAttributesA(p.c_str()) != INVALID_FILE_ATTRIBUTES) {
            // CreateProcess cannot reliably resolve relative paths with
            // directory separators; return an absolute path.
            char full[MAX_PATH];
            if (GetFullPathNameA(p.c_str(), MAX_PATH, full, nullptr) > 0)
                return full;
            return p;
        }
    }
    return "";
}

static int run_cov_injector(DWORD pid, const std::string& lib, const std::string& pf, int sleep_ms) {
    std::string ip = find_binary("qt-injector.exe");
    if (ip.empty()) return -1;
    std::string cmd = ip + " " + std::to_string(pid) + " \"" + lib + "\" \"" + pf + "\" --sleep-before-check " + std::to_string(sleep_ms);
    STARTUPINFOA si = {sizeof(si)}; PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) return -1;
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD ec = 99; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)ec;
}

// Launch the widget target, or return 0 when it / the library is unavailable.
static DWORD launch_target(PROCESS_INFORMATION& pi, std::string& lib) {
    std::string tp = find_binary("qt-widget-test.exe");
    if (tp.empty()) { printf("SKIP: qt-widget-test.exe not found\n"); return 0; }
    STARTUPINFOA si = {sizeof(si)};
    pi = PROCESS_INFORMATION{};
    if (!CreateProcessA(nullptr, (LPSTR)tp.c_str(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        CHECK(false, "launch Qt test app"); return 0;
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));
    lib = find_binary("libqt-commander.dll");
    if (lib.empty()) {
        printf("SKIP: libqt-commander.dll not found\n");
        TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        pi = PROCESS_INFORMATION{};
        return 0;
    }
    return pi.dwProcessId;
}

static void stop_target(PROCESS_INFORMATION& pi) {
    if (!pi.hProcess) return;
    TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    pi = PROCESS_INFORMATION{};
}

void test_port_file_deleted_after_handshake() {
    PROCESS_INFORMATION pi{}; std::string lib;
    DWORD pid = launch_target(pi, lib);
    if (!pid) return;

    std::string pf = std::string(getenv("TEMP") ? getenv("TEMP") : ".") + "\\e2e_exit4.txt";
    DeleteFileA(pf.c_str());

    // Remove the handshake file while the injector is past its handshake.
    std::thread killer([&pf]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        DeleteFileA(pf.c_str());
    });

    int ec = run_cov_injector(pid, lib, pf, 3000);
    killer.join();

    printf("Exit code with port file deleted after the handshake: %d\n", ec);
    CHECK(ec == 0, (std::string("injection still succeeds, got ") + std::to_string(ec)).c_str());

    stop_target(pi);
}

void test_token_overwritten_after_handshake() {
    PROCESS_INFORMATION pi{}; std::string lib;
    DWORD pid = launch_target(pi, lib);
    if (!pid) return;

    std::string pf = std::string(getenv("TEMP") ? getenv("TEMP") : ".") + "\\e2e_exit5.txt";
    DeleteFileA(pf.c_str());

    // Corrupt the token while the injector is past its handshake.  The eject
    // path resolves the port/token from the handshake result, not from the
    // file, so this must not change the outcome.
    std::thread modifier([&pf]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        for (int i = 0; i < 20; i++) {
            std::ifstream check(pf);
            if (check.is_open()) {
                check.close();
                std::ifstream in(pf);
                std::string port_line, token_line;
                std::getline(in, port_line);
                std::getline(in, token_line);
                in.close();
                std::ofstream out(pf);
                out << port_line << "\n" << "wrong_token_0000000000000000000000000000000000000000000000000000\n";
                out.close();
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    });

    int ec = run_cov_injector(pid, lib, pf, 3000);
    modifier.join();

    printf("Exit code with token overwritten after the handshake: %d\n", ec);
    CHECK(ec == 0, (std::string("injection still succeeds, got ") + std::to_string(ec)).c_str());

    stop_target(pi);
}

int main() {
    chdir_to_exe_dir();          // anchor CWD to this exe's build tree
    printf("=== Port-file tamper resistance tests ===\n\n");
    test_port_file_deleted_after_handshake();
    test_token_overwritten_after_handshake();
    printf("\n%d/%d tests passed\n", passed, total);
    return passed == total ? 0 : 1;
}
