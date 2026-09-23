#include "injector.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <filesystem>

namespace fs = std::filesystem;

static void print_usage() {
    std::cerr << "Usage:\n"
              << "  qt-injector <pid> <library_path> <port_file_path> [--sleep-before-check <ms>]\n"
              << "  qt-injector --eject <pid> <library_path>\n"
              << "  qt-injector --list-deps <dll_path> [--search-dir <dir> ...]\n";
}

static void print_error_and_exit(int code, const std::string& msg) {
    std::cerr << "error(" << code << "): " << msg << "\n";
    std::exit(code);
}

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(); return 1; }

    std::string mode = argv[1];

    if (mode == "--list-deps") {
        // qt-injector --list-deps <dll> [--search-dir <dir> ...]
        if (argc < 3) { print_usage(); return 1; }
        fs::path dll(argv[2]);
        if (!fs::exists(dll))
            print_error_and_exit(2, "DLL not found: " + dll.string());
        std::vector<fs::path> searchDirs;
        for (int i = 3; i + 1 < argc; ++i) {
            if (std::string(argv[i]) == "--search-dir")
                searchDirs.emplace_back(argv[i + 1]);
        }
        const std::vector<fs::path> deps =
            resolveDependencyClosure(dll, searchDirs);
        // Escape backslashes/quote for JSON output (Windows paths).
        auto escape = [](const std::string& s) {
            std::string out;
            for (char c : s) {
                if (c == '\\' || c == '"')
                    out += '\\';
                out += c;
            }
            return out;
        };
        std::cout << "{\"deps\":[";
        for (size_t i = 0; i < deps.size(); ++i) {
            if (i) std::cout << ",";
            std::cout << "\"" << escape(deps[i].string()) << "\"";
        }
        std::cout << "]}\n";
        return 0;
    }

    if (mode == "--eject") {
        if (argc < 4) { print_usage(); return 1; }
        int pid = std::stoi(argv[2]);
        if (pid <= 0) print_error_and_exit(1, "invalid PID: " + std::to_string(pid));
        fs::path lib_path(argv[3]);
        InjectResult r = ejectLibrary(pid, lib_path);
        if (!r.ok) print_error_and_exit(2, r.error);
        std::cout << "{\"status\":\"ejected\",\"pid\":" << pid << "}\n";
        return 0;
    }

    if (argc < 4) { print_usage(); return 1; }

    int pid = std::stoi(argv[1]);
    if (pid <= 0) print_error_and_exit(1, "invalid PID: " + std::to_string(pid));

    fs::path lib_path(argv[2]);
    fs::path port_file(argv[3]);

    if (!fs::exists(lib_path))
        print_error_and_exit(2, "library not found: " + lib_path.string());

    if (!isQtProcess(pid))
        print_error_and_exit(6, "PID " + std::to_string(pid) + " is not a Qt process");

    // Drop any port file left behind by an earlier (possibly killed or timed
    // out) run before injecting.  The handshake only accepts a file whose
    // token matches, but a leftover would still be an atomic-rename target
    // racing with the library's own write.
    std::error_code removeEc;
    fs::remove(port_file, removeEc);

    InjectResult inject_r = injectLibrary(pid, lib_path);
    if (!inject_r.ok) print_error_and_exit(2, inject_r.error);

    std::string token = generateToken();
    fs::path workspace = port_file.parent_path().parent_path().parent_path();

    uint16_t port = performInitHandshake(
        pid, lib_path, workspace.string(),
        port_file.parent_path().filename().string(), token, port_file,
        inject_r.remote_base);

    if (port == 0) print_error_and_exit(3, "qt_commander_init failed or timed out");

    // Optional sleep for testing — creates window to delete/modify port file
    if (argc >= 6 && std::string(argv[4]) == "--sleep-before-check") {
        int ms = std::stoi(argv[5]);
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    // No second read of the port file: the handshake already polled it until
    // its token equalled ours, so a re-check here could only add a redundant
    // way to fail (and could not notice a token that changed after that).
    fs::remove(port_file);

    std::cout << "{\"port\":" << port << ",\"token\":\"" << token << "\"}\n";
    return 0;
}
