// ---------------------------------------------------------------------------
// qt-commander -- Windows entry point
//
// DllMain(DLL_PROCESS_ATTACH) sets an atomic flag only -- no threads, no
// socket APIs, no heap allocations (Windows loader lock restrictions).
//
// qt_commander_init() does the real work: validates InitParams, initialises
// Winsock, creates a listening socket, writes the port handshake file, and
// starts the RPC server background thread.  One session may be active per
// process at a time; once the RPC server thread exits (shutdown or client
// disconnect), the session slot is freed so the library can be re-injected
// into the same process without restarting it.
// ---------------------------------------------------------------------------

#include "api.h"
#include "../common/socket_utils.h"
#include "compat_qt.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------
namespace {

/// Set to `true` once DllMain(DLL_PROCESS_ATTACH) runs.
std::atomic<bool> g_library_loaded{false};

/// Guards the session slot.  Held briefly by qt_commander_init to claim the
/// slot and by the RPC server thread on exit to release it, so a new
/// injection can start a fresh session after the previous one ended.
std::mutex g_session_mutex;
bool g_session_active = false;

/// Shared shutdown flag that the RPC server thread polls.
std::atomic<bool> g_shutdown_flag{false};

/// One-time Winsock initialiser (called from qt_commander_init, NOT DllMain).
/// socket_init() in socket_utils.cpp is safe to call multiple times but we
/// only call it once for clarity.
bool ensure_socket_init()
{
    static std::once_flag flag;
    bool ok = true;
    std::call_once(flag, [&ok]() { ok = socket_init(); });
    return ok;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Forward declaration of the RPC server thread function
//
// Defined in rpc/rpc_server.cpp.  This function blocks the calling thread
// for the lifetime of the RPC connection (accept → auth → dispatch → close).
// It closes `listen_fd` after accepting one connection.
// ---------------------------------------------------------------------------
namespace qt_commander {

void run_rpc_server(socket_t listen_fd,
                    std::string port_file_path,
                    std::string session_id,
                    std::string token,
                    std::atomic<bool>& shutdown_flag);

} // namespace qt_commander

// ---------------------------------------------------------------------------
// DllMain
// ---------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Do NOT create threads, call socket APIs, or allocate memory here.
        // The loader lock is held and many operations are unsafe.
        g_library_loaded.store(true, std::memory_order_release);

        // Disable thread-attach/detach notifications for performance.
        DisableThreadLibraryCalls(hinstDLL);
    }

    return TRUE;
}

// ---------------------------------------------------------------------------
// qt_commander_init  --  called by the injector after LoadLibrary
// ---------------------------------------------------------------------------
// DEBUG: incremental enable to find ACCESS_VIOLATION root cause
extern "C" int qt_commander_init(const InitParams* params)
{
    if (!params) return -1;

    // Claim the session slot (one active session per process).
    {
        std::lock_guard<std::mutex> lock(g_session_mutex);
        if (g_session_active)
            return -1;  // a previous session is still running
        g_session_active = true;
        g_shutdown_flag.store(false, std::memory_order_relaxed);
    }

    // Release the slot on any failure below.
    auto abortInit = []() {
        std::lock_guard<std::mutex> lock(g_session_mutex);
        g_session_active = false;
    };

    // Hoisted out of the try block so the handler can close the listener.
    socket_t listen_fd = INVALID_SOCK;

    // Nothing may escape an extern "C" export: the injector calls this from a
    // remote thread, which has no handler, so an escaping exception would
    // unwind into the target's loader/thread start and terminate the host.
    // Same reasoning as the frame_encode guard in rpc_io::sendFrame.
    try {
        // Validate InitParams
        if (params->version != INIT_PARAMS_VERSION) { abortInit(); return -1; }
        if (params->total_size != INIT_PARAMS_TOTAL_SIZE) { abortInit(); return -1; }

        // Init Winsock
        if (!ensure_socket_init()) { abortInit(); return -1; }

        // Create listening socket
        uint16_t port = 0;
        listen_fd = tcp_listen_loopback(port);
        if (listen_fd == INVALID_SOCK) { abortInit(); return -1; }

        // Copy string fields
        std::string ws(params->workspace_path);
        std::string sid(params->session_id);
        std::string tok(params->token);
        std::string pf(params->port_file_path);

        // Write port file (atomic: temp file + rename, so the injector's
        // polling never observes a half-written port).
        if (!qt_commander::writePortFileAtomic(pf, std::to_string(port) + '\n' + tok + '\n')) {
            tcp_close(listen_fd);
            abortInit();
            return -1;
        }

        // Start RPC thread.  When the session ends (shutdown RPC or client
        // disconnect) the thread frees the slot so a new injection can start
        // another session in this process.
        std::thread rpc_thread([listen_fd, pf, sid, tok]() mutable {
            // Pin this module for as long as the thread can execute inside it.
            // The thread is detached and normally blocks in tcp_accept/recv --
            // i.e. inside this module -- while the injector's --eject path
            // calls FreeLibrary in the target, which can drop the reference
            // count to zero and unmap the module.  The blocked call would then
            // return into unmapped memory and kill the host process.  Note:
            // deliberately NOT passing GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
            // -- incrementing the count is the entire point.
            HMODULE self = nullptr;
            ::GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                reinterpret_cast<LPCSTR>(&qt_commander::run_rpc_server), &self);
            if (!self) {
                // Cannot pin ourselves, so running the server would be unsafe.
                // Release everything this init took: leaving the slot claimed
                // would make every later injection into this process return -1
                // for the lifetime of the host, and the accepted-but-unserved
                // listener would stay bound.
                tcp_close(listen_fd);
                std::lock_guard<std::mutex> lock(g_session_mutex);
                g_session_active = false;
                return;
            }

            qt_commander::run_rpc_server(listen_fd, std::move(pf),
                                         std::move(sid), std::move(tok),
                                         g_shutdown_flag);
            {
                std::lock_guard<std::mutex> lock(g_session_mutex);
                g_session_active = false;
            }
            // FreeLibraryAndExitThread drops the reference taken above and
            // leaves the thread without executing one more instruction in this
            // module.  FreeLibrary + return would run the return sequence --
            // and the thread-exit bookkeeping -- on a module that the call may
            // just have unmapped.
            if (self)
                ::FreeLibraryAndExitThread(self, 0);
            return;  // unreachable fallback: FreeLibraryAndExitThread never returns
        });
        rpc_thread.detach();

        return 0;
    } catch (const std::exception&) {
        tcp_close(listen_fd);
        abortInit();
        return -1;
    } catch (...) {
        tcp_close(listen_fd);
        abortInit();
        return -1;
    }
}

// ---------------------------------------------------------------------------
// qt_commander_request_shutdown  --  ask the active session to stop
// ---------------------------------------------------------------------------
// Allocation-free and callable from any thread: it only flips the flag the
// RPC thread polls between accepts and before each frame, so the eject path
// can use it from a remote thread instead of waiting for a client disconnect.
extern "C" int qt_commander_request_shutdown(void)
{
    g_shutdown_flag.store(true, std::memory_order_relaxed);
    return 0;
}

// ---------------------------------------------------------------------------
// qt_commander_session_state  --  1 while a session is active, 0 when idle
// ---------------------------------------------------------------------------
// Read under g_session_mutex because the RPC thread clears the slot on exit:
// the eject path polls this to learn when it is actually safe to unload.
extern "C" int qt_commander_session_state(void)
{
    std::lock_guard<std::mutex> lock(g_session_mutex);
    return g_session_active ? 1 : 0;
}
