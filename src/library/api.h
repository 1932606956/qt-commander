#pragma once
#include <cstdint>
#include <string>

// ---------------------------------------------------------------------------
// InitParams -- POD struct passed from injector to injected library via
// target-process memory.  Fixed-layout, no pointers, exactly 1024 bytes.
// All fields are stored inline at compile-time offsets so the struct can be
// written directly into the target's address space without pointer fixup.
// ---------------------------------------------------------------------------

#define INIT_PARAMS_VERSION      1
#define INIT_PARAMS_MAX_PATH     256
#define INIT_PARAMS_TOKEN_LEN    64
#define INIT_PARAMS_TOTAL_SIZE   1024

// NOLINTBEGIN(modernize-avoid-c-arrays)  --  C-compatible POD layout
typedef struct {
    uint32_t version;                                   // offset   0
    uint32_t total_size;                                // offset   4
    char     workspace_path[INIT_PARAMS_MAX_PATH];      // offset   8  (256 B)
    char     session_id[13];                            // offset 264  (12 chars + NUL)
    char     token[INIT_PARAMS_TOKEN_LEN + 1];          // offset 277  (64 hex + NUL)
    char     port_file_path[INIT_PARAMS_MAX_PATH];      // offset 342  (256 B)
    uint8_t  reserved[426];                             // offset 598  (pad to 1024)
} InitParams;
// NOLINTEND(modernize-avoid-c-arrays)

static_assert(sizeof(InitParams) == INIT_PARAMS_TOTAL_SIZE,
              "InitParams size mismatch -- check member sizes");

// ---------------------------------------------------------------------------
// Exported entry point
//
// Called by the injector AFTER DllMain / library constructor has finished.
// Must only be called once per process.  Returns 0 on success, -1 on failure.
//
// Responsibilities:
//   1. Validate the InitParams version and total_size
//   2. Initialise platform socket subsystem (WSAStartup, etc.)
//   3. Bind a TCP listening socket on loopback (OS-assigned port)
//   4. Write the port handshake file (*.port.txt) with port and auth token
//   5. Start the RPC server background thread (accept, authenticate, dispatch)
//   6. Return immediately -- the RPC thread owns the accept/listen lifetime
// ---------------------------------------------------------------------------
extern "C" int qt_commander_init(const InitParams* params);

// ---------------------------------------------------------------------------
// Session control entry points
//
// qt_commander_request_shutdown() asks the active session to stop: it only
// sets the flag the RPC thread polls, so it is safe to call from any thread
// and allocates nothing.  Returns 0 unconditionally.
//
// qt_commander_session_state() returns 1 while a session is active (the RPC
// thread claimed the slot and has not released it yet), 0 when idle.  The
// injector's eject path polls this before deciding whether the module can be
// unloaded: unloading while the RPC thread is still running would leave that
// thread to resume into unmapped memory.
// ---------------------------------------------------------------------------
extern "C" int qt_commander_request_shutdown(void);
extern "C" int qt_commander_session_state(void);

namespace qt_commander {

// ---------------------------------------------------------------------------
// Atomic port-file write (temp file + rename)
// ---------------------------------------------------------------------------
// Writes content (typically "<port>\n<token>\n") so the injector polling the
// file never observes a half-written port.  Implemented in rpc_server.cpp.
bool writePortFileAtomic(const std::string& path, const std::string& content);

} // namespace qt_commander
