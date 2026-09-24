#pragma once
#include <string>
#include "api.h"
#include "common/socket_utils.h"

// TCP JSON-RPC server entry point for the injected library.
// The single production implementation is the free function below,
// called by entry_win.cpp / entry_unix.cpp.
namespace qt_commander {

// run_rpc_server is defined in rpc_server.cpp with a five-parameter
// signature (listen_fd, port_file_path, session_id, token, shutdown_flag)
// and forward-declared by the entry_*.cpp files themselves.  The stale
// four-parameter declaration that used to live here never matched the
// definition and has been removed.

} // namespace qt_commander
