// Windows named-pipe transport for the fake client/server pair.
//
// READ THIS BEFORE ASSUMING THIS IS THE PHASE 3 ENDPOINT. It is not.
//
// This creates a pipe owned by, and accessible only to, the user running the
// test tool. It is not created by a service, it has no service SID in its
// DACL, it performs no client-token check, and its name is explicitly marked
// as a protocol test. The privileged endpoint specified in ADR-0003 section
// 5.2 - service-created, SYSTEM + NT SERVICE\FaceAuthVerifier only, with a
// System-integrity mandatory label and an ImpersonateNamedPipeClient check -
// is a Phase 3 deliverable and is deliberately not built here.
//
// WHY EVERYTHING HERE IS OVERLAPPED.
//
// Microsoft documents that synchronous named-pipe operations can block
// indefinitely, and that a pipe's nDefaultTimeOut does NOT bound a synchronous
// ConnectNamedPipe. An earlier version of this file used blocking ReadFile,
// WriteFile, and ConnectNamedPipe and simply ignored the caller's timeout, so
// its "timeout" tests proved nothing and an unresponsive peer could have hung
// CI forever.
//
// Every operation is therefore issued with FILE_FLAG_OVERLAPPED and its own
// OVERLAPPED structure plus a manual-reset event, and awaited with
// GetOverlappedResultEx, which takes a real millisecond bound. On expiry the
// operation is cancelled with CancelIoEx for that exact OVERLAPPED and then
// drained with a blocking GetOverlappedResult, because Microsoft states the
// caller "must not free or reuse the OVERLAPPED structure associated with the
// canceled I/O operations until they have completed" and that CancelIoEx
// "does not wait for all canceled operations to complete".
//
// FlushFileBuffers is deliberately NOT called on shutdown: for a named pipe it
// waits for the peer to drain the buffer, which reintroduces an unbounded wait
// on exactly the path that must never block.
//
// What this file still demonstrates from the real design:
//   * an EXPLICIT security descriptor, never the NULL default, whose ACLs per
//     Microsoft "grant read access to members of the Everyone group and the
//     anonymous account".
//   * FILE_FLAG_FIRST_PIPE_INSTANCE, so a squatter that got there first causes
//     a loud failure instead of a silent hijack.
//   * PIPE_REJECT_REMOTE_CLIENTS.
//   * message-mode framing.

#include "faceauth/ipc/transport.hpp"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// <sddl.h> must follow <windows.h>.
#include <sddl.h>

#include <chrono>
#include <thread>

#include "faceauth/ipc/protocol.hpp"

namespace faceauth::ipc {
namespace {

std::wstring full_pipe_path(const std::string& pipe_name) {
    std::wstring path = L"\\\\.\\pipe\\";
    for (const char ch : pipe_name) {
        path.push_back(static_cast<wchar_t>(static_cast<unsigned char>(ch)));
    }
    return path;
}

// Returns the SDDL string SID of the current process user, or an empty string
// on failure. Failure must abort pipe creation - never fall back to a default
// or permissive descriptor.
std::wstring current_user_sid_string() {
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0) {
        return std::wstring{};
    }

    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        CloseHandle(token);
        return std::wstring{};
    }

    std::vector<unsigned char> buffer(needed);
    if (GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed) == 0) {
        CloseHandle(token);
        return std::wstring{};
    }
    CloseHandle(token);

    const TOKEN_USER* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR sid_text = nullptr;
    if (ConvertSidToStringSidW(user->User.Sid, &sid_text) == 0) {
        return std::wstring{};
    }
    std::wstring result(sid_text);
    LocalFree(sid_text);
    return result;
}

// One overlapped operation: an OVERLAPPED plus the manual-reset event it
// signals. Kept as a scoped object so the event is always closed, and so the
// OVERLAPPED outlives any I/O still referring to it.
class OverlappedOp {
public:
    OverlappedOp() {
        ZeroMemory(&overlapped_, sizeof(overlapped_));
        // Manual reset, initially unsignalled - required so a completed
        // operation stays signalled until we observe it.
        overlapped_.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }

    ~OverlappedOp() {
        if (overlapped_.hEvent != nullptr) {
            CloseHandle(overlapped_.hEvent);
        }
    }

    OverlappedOp(const OverlappedOp&) = delete;
    OverlappedOp& operator=(const OverlappedOp&) = delete;

    bool valid() const { return overlapped_.hEvent != nullptr; }
    OVERLAPPED* get() { return &overlapped_; }

private:
    OVERLAPPED overlapped_{};
};

// Awaits an already-issued overlapped operation with a real bound.
//
// `issue_ok` / `issue_error` are the result of the ReadFile/WriteFile/
// ConnectNamedPipe call. Returns the transport status and, on success, the
// number of bytes transferred.
TransportStatus await_overlapped(HANDLE handle, OverlappedOp& op, BOOL issue_ok,
                                 DWORD issue_error, std::uint32_t timeout_ms,
                                 DWORD* out_transferred) {
    if (out_transferred != nullptr) {
        *out_transferred = 0;
    }

    if (issue_ok == 0 && issue_error != ERROR_IO_PENDING) {
        if (issue_error == ERROR_BROKEN_PIPE || issue_error == ERROR_PIPE_NOT_CONNECTED ||
            issue_error == ERROR_NO_DATA) {
            return TransportStatus::Disconnected;
        }
        return TransportStatus::Error;
    }

    DWORD transferred = 0;
    // Bounded wait. This - not the pipe's nDefaultTimeOut - is what actually
    // enforces the caller's timeout.
    if (GetOverlappedResultEx(handle, op.get(), &transferred, timeout_ms, FALSE) != 0) {
        if (out_transferred != nullptr) {
            *out_transferred = transferred;
        }
        return TransportStatus::Ok;
    }

    const DWORD wait_error = GetLastError();
    if (wait_error != WAIT_TIMEOUT) {
        if (wait_error == ERROR_BROKEN_PIPE || wait_error == ERROR_PIPE_NOT_CONNECTED ||
            wait_error == ERROR_NO_DATA) {
            return TransportStatus::Disconnected;
        }
        if (wait_error == ERROR_OPERATION_ABORTED) {
            return TransportStatus::Timeout;
        }
        return TransportStatus::Error;
    }

    // Timed out: cancel exactly this operation, then wait for it to finish.
    // CancelIoEx only *marks* the request; the OVERLAPPED must stay alive and
    // untouched until completion, so the blocking drain below is mandatory,
    // not optional politeness.
    CancelIoEx(handle, op.get());

    DWORD cancelled_transferred = 0;
    if (GetOverlappedResult(handle, op.get(), &cancelled_transferred, TRUE) != 0) {
        // The operation actually completed in the race with the cancel. That
        // is a documented outcome, and the data is genuinely there.
        if (out_transferred != nullptr) {
            *out_transferred = cancelled_transferred;
        }
        return TransportStatus::Ok;
    }

    const DWORD drain_error = GetLastError();
    if (drain_error == ERROR_BROKEN_PIPE || drain_error == ERROR_PIPE_NOT_CONNECTED) {
        return TransportStatus::Disconnected;
    }
    // ERROR_OPERATION_ABORTED is the expected cancellation result.
    return TransportStatus::Timeout;
}

class NamedPipeTransport : public Transport {
public:
    NamedPipeTransport(HANDLE handle, bool is_server) : handle_(handle), is_server_(is_server) {}

    ~NamedPipeTransport() override { close(); }

    NamedPipeTransport(const NamedPipeTransport&) = delete;
    NamedPipeTransport& operator=(const NamedPipeTransport&) = delete;

    TransportStatus send(const std::vector<std::uint8_t>& message) override {
        return send_with_timeout(message, default_timeout_ms_);
    }

    TransportStatus send_with_timeout(const std::vector<std::uint8_t>& message,
                                      std::uint32_t timeout_ms) override {
        if (handle_ == INVALID_HANDLE_VALUE) {
            return TransportStatus::Disconnected;
        }
        if (message.empty() || message.size() > kMaxMessageBytes) {
            return TransportStatus::Error;
        }

        OverlappedOp op;
        if (!op.valid()) {
            return TransportStatus::Error;
        }

        DWORD written = 0;
        const BOOL ok = WriteFile(handle_, message.data(), static_cast<DWORD>(message.size()),
                                  nullptr, op.get());
        const DWORD issue_error = (ok != 0) ? ERROR_SUCCESS : GetLastError();

        const TransportStatus status =
            await_overlapped(handle_, op, ok, issue_error, timeout_ms, &written);
        if (status != TransportStatus::Ok) {
            return status;
        }
        return (written == message.size()) ? TransportStatus::Ok : TransportStatus::Error;
    }

    TransportStatus receive(std::vector<std::uint8_t>& out, std::uint32_t timeout_ms) override {
        if (handle_ == INVALID_HANDLE_VALUE) {
            return TransportStatus::Disconnected;
        }

        OverlappedOp op;
        if (!op.valid()) {
            return TransportStatus::Error;
        }

        std::vector<std::uint8_t> buffer(kMaxMessageBytes);
        DWORD read = 0;
        const BOOL ok = ReadFile(handle_, buffer.data(), static_cast<DWORD>(buffer.size()),
                                 nullptr, op.get());
        const DWORD issue_error = (ok != 0) ? ERROR_SUCCESS : GetLastError();

        // ERROR_MORE_DATA means the peer sent a message larger than our
        // ceiling. Refuse it; do not try to reassemble.
        if (ok == 0 && issue_error == ERROR_MORE_DATA) {
            return TransportStatus::Error;
        }

        const TransportStatus status =
            await_overlapped(handle_, op, ok, issue_error, timeout_ms, &read);
        if (status != TransportStatus::Ok) {
            return status;
        }
        if (read == 0) {
            return TransportStatus::Disconnected;
        }
        buffer.resize(read);
        out = buffer;
        return TransportStatus::Ok;
    }

    void close() override {
        if (handle_ == INVALID_HANDLE_VALUE) {
            return;
        }
        // Cancel anything this process still has pending on the handle, then
        // tear down. Deliberately NO FlushFileBuffers: on a named pipe it
        // waits for the peer to consume the buffer, which is an unbounded wait
        // on an unresponsive peer - the exact hazard this file exists to
        // remove. DisconnectNamedPipe and CloseHandle do not block on the peer.
        CancelIoEx(handle_, nullptr);
        if (is_server_) {
            DisconnectNamedPipe(handle_);
        }
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }

    bool connected() const override { return handle_ != INVALID_HANDLE_VALUE; }

private:
    static constexpr std::uint32_t default_timeout_ms_ = 5000u;

    HANDLE handle_ = INVALID_HANDLE_VALUE;
    bool is_server_ = false;
};

}  // namespace

std::shared_ptr<Transport> make_named_pipe_server(const std::string& pipe_name,
                                                  std::uint32_t connect_timeout_ms,
                                                  TransportStatus* out_status) {
    const auto set_status = [out_status](TransportStatus status) {
        if (out_status != nullptr) {
            *out_status = status;
        }
    };
    set_status(TransportStatus::Error);

    const std::wstring user_sid = current_user_sid_string();
    if (user_sid.empty()) {
        return nullptr;
    }

    // Protected DACL (P), granting GENERIC_ALL to this user and nobody else.
    // No Everyone, no Anonymous, no Authenticated Users.
    const std::wstring sddl = L"D:P(A;;GA;;;" + user_sid + L")";

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                             &descriptor, nullptr) == 0) {
        return nullptr;
    }

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;

    const std::wstring path = full_pipe_path(pipe_name);
    const HANDLE handle = CreateNamedPipeW(
        path.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, static_cast<DWORD>(kMaxMessageBytes), static_cast<DWORD>(kMaxMessageBytes),
        connect_timeout_ms, &attributes);

    LocalFree(descriptor);

    if (handle == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    // Overlapped connect with a real bound. nDefaultTimeOut above does NOT
    // bound this; GetOverlappedResultEx does.
    OverlappedOp op;
    if (!op.valid()) {
        CloseHandle(handle);
        return nullptr;
    }

    const BOOL ok = ConnectNamedPipe(handle, op.get());
    DWORD issue_error = (ok != 0) ? ERROR_SUCCESS : GetLastError();

    // ERROR_PIPE_CONNECTED means the client won the race between
    // CreateNamedPipe and ConnectNamedPipe. That is a success, not a failure.
    if (ok == 0 && issue_error == ERROR_PIPE_CONNECTED) {
        set_status(TransportStatus::Ok);
        return std::make_shared<NamedPipeTransport>(handle, true);
    }

    const TransportStatus status =
        await_overlapped(handle, op, ok, issue_error, connect_timeout_ms, nullptr);
    if (status != TransportStatus::Ok) {
        // Nothing connected within the bound. Close the handle rather than
        // leaving a half-open listener behind.
        CloseHandle(handle);
        set_status(status);
        return nullptr;
    }

    set_status(TransportStatus::Ok);
    return std::make_shared<NamedPipeTransport>(handle, true);
}

std::shared_ptr<Transport> make_named_pipe_client(const std::string& pipe_name,
                                                  std::uint32_t connect_timeout_ms,
                                                  TransportStatus* out_status) {
    const auto set_status = [out_status](TransportStatus status) {
        if (out_status != nullptr) {
            *out_status = status;
        }
    };
    set_status(TransportStatus::Error);

    const std::wstring path = full_pipe_path(pipe_name);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(connect_timeout_ms);

    for (;;) {
        const HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                          OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_MESSAGE;
            if (SetNamedPipeHandleState(handle, &mode, nullptr, nullptr) == 0) {
                CloseHandle(handle);
                return nullptr;
            }
            set_status(TransportStatus::Ok);
            return std::make_shared<NamedPipeTransport>(handle, false);
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            set_status(TransportStatus::Timeout);
            return nullptr;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

}  // namespace faceauth::ipc

#endif  // _WIN32
