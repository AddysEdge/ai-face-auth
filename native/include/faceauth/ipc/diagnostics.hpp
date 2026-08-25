// Privacy-safe structured diagnostics for the native IPC layer.
//
// This mirrors the discipline of Phase 1's src/faceauth/logging_utils.py, with
// one deliberate difference: where the Python SecurityLogger *raises* on a
// forbidden field, this rejects the whole event and renders nothing. Both
// behave the same way in practice - a privacy mistake fails loudly in tests
// instead of quietly shipping - and neither redacts, because a redacting
// filter can be defeated by a payload that does not match its pattern.
//
// Three structural guarantees:
//   1. Only string / int64 / bool values can be attached. There is no overload
//      that accepts a buffer, a pointer, or a container, so an embedding or a
//      frame cannot reach a log line even by mistake.
//   2. A denylisted field name rejects the event outright.
//   3. Identifiers must be passed through hex_prefix(); a full request_id or
//      nonce in a log would itself be a replay aid (ADR-0003 section 5.5).

#ifndef FACEAUTH_IPC_DIAGNOSTICS_HPP
#define FACEAUTH_IPC_DIAGNOSTICS_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace faceauth::ipc {

// Case-insensitive substring match against the denylist. An identifier field
// ending in "_id" is allowed even when it contains a denylisted word, matching
// the Python logger's "template_id is a correlation handle, not the payload"
// carve-out - but the value must still be a hex prefix, never a full value.
bool is_forbidden_field_name(std::string_view name);

// Rejects control characters and anything longer than 128 characters, so a
// hostile or accidental value cannot smear across a log file.
bool is_safe_field_value(std::string_view value);

class DiagnosticEvent {
public:
    explicit DiagnosticEvent(std::string_view event_name);

    DiagnosticEvent& add(std::string_view key, std::string_view value);
    // Without this overload a `const char*` argument would silently prefer the
    // bool overload (pointer-to-bool is a standard conversion, while
    // pointer-to-string_view is a user-defined one), turning every string
    // literal into `true`.
    DiagnosticEvent& add(std::string_view key, const char* value);
    DiagnosticEvent& add(std::string_view key, std::int64_t value);
    DiagnosticEvent& add(std::string_view key, bool value);

    // True when a denylisted key or unsafe value was supplied. A rejected
    // event renders as an empty string and must not be emitted.
    bool rejected() const { return rejected_; }
    const std::string& rejection_reason() const { return rejection_reason_; }

    std::string render() const;

private:
    void reject(std::string reason);

    std::string event_name_;
    std::vector<std::pair<std::string, std::string>> fields_;
    bool rejected_ = false;
    std::string rejection_reason_;
};

class DiagnosticSink {
public:
    virtual ~DiagnosticSink() = default;
    virtual void write(const std::string& line) = 0;
};

// Emits the event if it is acceptable. Returns false (and writes nothing) if
// the event was rejected.
bool emit(DiagnosticSink& sink, const DiagnosticEvent& event);

class CollectingSink : public DiagnosticSink {
public:
    void write(const std::string& line) override { lines_.push_back(line); }
    const std::vector<std::string>& lines() const { return lines_; }
    void clear() { lines_.clear(); }

private:
    std::vector<std::string> lines_;
};

class StdoutSink : public DiagnosticSink {
public:
    void write(const std::string& line) override;
};

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_DIAGNOSTICS_HPP
