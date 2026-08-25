#include "faceauth/ipc/diagnostics.hpp"

#include <array>
#include <cctype>
#include <cstdio>
#include <string>

namespace faceauth::ipc {
namespace {

constexpr std::size_t kMaxFieldValueChars = 128u;

// Deliberately broader than the Python denylist: it additionally covers
// "nonce", "pin", "key", and "certificate", because those are meaningful in
// the native layer and none of them belongs in a log line.
const std::array<const char*, 12> kForbiddenSubstrings = {
    "password", "secret",  "embedding", "template", "image", "frame",
    "biometric", "nonce", "pin",       "key",      "certificate", "credential",
};

std::string to_lower(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char ch : value) {
        out.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

bool ends_with(const std::string& value, const char* suffix) {
    const std::string needle(suffix);
    if (value.size() < needle.size()) {
        return false;
    }
    return value.compare(value.size() - needle.size(), needle.size(), needle) == 0;
}

std::string quote(std::string_view value) {
    std::string out;
    out.reserve(value.size() + 2u);
    out.push_back('"');
    for (const char ch : value) {
        if (ch == '"' || ch == '\\') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    out.push_back('"');
    return out;
}

}  // namespace

bool is_forbidden_field_name(std::string_view name) {
    const std::string lowered = to_lower(name);
    // An opaque correlation handle is safe to log even when its name contains
    // a denylisted word - "template_id" is a handle, "template_bytes" is the
    // payload. Same carve-out as SecurityLogger._validate_fields.
    const bool is_identifier = ends_with(lowered, "_id");
    for (const char* needle : kForbiddenSubstrings) {
        if (lowered.find(needle) != std::string::npos) {
            if (is_identifier) {
                continue;
            }
            return true;
        }
    }
    return false;
}

bool is_safe_field_value(std::string_view value) {
    if (value.size() > kMaxFieldValueChars) {
        return false;
    }
    for (const char ch : value) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20u || byte == 0x7Fu) {
            return false;
        }
    }
    return true;
}

DiagnosticEvent::DiagnosticEvent(std::string_view event_name) : event_name_(event_name) {
    if (!is_safe_field_value(event_name)) {
        reject("event name is not a safe value");
    }
}

void DiagnosticEvent::reject(std::string reason) {
    rejected_ = true;
    if (rejection_reason_.empty()) {
        rejection_reason_ = std::move(reason);
    }
}

DiagnosticEvent& DiagnosticEvent::add(std::string_view key, std::string_view value) {
    if (is_forbidden_field_name(key)) {
        reject("field name '" + std::string(key) + "' is on the privacy denylist");
        return *this;
    }
    if (!is_safe_field_value(key) || !is_safe_field_value(value)) {
        reject("field '" + std::string(key) + "' has an unsafe value");
        return *this;
    }
    fields_.emplace_back(std::string(key), quote(value));
    return *this;
}

DiagnosticEvent& DiagnosticEvent::add(std::string_view key, const char* value) {
    return add(key, (value == nullptr) ? std::string_view{} : std::string_view(value));
}

DiagnosticEvent& DiagnosticEvent::add(std::string_view key, std::int64_t value) {
    if (is_forbidden_field_name(key)) {
        reject("field name '" + std::string(key) + "' is on the privacy denylist");
        return *this;
    }
    if (!is_safe_field_value(key)) {
        reject("field name '" + std::string(key) + "' is not a safe value");
        return *this;
    }
    fields_.emplace_back(std::string(key), std::to_string(value));
    return *this;
}

DiagnosticEvent& DiagnosticEvent::add(std::string_view key, bool value) {
    if (is_forbidden_field_name(key)) {
        reject("field name '" + std::string(key) + "' is on the privacy denylist");
        return *this;
    }
    if (!is_safe_field_value(key)) {
        reject("field name '" + std::string(key) + "' is not a safe value");
        return *this;
    }
    fields_.emplace_back(std::string(key), value ? "true" : "false");
    return *this;
}

std::string DiagnosticEvent::render() const {
    if (rejected_) {
        return std::string{};
    }
    std::string out = "{\"event\":" + quote(event_name_);
    for (const auto& field : fields_) {
        out += ",";
        out += quote(field.first);
        out += ":";
        out += field.second;
    }
    out += "}";
    return out;
}

bool emit(DiagnosticSink& sink, const DiagnosticEvent& event) {
    if (event.rejected()) {
        return false;
    }
    sink.write(event.render());
    return true;
}

void StdoutSink::write(const std::string& line) {
    std::fputs(line.c_str(), stdout);
    std::fputc('\n', stdout);
}

}  // namespace faceauth::ipc
