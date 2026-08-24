#include "faceauth/ipc/boundaries.hpp"

namespace faceauth::ipc {

VerificationDecision ScriptedVerificationBackend::verify(const VerifyRequest& request,
                                                         std::uint64_t now_unix_ms) {
    // Neither argument influences the simulated outcome. They are consumed
    // here only so the signature matches the real Phase 3 boundary.
    (void)request;
    (void)now_unix_ms;

    if (calls_ < script_.size()) {
        return script_[calls_++];
    }
    ++calls_;
    // Script exhausted: deny. There is no default-allow anywhere in this
    // codebase, including in test doubles.
    return VerificationDecision{Outcome::Deny, static_cast<std::uint16_t>(ErrorCode::VerificationFailed)};
}

}  // namespace faceauth::ipc
