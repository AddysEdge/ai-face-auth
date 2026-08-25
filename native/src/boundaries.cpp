#include "faceauth/ipc/boundaries.hpp"

#include <stdexcept>

namespace faceauth::ipc {

VerificationDecision ScriptedVerificationBackend::verify(const VerifyRequest& request,
                                                         std::uint64_t now_steady_ms) {
    // Neither argument influences the simulated outcome. They are consumed
    // here only so the signature matches the real Phase 3 boundary.
    (void)request;
    (void)now_steady_ms;

    if (calls_ < script_.size()) {
        return script_[calls_++];
    }
    ++calls_;
    // Script exhausted: deny. There is no default-allow anywhere in this
    // codebase, including in test doubles.
    return VerificationDecision{Outcome::Deny, static_cast<std::uint16_t>(ErrorCode::VerificationFailed)};
}

VerificationDecision BlockingVerificationBackend::verify(const VerifyRequest& request,
                                                         std::uint64_t now_steady_ms) {
    (void)request;
    (void)now_steady_ms;

    std::unique_lock<std::mutex> lock(mutex_);
    ++entered_;
    condition_.notify_all();
    condition_.wait(lock, [this] { return released_; });
    return decision_;
}

void BlockingVerificationBackend::wait_until_entered(std::size_t count) {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this, count] { return entered_ >= count; });
}

void BlockingVerificationBackend::release_all() {
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        released_ = true;
    }
    condition_.notify_all();
}

std::size_t BlockingVerificationBackend::entered() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return entered_;
}

VerificationDecision SlowVerificationBackend::verify(const VerifyRequest& request,
                                                     std::uint64_t now_steady_ms) {
    (void)request;
    (void)now_steady_ms;
    ++calls_;
    // Time passes inside the verification, exactly as it would with a real
    // camera and pipeline - but deterministically.
    clock_.advance(elapsed_ms_);
    return decision_;
}

VerificationDecision ThrowingVerificationBackend::verify(const VerifyRequest& request,
                                                         std::uint64_t now_steady_ms) {
    (void)request;
    (void)now_steady_ms;
    ++calls_;
    throw std::runtime_error("simulated verification backend failure");
}

}  // namespace faceauth::ipc
