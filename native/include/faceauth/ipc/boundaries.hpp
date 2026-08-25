// INERT boundary declarations.
//
// These two interfaces mark exactly where the Phase 3 boundaries would attach.
// NOTHING IN THIS REPOSITORY IMPLEMENTS EITHER OF THEM AGAINST WINDOWS.
//
//   IVerificationBackend  - the future Session 0 verification service
//                           (ADR-0002). The only implementation that ships here
//                           is ScriptedVerificationBackend, which returns
//                           pre-programmed allow/deny values for protocol
//                           tests and never looks at a camera.
//
//   ICredentialGate       - the future credential provider side (ADR-0001).
//                           In Phase 3 this is where an ALLOW would release a
//                           pre-provisioned certificate credential handle to
//                           the smart-card logon path. There is deliberately
//                           NO implementation, not even a fake one: a fake
//                           credential gate is precisely the "path that reports
//                           successful Windows authentication based only on a
//                           face match" that this project must never create.
//
// The presence of these declarations does not activate anything. They exist so
// the shape of the future system is reviewable now, and so that a reader can
// see at a glance which side of the boundary each piece of code lives on.

#ifndef FACEAUTH_IPC_BOUNDARIES_HPP
#define FACEAUTH_IPC_BOUNDARIES_HPP

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <utility>
#include <vector>

#include "faceauth/ipc/clock.hpp"
#include "faceauth/ipc/protocol.hpp"

namespace faceauth::ipc {

struct VerificationDecision {
    Outcome outcome = Outcome::Deny;
    std::uint16_t reason_code = 0;
};

class IVerificationBackend {
public:
    virtual ~IVerificationBackend() = default;

    // Phase 3: run the face + liveness pipeline and return a decision.
    // Phase 2: only the test doubles below implement this, and they return a
    // simulated value with no biometric processing whatsoever.
    //
    // `now_steady_ms` is the server's own monotonic clock reading. No wall
    // clock and no peer-supplied timestamp reaches this boundary.
    //
    // NOTE: in protocol version 1 this call is SYNCHRONOUS, which is exactly
    // why in-flight cancellation does not exist (see MessageType in
    // protocol.hpp and ADR-0003 sections 5.8/5.9).
    //
    // While this call runs, the calling worker thread and the concurrency gate
    // are held, and nothing can preempt it - not a client abandonment, which
    // sends nothing and leaves the server unaware, and not the server's own
    // deadline, which is only re-checked AFTER this returns. That check stops a
    // late decision producing an Allow; it does not bound or interrupt this
    // call. B16 requires the Phase 3 design to make the call itself genuinely
    // bounded and cancellable, which also needs an asynchronous/event-loop
    // service shape before cancellation is meaningful.
    virtual VerificationDecision verify(const VerifyRequest& request,
                                        std::uint64_t now_steady_ms) = 0;
};

// NOT IMPLEMENTED ANYWHERE, BY DESIGN. See the file header.
class ICredentialGate {
public:
    virtual ~ICredentialGate() = default;

    // Phase 3 would, on a validated ALLOW, authorise use of an already
    // provisioned, Windows-recognised credential. It would never construct,
    // read, derive, or store a Windows password, and it would never return a
    // credential of its own invention.
    virtual bool authorise_credential_use(const RequestId& request_id,
                                          const OpaqueBinding& account_binding) = 0;
};

// Test double for IVerificationBackend. Returns outcomes from a fixed script,
// then Deny once the script is exhausted - fail closed, as everywhere else.
class ScriptedVerificationBackend : public IVerificationBackend {
public:
    ScriptedVerificationBackend() = default;
    explicit ScriptedVerificationBackend(std::vector<VerificationDecision> script)
        : script_(std::move(script)) {}

    VerificationDecision verify(const VerifyRequest& request,
                                std::uint64_t now_steady_ms) override;

    std::size_t calls() const { return calls_; }

private:
    std::vector<VerificationDecision> script_{};
    std::size_t calls_ = 0;
};

// Test double that BLOCKS inside verify() until it is released, so a test can
// hold two verifications genuinely in flight at the same time. Without this,
// a "concurrency" test on a synchronous backend would only ever be a sequence
// of calls that never overlap - which proves nothing about admission control.
class BlockingVerificationBackend : public IVerificationBackend {
public:
    explicit BlockingVerificationBackend(VerificationDecision decision) : decision_(decision) {}

    VerificationDecision verify(const VerifyRequest& request,
                                std::uint64_t now_steady_ms) override;

    // Blocks until at least `count` callers are simultaneously inside verify().
    void wait_until_entered(std::size_t count);

    // Lets every blocked caller return.
    void release_all();

    std::size_t entered() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    VerificationDecision decision_;
    std::size_t entered_ = 0;
    bool released_ = false;
};

// Test double that consumes a controllable amount of the request window by
// advancing an injected ManualMonotonicClock while "verifying". This is how a
// slow or overrunning backend is simulated deterministically - a real sleep
// would make the assertion depend on scheduler luck.
class SlowVerificationBackend : public IVerificationBackend {
public:
    SlowVerificationBackend(ManualMonotonicClock& clock, std::uint64_t elapsed_ms,
                            VerificationDecision decision)
        : clock_(clock), elapsed_ms_(elapsed_ms), decision_(decision) {}

    VerificationDecision verify(const VerifyRequest& request,
                                std::uint64_t now_steady_ms) override;

    std::size_t calls() const { return calls_; }

private:
    ManualMonotonicClock& clock_;
    std::uint64_t elapsed_ms_;
    VerificationDecision decision_;
    std::size_t calls_ = 0;
};

// Test double that throws. A verification backend is the least trustworthy
// component in the design - it is where camera and ML code would eventually
// live - so the session boundary must survive it throwing without leaking the
// concurrency gate or emitting an Allow.
class ThrowingVerificationBackend : public IVerificationBackend {
public:
    VerificationDecision verify(const VerifyRequest& request,
                                std::uint64_t now_steady_ms) override;

    std::size_t calls() const { return calls_; }

private:
    std::size_t calls_ = 0;
};

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_BOUNDARIES_HPP
