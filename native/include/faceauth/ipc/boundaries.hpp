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

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

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
    // Phase 2: only ScriptedVerificationBackend implements this, and it
    // returns a simulated value with no biometric processing whatsoever.
    virtual VerificationDecision verify(const VerifyRequest& request,
                                        std::uint64_t now_unix_ms) = 0;
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

    VerificationDecision verify(const VerifyRequest& request, std::uint64_t now_unix_ms) override;

    std::size_t calls() const { return calls_; }

private:
    std::vector<VerificationDecision> script_{};
    std::size_t calls_ = 0;
};

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_BOUNDARIES_HPP
