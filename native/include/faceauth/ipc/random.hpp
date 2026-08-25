// Cryptographically random identifiers.
//
// Request IDs and nonces are the entire basis of replay rejection and
// request-to-result binding (ADR-0003 section 5.4, T4/T5). A predictable value
// here would let an attacker precompute a result the client would accept, so
// this deliberately does not use <random>'s engines.

#ifndef FACEAUTH_IPC_RANDOM_HPP
#define FACEAUTH_IPC_RANDOM_HPP

#include <cstddef>
#include <cstdint>

#include "faceauth/ipc/protocol.hpp"

namespace faceauth::ipc {

// Fills `out` with `length` cryptographically random bytes.
// Windows: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
// Elsewhere: /dev/urandom.
// Returns false on failure. Callers MUST treat false as fatal and fail closed -
// never fall back to a weaker source.
bool secure_random_bytes(std::uint8_t* out, std::size_t length);

// Both abort the calling operation via `ok=false` rather than returning a
// low-entropy value.
RequestId make_request_id(bool& ok);
Nonce make_nonce(bool& ok);

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_RANDOM_HPP
