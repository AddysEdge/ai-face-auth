// Replay rejection (ADR-0003 section 5.4, T4).
//
// The server records every (request_id, nonce) pair it has accepted, until
// that request's deadline passes. A repeated request_id is a duplicate
// request; a repeated nonce under a different request_id is a replay attempt
// with a rewritten header. Both are rejected.
//
// The cache is bounded (kReplayCacheCapacity). When it is full, expired
// entries are evicted first; if that is not enough, the *new* observation is
// rejected rather than an old entry being dropped. Dropping an old entry to
// make room would let an attacker flush the cache and then replay - so the
// full cache fails closed, exactly like everything else here.

#ifndef FACEAUTH_IPC_REPLAY_CACHE_HPP
#define FACEAUTH_IPC_REPLAY_CACHE_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include "faceauth/ipc/protocol.hpp"

namespace faceauth::ipc {

class ReplayCache {
public:
    explicit ReplayCache(std::size_t capacity = kReplayCacheCapacity) : capacity_(capacity) {}

    // Returns ErrorCode::None if the pair is fresh and was recorded.
    // Returns DuplicateRequestId, ReplayedNonce, or LimitExceeded otherwise.
    ErrorCode observe(const RequestId& request_id, const Nonce& nonce,
                      std::uint64_t expires_at_unix_ms, std::uint64_t now_unix_ms);

    void evict_expired(std::uint64_t now_unix_ms);

    std::size_t size() const { return entries_.size(); }
    std::size_t capacity() const { return capacity_; }
    void clear() { entries_.clear(); }

private:
    struct Entry {
        RequestId request_id{};
        Nonce nonce{};
        std::uint64_t expires_at_unix_ms = 0;
    };

    std::size_t capacity_;
    std::vector<Entry> entries_{};
};

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_REPLAY_CACHE_HPP
