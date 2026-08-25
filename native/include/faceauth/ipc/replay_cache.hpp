// Replay rejection (ADR-0003 section 5.4, T4).
//
// The server records every (request_id, nonce) pair it has accepted, until
// that request's server-side deadline passes. A repeated request_id is a
// duplicate request; a repeated nonce under a different request_id is a replay
// attempt with a rewritten header. Both are rejected.
//
// TIME BASE: entries expire against the SERVER'S OWN MONOTONIC CLOCK. The
// expiry value passed in is a server-local `steady_now_ms()`-derived instant,
// never a peer-supplied timestamp and never wall-clock time. A client cannot
// influence how long its entry is remembered beyond the bounded lifetime the
// server already clamped.
//
// EXPIRY IS HALF-OPEN, matching requests and results exactly: an entry is live
// while `now < expires_at`, and gone once `now >= expires_at`. That is the same
// rule the sessions use, so a request whose deadline has just passed and the
// cache entry that protected it stop being live at the same instant - no seam
// where one component still considers something alive and the other does not.
//
// The cache is bounded (kReplayCacheCapacity). When it is full, expired
// entries are evicted first; if that is not enough, the *new* observation is
// rejected rather than an old entry being dropped. Dropping an old entry to
// make room would let an attacker flush the cache and then replay - so the
// full cache fails closed, exactly like everything else here.
//
// THREAD SAFETY: this class is internally synchronised. A single cache is
// intended to be shared by every concurrent ServerSession on a machine, which
// is the only way duplicate detection can work across connections, so it must
// be safe to call from several threads at once.

#ifndef FACEAUTH_IPC_REPLAY_CACHE_HPP
#define FACEAUTH_IPC_REPLAY_CACHE_HPP

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

#include "faceauth/ipc/protocol.hpp"

namespace faceauth::ipc {

class ReplayCache {
public:
    explicit ReplayCache(std::size_t capacity = kReplayCacheCapacity) : capacity_(capacity) {}

    ReplayCache(const ReplayCache&) = delete;
    ReplayCache& operator=(const ReplayCache&) = delete;

    // Returns ErrorCode::None if the pair is fresh and was recorded.
    // Returns DuplicateRequestId, ReplayedNonce, or LimitExceeded otherwise.
    //
    // Both time arguments are server-local monotonic milliseconds.
    ErrorCode observe(const RequestId& request_id, const Nonce& nonce,
                      std::uint64_t expires_at_steady_ms, std::uint64_t now_steady_ms);

    void evict_expired(std::uint64_t now_steady_ms);

    std::size_t size() const;
    std::size_t capacity() const { return capacity_; }
    void clear();

private:
    struct Entry {
        RequestId request_id{};
        Nonce nonce{};
        std::uint64_t expires_at_steady_ms = 0;
    };

    // Caller must hold mutex_.
    void evict_expired_locked(std::uint64_t now_steady_ms);

    mutable std::mutex mutex_;
    std::size_t capacity_;
    std::vector<Entry> entries_{};
};

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_REPLAY_CACHE_HPP
