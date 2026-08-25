#include "faceauth/ipc/replay_cache.hpp"

namespace faceauth::ipc {

void ReplayCache::evict_expired_locked(std::uint64_t now_steady_ms) {
    std::size_t write = 0;
    for (std::size_t read = 0; read < entries_.size(); ++read) {
        if (entries_[read].expires_at_steady_ms > now_steady_ms) {
            entries_[write++] = entries_[read];
        }
    }
    entries_.resize(write);
}

void ReplayCache::evict_expired(std::uint64_t now_steady_ms) {
    const std::lock_guard<std::mutex> lock(mutex_);
    evict_expired_locked(now_steady_ms);
}

ErrorCode ReplayCache::observe(const RequestId& request_id, const Nonce& nonce,
                               std::uint64_t expires_at_steady_ms, std::uint64_t now_steady_ms) {
    // The whole check-then-insert sequence is under one lock. Doing the lookup
    // and the insert as two separately-locked steps would let two concurrent
    // sessions both observe "fresh" for the same request_id and both proceed -
    // which is precisely the duplicate this class exists to reject.
    const std::lock_guard<std::mutex> lock(mutex_);

    evict_expired_locked(now_steady_ms);

    for (const Entry& entry : entries_) {
        if (entry.request_id == request_id) {
            return ErrorCode::DuplicateRequestId;
        }
        if (entry.nonce == nonce) {
            return ErrorCode::ReplayedNonce;
        }
    }

    if (entries_.size() >= capacity_) {
        // Fail closed rather than evicting a live entry to make room; see the
        // header for why.
        return ErrorCode::LimitExceeded;
    }

    Entry entry{};
    entry.request_id = request_id;
    entry.nonce = nonce;
    entry.expires_at_steady_ms = expires_at_steady_ms;
    entries_.push_back(entry);
    return ErrorCode::None;
}

std::size_t ReplayCache::size() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

void ReplayCache::clear() {
    const std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

}  // namespace faceauth::ipc
