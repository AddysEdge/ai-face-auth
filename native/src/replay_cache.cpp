#include "faceauth/ipc/replay_cache.hpp"

namespace faceauth::ipc {

void ReplayCache::evict_expired(std::uint64_t now_unix_ms) {
    std::size_t write = 0;
    for (std::size_t read = 0; read < entries_.size(); ++read) {
        if (entries_[read].expires_at_unix_ms > now_unix_ms) {
            entries_[write++] = entries_[read];
        }
    }
    entries_.resize(write);
}

ErrorCode ReplayCache::observe(const RequestId& request_id, const Nonce& nonce,
                               std::uint64_t expires_at_unix_ms, std::uint64_t now_unix_ms) {
    evict_expired(now_unix_ms);

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
    entry.expires_at_unix_ms = expires_at_unix_ms;
    entries_.push_back(entry);
    return ErrorCode::None;
}

}  // namespace faceauth::ipc
