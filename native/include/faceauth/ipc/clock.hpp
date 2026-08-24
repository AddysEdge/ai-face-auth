// Injectable clock.
//
// Deadlines, timeouts, and result expiry are security controls (ADR-0003
// section 5.7), so they need deterministic tests. Everything that consults time
// does so through this interface; nothing calls the system clock directly.

#ifndef FACEAUTH_IPC_CLOCK_HPP
#define FACEAUTH_IPC_CLOCK_HPP

#include <cstdint>

namespace faceauth::ipc {

class Clock {
public:
    virtual ~Clock() = default;
    virtual std::uint64_t now_unix_ms() const = 0;
};

class SystemClock : public Clock {
public:
    std::uint64_t now_unix_ms() const override;
};

// Test double. Time only ever moves forward, matching wall-clock semantics -
// see docs/THREAT_MODEL.md section 12 for why the Python rate limiter also
// uses wall-clock rather than monotonic time.
class ManualClock : public Clock {
public:
    explicit ManualClock(std::uint64_t start_unix_ms) : now_(start_unix_ms) {}

    std::uint64_t now_unix_ms() const override { return now_; }
    void advance(std::uint64_t delta_ms) { now_ += delta_ms; }

private:
    std::uint64_t now_;
};

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_CLOCK_HPP
