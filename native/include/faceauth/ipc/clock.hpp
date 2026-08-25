// Monotonic clock.
//
// WHY THERE IS NO WALL CLOCK HERE.
//
// Deadlines and result expiry are security controls (ADR-0003 section 5.7).
// A wall clock is the wrong instrument for them: system time can jump
// backwards or forwards - NTP correction, a user changing the clock, a VM
// resuming from a snapshot, a dual-boot machine disagreeing about the RTC.
// A backwards jump would silently extend a "short-lived" result; a forwards
// jump would expire a request that had barely started.
//
// So no security decision in this library consults wall-clock time, and no
// absolute timestamp is ever put on the wire. Instead:
//
//   * The protocol carries a bounded, relative REQUESTED LIFETIME.
//   * Each side derives its OWN deadline from its OWN monotonic clock at the
//     moment it starts or accepts the request.
//   * Neither side ever trusts a peer-supplied point in time.
//
// steady_now_ms() values are process-local and their origin is
// implementation-defined. They MUST NEVER be serialized: they are meaningless
// to another process, and comparing two processes' values would silently
// reintroduce exactly the problem this design removes.

#ifndef FACEAUTH_IPC_CLOCK_HPP
#define FACEAUTH_IPC_CLOCK_HPP

#include <cstdint>

namespace faceauth::ipc {

class MonotonicClock {
public:
    virtual ~MonotonicClock() = default;

    // Milliseconds since an arbitrary, process-local origin. Never decreases.
    // Never serialized - see the file header.
    virtual std::uint64_t steady_now_ms() const = 0;
};

// std::chrono::steady_clock, which the standard requires to be monotonic.
class SteadyClock : public MonotonicClock {
public:
    std::uint64_t steady_now_ms() const override;
};

// Test double. Only ever moves forward, matching the guarantee the real clock
// provides, so a test cannot accidentally assert behaviour that a monotonic
// clock could never produce.
class ManualMonotonicClock : public MonotonicClock {
public:
    explicit ManualMonotonicClock(std::uint64_t start_ms = 0) : now_ms_(start_ms) {}

    std::uint64_t steady_now_ms() const override { return now_ms_; }
    void advance(std::uint64_t delta_ms) { now_ms_ += delta_ms; }

private:
    std::uint64_t now_ms_;
};

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_CLOCK_HPP
