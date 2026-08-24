#include "faceauth/ipc/clock.hpp"

#include <chrono>

namespace faceauth::ipc {

std::uint64_t SystemClock::now_unix_ms() const {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    return static_cast<std::uint64_t>(millis);
}

}  // namespace faceauth::ipc
