#include "faceauth/ipc/clock.hpp"

#include <chrono>

namespace faceauth::ipc {

std::uint64_t SteadyClock::steady_now_ms() const {
    const auto since_epoch = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(since_epoch).count());
}

}  // namespace faceauth::ipc
