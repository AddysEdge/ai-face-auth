#include "faceauth/ipc/random.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// <bcrypt.h> must follow <windows.h>.
#include <bcrypt.h>
#else
#include <cstdio>
#endif

namespace faceauth::ipc {

bool secure_random_bytes(std::uint8_t* out, std::size_t length) {
    if (out == nullptr) {
        return false;
    }
    if (length == 0u) {
        return true;
    }
#if defined(_WIN32)
    const NTSTATUS status = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(out),
                                            static_cast<ULONG>(length),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status >= 0;
#else
    std::FILE* source = std::fopen("/dev/urandom", "rb");
    if (source == nullptr) {
        return false;
    }
    const std::size_t read = std::fread(out, 1u, length, source);
    std::fclose(source);
    return read == length;
#endif
}

RequestId make_request_id(bool& ok) {
    RequestId id{};
    ok = secure_random_bytes(id.data(), id.size());
    if (!ok) {
        id.fill(0u);
    }
    return id;
}

Nonce make_nonce(bool& ok) {
    Nonce nonce{};
    ok = secure_random_bytes(nonce.data(), nonce.size());
    if (!ok) {
        nonce.fill(0u);
    }
    return nonce;
}

}  // namespace faceauth::ipc
