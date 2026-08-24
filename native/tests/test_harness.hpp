// Minimal test harness.
//
// Deliberately dependency-free: the Phase 2 brief asks for no unnecessary
// third-party runtime dependencies, and a security-boundary scaffold is a poor
// place to add a build-time download. Each test registers itself by name; CMake
// registers each name with CTest, so a failure names exactly one test.

#ifndef FACEAUTH_TEST_HARNESS_HPP
#define FACEAUTH_TEST_HARNESS_HPP

#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace faceauth::testing {

class Registry {
public:
    static Registry& instance() {
        static Registry registry;
        return registry;
    }

    void add(const std::string& name, std::function<void()> body) {
        tests_[name] = std::move(body);
    }

    const std::map<std::string, std::function<void()>>& tests() const { return tests_; }

private:
    std::map<std::string, std::function<void()>> tests_;
};

struct Registrar {
    Registrar(const std::string& name, std::function<void()> body) {
        Registry::instance().add(name, std::move(body));
    }
};

class AssertionFailure {
public:
    explicit AssertionFailure(std::string message) : message_(std::move(message)) {}
    const std::string& message() const { return message_; }

private:
    std::string message_;
};

inline void fail(const char* file, int line, const std::string& detail) {
    throw AssertionFailure(std::string(file) + ":" + std::to_string(line) + ": " + detail);
}

}  // namespace faceauth::testing

#define FACEAUTH_TEST(name)                                                         \
    static void name();                                                             \
    static ::faceauth::testing::Registrar registrar_##name(#name, []() { name(); }); \
    static void name()

#define CHECK(condition)                                                                    \
    do {                                                                                    \
        if (!(condition)) {                                                                 \
            ::faceauth::testing::fail(__FILE__, __LINE__, "CHECK failed: " #condition);     \
        }                                                                                   \
    } while (false)

#define CHECK_EQ(actual, expected)                                                          \
    do {                                                                                    \
        const auto& faceauth_actual = (actual);                                             \
        const auto& faceauth_expected = (expected);                                         \
        if (!(faceauth_actual == faceauth_expected)) {                                      \
            ::faceauth::testing::fail(__FILE__, __LINE__,                                   \
                                      "CHECK_EQ failed: " #actual " != " #expected);        \
        }                                                                                   \
    } while (false)

#endif  // FACEAUTH_TEST_HARNESS_HPP
