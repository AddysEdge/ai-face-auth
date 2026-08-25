#include <cstdio>
#include <exception>
#include <string>

#include "test_harness.hpp"

using faceauth::testing::AssertionFailure;
using faceauth::testing::Registry;

namespace {

int run_one(const std::string& name) {
    const auto& tests = Registry::instance().tests();
    const auto it = tests.find(name);
    if (it == tests.end()) {
        std::printf("unknown test: %s\n", name.c_str());
        return 2;
    }
    try {
        it->second();
    } catch (const AssertionFailure& failure) {
        std::printf("FAIL %s\n  %s\n", name.c_str(), failure.message().c_str());
        return 1;
    } catch (const std::exception& error) {
        std::printf("FAIL %s\n  unexpected exception: %s\n", name.c_str(), error.what());
        return 1;
    } catch (...) {
        std::printf("FAIL %s\n  unexpected non-standard exception\n", name.c_str());
        return 1;
    }
    std::printf("PASS %s\n", name.c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--list") {
        for (const auto& entry : Registry::instance().tests()) {
            std::printf("%s\n", entry.first.c_str());
        }
        return 0;
    }
    if (argc > 1) {
        return run_one(argv[1]);
    }

    int failures = 0;
    for (const auto& entry : Registry::instance().tests()) {
        failures += (run_one(entry.first) == 0) ? 0 : 1;
    }
    std::printf("%d failing test(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
