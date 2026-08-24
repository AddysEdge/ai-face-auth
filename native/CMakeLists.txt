cmake_minimum_required(VERSION 3.21)

project(faceauth_native
    VERSION 0.1.0
    DESCRIPTION "Phase 2 IPC contract scaffold - NOT a Credential Provider, NOT a service"
    LANGUAGES CXX)

# --------------------------------------------------------------------------
# What this project is, and is not.
#
# It builds a static library implementing the versioned IPC contract from
# docs/adr/0003-ipc-security-protocol.md, a test executable, and a fake
# client/server tool that runs on the normal desktop.
#
# It deliberately does NOT build a Credential Provider DLL, does not register
# any COM class, does not install a Windows service, does not construct any
# Windows credential structure, and does not link against any authentication,
# TPM, certificate, or camera API. See docs/PHASE2_ACCEPTANCE_CRITERIA.md
# Part C for the full exclusion list.
# --------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(FACEAUTH_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

if(WIN32)
    # Target x64 only. The Phase 2 brief specifies Windows x64; a 32-bit build
    # is neither tested nor supported.
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        message(FATAL_ERROR
            "faceauth_native targets Windows x64 only. Configure with -A x64.")
    endif()
endif()

add_library(faceauth_ipc STATIC
    src/protocol.cpp
    src/wire.cpp
    src/clock.cpp
    src/random.cpp
    src/replay_cache.cpp
    src/boundaries.cpp
    src/state_machine.cpp
    src/diagnostics.cpp
    src/transport_memory.cpp
    src/transport_pipe_win.cpp
    src/fake_peer.cpp
)

target_include_directories(faceauth_ipc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

# No third-party runtime dependencies. On Windows the only extra libraries are
# OS components already present: bcrypt for CSPRNG bytes, advapi32 for the
# SDDL helper used by the user-owned test pipe.
if(WIN32)
    target_link_libraries(faceauth_ipc PUBLIC bcrypt advapi32)
    target_compile_definitions(faceauth_ipc PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

find_package(Threads REQUIRED)
target_link_libraries(faceauth_ipc PUBLIC Threads::Threads)

function(faceauth_set_strict_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
        if(FACEAUTH_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
        if(FACEAUTH_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

faceauth_set_strict_warnings(faceauth_ipc)

# --------------------------------------------------------------------------
# Fake client/server tool. Normal desktop, opaque test identities, simulated
# outcomes. Not an authentication tool.
# --------------------------------------------------------------------------
add_executable(faceauth_ipc_fake tools/fake_peer_main.cpp)
target_link_libraries(faceauth_ipc_fake PRIVATE faceauth_ipc)
faceauth_set_strict_warnings(faceauth_ipc_fake)

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------
include(CTest)
enable_testing()

add_executable(faceauth_ipc_tests
    tests/test_main.cpp
    tests/test_protocol.cpp
)
target_include_directories(faceauth_ipc_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(faceauth_ipc_tests PRIVATE faceauth_ipc)
faceauth_set_strict_warnings(faceauth_ipc_tests)

# Each protocol test is registered with CTest individually so a failure names
# exactly one behaviour. Keep this list in sync with tests/test_protocol.cpp;
# `faceauth_ipc_tests --list` prints the names the binary actually has, and
# the guard test below fails if the two drift apart.
set(FACEAUTH_TEST_NAMES
    round_trip_all_message_types
    malformed_message_is_rejected
    truncated_message_is_rejected
    unknown_protocol_version_is_rejected
    oversized_message_is_rejected_before_allocation
    opaque_fields_are_length_capped
    empty_account_binding_is_rejected
    valid_request_response_flow
    denied_verification_is_reported_as_deny
    exhausted_backend_script_denies
    duplicate_request_id_is_rejected
    replayed_nonce_is_rejected
    replay_cache_evicts_expired_entries
    full_replay_cache_fails_closed
    expired_request_is_rejected_by_server
    excessive_request_lifetime_is_rejected
    result_never_outlives_its_request
    expired_result_cannot_be_consumed
    result_arriving_after_the_deadline_is_rejected
    client_timeout_denies
    server_timeout_denies
    cancellation_moves_both_sides_out_of_flight
    client_invalid_state_transition
    client_rejects_a_request_message_from_the_server
    server_invalid_state_transition
    server_rejects_a_result_message_from_the_client
    result_with_wrong_identity_binding_is_rejected
    result_with_wrong_request_id_is_rejected
    result_with_wrong_nonce_is_rejected
    successful_result_cannot_be_reused
    client_handles_server_disconnect
    server_handles_client_disconnect
    mid_request_disconnect_denies
    service_restart_voids_an_in_flight_request
    concurrent_requests_are_admission_controlled
    concurrent_sessions_do_not_share_replay_state
    end_to_end_exchange_over_in_memory_transport
    secure_random_produces_distinct_identifiers
    diagnostics_reject_forbidden_field_names
    diagnostics_allow_opaque_identifier_fields
    diagnostics_reject_unsafe_values
    identifiers_are_only_ever_logged_as_short_prefixes
    protocol_test_results_are_labelled_as_such
)

foreach(test_name IN LISTS FACEAUTH_TEST_NAMES)
    add_test(NAME protocol.${test_name}
             COMMAND faceauth_ipc_tests ${test_name})
endforeach()

# Running with no arguments executes every registered test and returns a
# non-zero exit code if any fails. This catches a test that exists in the
# source but was never added to FACEAUTH_TEST_NAMES above.
add_test(NAME protocol.all_registered_tests COMMAND faceauth_ipc_tests)

# End-to-end exercises of the fake peers, as separate processes.
add_test(NAME fake_peer.memory_allow COMMAND faceauth_ipc_fake --memory)
add_test(NAME fake_peer.memory_deny COMMAND faceauth_ipc_fake --memory-deny)
if(WIN32)
    add_test(NAME fake_peer.named_pipe_loopback COMMAND faceauth_ipc_fake --pipe)
endif()
