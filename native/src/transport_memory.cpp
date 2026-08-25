#include "faceauth/ipc/transport.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>

#include "faceauth/ipc/protocol.hpp"

namespace faceauth::ipc {
namespace {

// One directed queue. Two of these, crossed over, make a duplex channel.
class Queue {
public:
    bool push(const std::vector<std::uint8_t>& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) {
            return false;
        }
        messages_.push_back(message);
        condition_.notify_all();
        return true;
    }

    TransportStatus pop(std::vector<std::uint8_t>& out, std::uint32_t timeout_ms) {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        while (messages_.empty() && !closed_) {
            if (condition_.wait_until(lock, deadline) == std::cv_status::timeout) {
                if (messages_.empty() && !closed_) {
                    return TransportStatus::Timeout;
                }
                break;
            }
        }
        if (!messages_.empty()) {
            out = messages_.front();
            messages_.pop_front();
            return TransportStatus::Ok;
        }
        return TransportStatus::Disconnected;
    }

    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        condition_.notify_all();
    }

    bool closed() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<std::vector<std::uint8_t>> messages_;
    bool closed_ = false;
};

class InMemoryTransport : public Transport {
public:
    InMemoryTransport(std::shared_ptr<Queue> inbound, std::shared_ptr<Queue> outbound)
        : inbound_(std::move(inbound)), outbound_(std::move(outbound)) {}

    TransportStatus send(const std::vector<std::uint8_t>& message) override {
        return send_with_timeout(message, 0u);
    }

    // The in-memory queue is unbounded, so a send never needs to wait and the
    // timeout is unused. It is accepted so this transport satisfies the same
    // contract as the named-pipe one, where the bound is load-bearing.
    TransportStatus send_with_timeout(const std::vector<std::uint8_t>& message,
                                      std::uint32_t timeout_ms) override {
        (void)timeout_ms;
        if (message.size() > kMaxMessageBytes) {
            // Oversized messages are refused at the transport too, so a bug
            // upstream cannot put one on the wire.
            return TransportStatus::Error;
        }
        return outbound_->push(message) ? TransportStatus::Ok : TransportStatus::Disconnected;
    }

    TransportStatus receive(std::vector<std::uint8_t>& out, std::uint32_t timeout_ms) override {
        return inbound_->pop(out, timeout_ms);
    }

    void close() override {
        outbound_->close();
        inbound_->close();
    }

    bool connected() const override { return !inbound_->closed() && !outbound_->closed(); }

private:
    std::shared_ptr<Queue> inbound_;
    std::shared_ptr<Queue> outbound_;
};

}  // namespace

const char* to_string(TransportStatus status) {
    switch (status) {
        case TransportStatus::Ok: return "Ok";
        case TransportStatus::Timeout: return "Timeout";
        case TransportStatus::Disconnected: return "Disconnected";
        case TransportStatus::Error: return "Error";
    }
    return "Unknown";
}

std::pair<std::shared_ptr<Transport>, std::shared_ptr<Transport>> make_in_memory_pair() {
    auto a_to_b = std::make_shared<Queue>();
    auto b_to_a = std::make_shared<Queue>();
    auto a = std::make_shared<InMemoryTransport>(b_to_a, a_to_b);
    auto b = std::make_shared<InMemoryTransport>(a_to_b, b_to_a);
    return {a, b};
}

}  // namespace faceauth::ipc
