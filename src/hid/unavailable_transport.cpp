// Placeholder transport for the "no device" state.
//
// An IOHIDUserDevice needs a restricted entitlement. Without it the daemon used
// to exit, which under the packaged LaunchAgent (KeepAlive: SuccessfulExit=false)
// turns into a restart loop and an app that appears to do nothing. Keeping the
// process alive with this transport means the menu bar can explain the problem,
// the control socket still answers, and the user can fix the signing and retry
// instead of guessing.
#include "swpasskey/hid/transport.hpp"

#include "swpasskey/log/log.hpp"

#include <chrono>
#include <thread>
#include <utility>

namespace swpk::hid {
namespace {

class UnavailableTransport final : public Transport {
public:
  explicit UnavailableTransport(std::string reason) : reason_(std::move(reason)) {}

  Result<void> open() override { return {}; }
  void close() noexcept override {}

  // Nothing can arrive: honour the timeout so the loop keeps its normal cadence
  // (keepalives, stop requests) at negligible cost.
  Result<std::optional<Report>> read(std::chrono::milliseconds timeout) override {
    std::this_thread::sleep_for(timeout);
    return std::optional<Report>{};
  }

  // No host is attached, so a report has nowhere to go. Dropping it keeps the
  // loop counters meaningful instead of failing the I/O thread.
  Result<void> write(std::span<const std::uint8_t, kReportSize>) override { return {}; }

  std::string describe() const override { return "unavailable"; }
  std::string last_error() const override { return reason_; }

private:
  std::string reason_;
};

}  // namespace

std::unique_ptr<Transport> make_unavailable_transport(std::string reason) {
  log::warn("hid_transport_unavailable",
            {{"reason", reason}, {"effect", "the key is not visible to browsers"}});
  return std::make_unique<UnavailableTransport>(std::move(reason));
}

}  // namespace swpk::hid
