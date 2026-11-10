// Per-registration diagnostics: what this authenticator actually emitted, kept
// so a relying party's classification can be correlated with the exact bytes it
// received. No private key material and no PIN material is recorded.
#pragma once

#include "swpasskey/status.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace swpk::diag {

struct RegistrationRecord {
  // Identity
  std::string profile_id;
  std::string profile_name;
  std::string aaguid;        // 8-4-4-4-12 text, as sent in authData
  std::string rp_id;
  std::string cred_id_hex;
  // Attestation
  std::string attestation_format{"packed"};
  std::string attestation_source;  // "self-signed" | "vendor-chain" | "none"
  bool x5c_present{false};
  std::size_t x5c_len{0};
  std::string x5c_subject;
  std::string x5c_issuer;
  std::string x5c_leaf_sha256;  // hex digest of the DER leaf
  // authData flags (WebAuthn L3 §6.1). BE/BS must stay false for a device-bound
  // credential; UP/UV record what was actually asserted.
  bool flag_up{false};
  bool flag_uv{false};
  bool flag_be{false};
  bool flag_bs{false};
  bool flag_at{false};
  bool flag_ed{false};
  std::uint32_t sign_count{0};
  // Environment
  std::string key_backend;
  std::string timestamp;  // ISO-8601 UTC
};

// Bounded in-memory ring, thread-safe. Every record also rewrites the export
// file (when one was configured) so an operator never has to remember to dump
// state before closing a browser tab.
class Registry {
public:
  explicit Registry(std::filesystem::path export_path = {})
      : export_path_(std::move(export_path)) {}

  void record(RegistrationRecord r);
  std::vector<RegistrationRecord> entries() const;
  void clear();

  // {"generated":"…","count":N,"records":[…]}
  Result<std::string> to_json() const;
  Result<void> export_to(const std::filesystem::path& path) const;

  const std::filesystem::path& export_path() const { return export_path_; }
  void set_export_path(std::filesystem::path p) { export_path_ = std::move(p); }

  static constexpr std::size_t kMaxRecords = 512;

private:
  Result<void> write_locked(const std::filesystem::path& path) const;

  mutable std::mutex mu_;
  std::deque<RegistrationRecord> entries_;
  std::filesystem::path export_path_;
};

// ISO-8601 UTC with millisecond precision ("2026-01-31T09:12:03.481Z").
std::string iso8601_now();

}  // namespace swpk::diag
