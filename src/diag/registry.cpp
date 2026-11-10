#include "swpasskey/diag/registry.hpp"

#include "swpasskey/log/log.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string_view>

namespace swpk::diag {
namespace {

std::string escape(std::string_view in) {
  std::string out;
  out.reserve(in.size() + 2);
  for (char c : in) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(c));
          out += buf;
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

void kv(std::string& out, bool& first, std::string_view key, std::string_view value) {
  if (!first) {
    out.push_back(',');
  }
  first = false;
  out.push_back('"');
  out += key;
  out += "\":\"";
  out += escape(value);
  out.push_back('"');
}

void kv(std::string& out, bool& first, std::string_view key, bool value) {
  if (!first) {
    out.push_back(',');
  }
  first = false;
  out.push_back('"');
  out += key;
  out += value ? "\":true" : "\":false";
}

void kv(std::string& out, bool& first, std::string_view key, std::uint64_t value) {
  if (!first) {
    out.push_back(',');
  }
  first = false;
  out.push_back('"');
  out += key;
  out += "\":";
  out += std::to_string(value);
}

std::string record_json(const RegistrationRecord& r) {
  std::string out = "{";
  bool first = true;
  kv(out, first, "timestamp", r.timestamp);
  kv(out, first, "profile", r.profile_id);
  kv(out, first, "profile_name", r.profile_name);
  kv(out, first, "aaguid", r.aaguid);
  kv(out, first, "rp_id", r.rp_id);
  kv(out, first, "credential_id", r.cred_id_hex);
  kv(out, first, "attestation_format", r.attestation_format);
  kv(out, first, "attestation_source", r.attestation_source);
  kv(out, first, "x5c_present", r.x5c_present);
  kv(out, first, "x5c_len", static_cast<std::uint64_t>(r.x5c_len));
  kv(out, first, "x5c_subject", r.x5c_subject);
  kv(out, first, "x5c_issuer", r.x5c_issuer);
  kv(out, first, "x5c_leaf_sha256", r.x5c_leaf_sha256);
  if (!first) {
    out.push_back(',');
  }
  out += "\"flags\":{";
  bool ff = true;
  kv(out, ff, "up", r.flag_up);
  kv(out, ff, "uv", r.flag_uv);
  kv(out, ff, "be", r.flag_be);
  kv(out, ff, "bs", r.flag_bs);
  kv(out, ff, "at", r.flag_at);
  kv(out, ff, "ed", r.flag_ed);
  out += "},";
  bool rest = true;
  kv(out, rest, "sign_count", static_cast<std::uint64_t>(r.sign_count));
  kv(out, rest, "key_backend", r.key_backend);
  out += "}";
  return out;
}

bool ensure_parent(const std::filesystem::path& file) {
  std::error_code ec;
  const auto dir = file.parent_path();
  if (dir.empty() || std::filesystem::is_directory(dir, ec)) {
    return true;
  }
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    return false;
  }
  ::chmod(dir.c_str(), 0700);
  return true;
}

}  // namespace

std::string iso8601_now() {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const auto secs = time_point_cast<seconds>(now);
  const auto ms = duration_cast<milliseconds>(now - secs).count();
  const std::time_t t = system_clock::to_time_t(secs);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char buf[32];
  std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                static_cast<int>(ms));
  return buf;
}

void Registry::record(RegistrationRecord r) {
  if (r.timestamp.empty()) {
    r.timestamp = iso8601_now();
  }
  std::lock_guard<std::mutex> lk(mu_);
  if (entries_.size() >= kMaxRecords) {
    entries_.pop_front();
  }
  entries_.push_back(std::move(r));
  if (!export_path_.empty()) {
    (void)write_locked(export_path_);
  }
}

std::vector<RegistrationRecord> Registry::entries() const {
  std::lock_guard<std::mutex> lk(mu_);
  return std::vector<RegistrationRecord>(entries_.begin(), entries_.end());
}

void Registry::clear() {
  std::lock_guard<std::mutex> lk(mu_);
  entries_.clear();
}

Result<std::string> Registry::to_json() const {
  std::lock_guard<std::mutex> lk(mu_);
  std::string out = "{\"generated\":\"";
  out += iso8601_now();
  out += "\",\"count\":";
  out += std::to_string(entries_.size());
  out += ",\"records\":[";
  bool first = true;
  for (const auto& r : entries_) {
    if (!first) {
      out.push_back(',');
    }
    first = false;
    out += record_json(r);
  }
  out += "]}";
  return out;
}

Result<void> Registry::write_locked(const std::filesystem::path& path) const {
  if (!ensure_parent(path)) {
    return std::unexpected(Status::Other);
  }
  std::string body = "{\"generated\":\"";
  body += iso8601_now();
  body += "\",\"count\":";
  body += std::to_string(entries_.size());
  body += ",\"records\":[";
  bool first = true;
  for (const auto& r : entries_) {
    if (!first) {
      body.push_back(',');
    }
    first = false;
    body += record_json(r);
  }
  body += "]}\n";

  const auto tmp = path.string() + ".tmp";
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    log::error("diag_write_failed", {{"path", tmp}, {"errno", std::strerror(errno)}});
    return std::unexpected(Status::Other);
  }
  std::size_t off = 0;
  bool ok = true;
  while (off < body.size()) {
    const ssize_t n = ::write(fd, body.data() + off, body.size() - off);
    if (n <= 0) {
      ok = false;
      break;
    }
    off += static_cast<std::size_t>(n);
  }
  ::fsync(fd);
  ::close(fd);
  if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) {
    ::unlink(tmp.c_str());
    return std::unexpected(Status::Other);
  }
  return {};
}

Result<void> Registry::export_to(const std::filesystem::path& path) const {
  std::lock_guard<std::mutex> lk(mu_);
  return write_locked(path);
}

}  // namespace swpk::diag
