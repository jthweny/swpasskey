#include "swpasskey/ctap/attestation.hpp"

#include "ctap_internal.hpp"

#include "swpasskey/cbor/cbor.hpp"
#include "swpasskey/log/log.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

namespace swpk::ctap {
namespace {

constexpr char kHex[] = "0123456789abcdef";

std::string to_hex(std::span<const std::uint8_t> v) {
  std::string s;
  s.reserve(v.size() * 2);
  for (auto b : v) {
    s.push_back(kHex[b >> 4]);
    s.push_back(kHex[b & 0x0F]);
  }
  return s;
}

// The batch attestation scalar: 32 raw bytes, 0600, next to the store. One key
// for the lifetime of the installation, exactly like a vendor batch key.
Result<std::array<std::uint8_t, 32>> load_or_create_scalar(crypto::Provider& crypto,
                                                           const std::filesystem::path& path) {
  std::array<std::uint8_t, 32> out{};
  const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd >= 0) {
    std::size_t got = 0;
    while (got < out.size()) {
      const ssize_t n = ::read(fd, out.data() + got, out.size() - got);
      if (n <= 0) {
        break;
      }
      got += static_cast<std::size_t>(n);
    }
    ::close(fd);
    if (got == out.size()) {
      return out;
    }
    log::warn("attestation_key_unreadable", {{"path", path.string()}, {"action", "regenerating"}});
  }
  if (auto r = crypto.random(out); !r) {
    return std::unexpected(Status::Other);
  }
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  const int wfd =
      ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (wfd < 0) {
    log::error("attestation_key_write_failed",
               {{"path", path.string()}, {"errno", std::strerror(errno)}});
    return std::unexpected(Status::Other);
  }
  const ssize_t n = ::write(wfd, out.data(), out.size());
  ::fsync(wfd);
  ::close(wfd);
  if (n != static_cast<ssize_t>(out.size())) {
    return std::unexpected(Status::Other);
  }
  log::info("attestation_key_created", {{"path", path.string()}});
  return out;
}

}  // namespace

BatchAttester::BatchAttester(crypto::Provider& crypto, std::filesystem::path key_path)
    : crypto_(crypto), key_path_(std::move(key_path)) {
  if (!key_path_.empty()) {
    auto sc = load_or_create_scalar(crypto_, key_path_);
    if (sc) {
      scalar_ = *sc;
      have_key_ = true;
    } else {
      log::error("attestation_key_unavailable", {{"path", key_path_.string()}});
    }
  }
}

void BatchAttester::invalidate() { cached_.reset(); }

Result<void> BatchAttester::use_vendor_chain(const std::filesystem::path& dir) {
  return load_vendor_chain(dir);
}

Result<void> BatchAttester::load_vendor_chain(const std::filesystem::path& dir) {
  const auto leaf_path = dir / "leaf.pem";
  const auto key_path = dir / "leaf.key";
  const auto chain_path = dir / "chain.pem";
  auto leaf = crypto::load_pem_certs(leaf_path);
  if (!leaf || leaf->empty()) {
    log::error("vendor_chain_leaf_missing", {{"path", leaf_path.string()}});
    return std::unexpected(Status::Other);
  }
  PackedAttestation att;
  att.chain = std::move(*leaf);
  if (std::filesystem::exists(chain_path)) {
    auto rest = crypto::load_pem_certs(chain_path);
    if (!rest) {
      log::error("vendor_chain_pem_invalid", {{"path", chain_path.string()}});
      return std::unexpected(Status::Other);
    }
    for (auto& c : *rest) {
      att.chain.push_back(std::move(c));
    }
  }
  if (!std::filesystem::exists(key_path)) {
    log::error("vendor_chain_key_missing", {{"path", key_path.string()}});
    return std::unexpected(Status::Other);
  }
  auto names = crypto::x509_subject_issuer(att.chain.front());
  if (names) {
    att.subject = std::move(names->first);
    att.issuer = std::move(names->second);
  }
  att.leaf_sha256 = to_hex(crypto_.sha256(att.chain.front()));
  att.source = "vendor-chain";
  att.pem_key = key_path;
  vendor_ = std::move(att);
  cached_.reset();
  log::warn("vendor_chain_loaded",
            {{"leaf", leaf_path.string()},
             {"chain_len", std::to_string(vendor_->chain.size())},
             {"subject", vendor_->subject},
             {"issuer", vendor_->issuer}});
  return {};
}

Result<PackedAttestation> BatchAttester::build_self_signed(const compat::CompatProfile& profile) {
  if (!have_key_) {
    if (!key_path_.empty()) {
      return std::unexpected(Status::Other);  // failed to load; do not silently replace it
    }
    if (auto r = crypto_.random(scalar_); !r) {
      return std::unexpected(Status::Other);
    }
    have_key_ = true;
  }
  if (!have_pub_) {
    auto pub = crypto::p256_pub_from_scalar(scalar_);
    if (!pub) {
      return std::unexpected(pub.error());
    }
    pub_ = *pub;
    have_pub_ = true;
  }
  crypto::AttestationCertSpec spec;
  spec.subject_cn = profile.att_cn.empty() ? profile.product : profile.att_cn;
  spec.subject_ou = profile.att_ou;
  spec.subject_o = profile.att_o.empty() ? profile.manufacturer : profile.att_o;
  spec.subject_c = profile.att_c;
  spec.aaguid = profile.aaguid;
  auto leaf = crypto::make_self_signed_attestation_cert(scalar_, pub_, spec);
  if (!leaf) {
    log::error("attestation_cert_failed", {{"profile", profile.id}});
    return std::unexpected(leaf.error());
  }
  PackedAttestation att;
  att.chain.push_back(std::move(*leaf));
  att.source = "self-signed";
  att.profile_id = profile.id;
  att.scalar = scalar_;
  att.pub = pub_;
  att.leaf_sha256 = to_hex(crypto_.sha256(att.chain.front()));
  if (auto names = crypto::x509_subject_issuer(att.chain.front()); names) {
    att.subject = std::move(names->first);
    att.issuer = std::move(names->second);
  }
  log::info("attestation_self_signed",
            {{"profile", profile.id},
             {"aaguid", profile.aaguid_str},
             {"subject", att.subject},
             {"issuer", att.issuer},
             {"note", "self-signed: does not chain to the modelled vendor root"}});
  return att;
}

const PackedAttestation* BatchAttester::for_profile(const compat::CompatProfile& profile) {
  if (vendor_.has_value()) {
    return &*vendor_;
  }
  if (cached_.has_value() && cached_->profile_id == profile.id) {
    return &*cached_;
  }
  auto att = build_self_signed(profile);
  if (!att) {
    return nullptr;
  }
  cached_ = std::move(*att);
  return &*cached_;
}

std::vector<std::uint8_t> encode_packed_att_stmt(std::span<const std::uint8_t> sig,
                                                std::span<const std::vector<std::uint8_t>> chain) {
  using detail::Entry;
  using cbor::Writer;
  std::vector<Entry> stmt;
  stmt.emplace_back(Writer::encode_tstr("alg"), Writer::encode_int(-7));  // ES256
  stmt.emplace_back(Writer::encode_tstr("sig"), Writer::encode_bstr(sig));
  if (!chain.empty()) {
    Writer x5c;
    x5c.write_array_header(chain.size());
    for (const auto& c : chain) {
      x5c.write_raw(Writer::encode_bstr(c));
    }
    stmt.emplace_back(Writer::encode_tstr("x5c"), x5c.finish());
  }
  Writer w;
  w.write_map(std::move(stmt));
  return w.finish();
}

Result<std::vector<std::uint8_t>> sign_attestation(const PackedAttestation& att,
                                                   crypto::KeyBackend& software,
                                                   std::span<const std::uint8_t> msg) {
  if (att.pem_key.has_value()) {
    return crypto::sign_pem_ecdsa_sha256(*att.pem_key, msg);
  }
  auto key = software.load(std::span<const std::uint8_t>(att.scalar), att.pub);
  if (!key) {
    return std::unexpected(Status::Other);
  }
  return (*key)->sign_der(msg);
}

}  // namespace swpk::ctap
