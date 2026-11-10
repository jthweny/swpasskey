#include "swpasskey/ctap/authenticator.hpp"

#include "ctap_internal.hpp"
#include "pin_state.hpp"
#include "swpasskey/log/log.hpp"

#include <chrono>
#include <cstdio>
#include <string>

namespace swpk::ctap {
namespace {

const char* cmd_name(std::uint8_t cmd) {
  switch (cmd) {
    case kCmdMakeCredential:
      return "makeCredential";
    case kCmdGetAssertion:
      return "getAssertion";
    case kCmdGetInfo:
      return "getInfo";
    case kCmdClientPin:
      return "clientPIN";
    case kCmdReset:
      return "reset";
    case kCmdGetNextAssertion:
      return "getNextAssertion";
    case kCmdAuthenticatorSelection:
      return "authenticatorSelection";
    default:
      return "unknown";
  }
}

const char* backend_name(crypto::BackendKind k) {
  switch (k) {
    case crypto::BackendKind::Software:
      return "software";
    case crypto::BackendKind::Tpm2:
      return "tpm2";
    case crypto::BackendKind::SecureEnclave:
      return "se";
  }
  return "software";
}

}  // namespace

Authenticator::Authenticator(AuthenticatorConfig cfg, crypto::Provider& crypto,
                             crypto::KeyBackend& primary_keys, crypto::KeyBackend& software_keys,
                             store::CredentialStore& store, ui::Presence& presence)
    : cfg_(cfg),
      crypto_(crypto),
      primary_(primary_keys),
      software_(software_keys),
      store_(store),
      presence_(presence),
      pin_(std::make_unique<detail::PinManager>(crypto, store, cfg.pin_failure_delay_base,
                                                cfg.pin_token_idle_timeout)) {
  attester_ = std::make_unique<BatchAttester>(crypto, cfg.attestation_key_path);
  if (cfg.attestation_chain_dir.has_value()) {
    if (auto r = attester_->use_vendor_chain(*cfg.attestation_chain_dir); !r) {
      log::warn("vendor_chain_unused", {{"dir", cfg.attestation_chain_dir->string()}});
    }
  }
}

Authenticator::~Authenticator() = default;

const char* Authenticator::primary_backend_name() const { return backend_name(primary_.kind()); }

AuthenticatorMetrics Authenticator::metrics() const {
  std::lock_guard<std::mutex> lk(metrics_mu_);
  AuthenticatorMetrics m = metrics_;
  m.pin_fail = pin_->pin_fail_count();
  m.pin_block = pin_->pin_block_count();
  return m;
}

void Authenticator::count_status(std::uint8_t status) {
  std::lock_guard<std::mutex> lk(metrics_mu_);
  ++metrics_.ctap_status[status];
}

std::uint64_t Authenticator::now_unix() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
}

GetInfoSnapshot Authenticator::get_info() const {
  GetInfoSnapshot s;
  s.versions = {"FIDO_2_1", "FIDO_2_0"};  // K24: PIN (PR9) + dual-credRandom hmac-secret (PR10)
  if (cfg_.u2f_enabled) {
    s.versions.emplace_back("U2F_V2");  // PR11; CTAP2 versions stay first
  }
  s.extensions = {"hmac-secret"};
  s.aaguid = current_aaguid();
  // Security-key semantics, not platform-authenticator semantics:
  //   plat=false (a roaming key), rk=true (discoverable credentials),
  //   uv=true  (user verification through PIN protocol 2),
  //   clientPin always present so the host knows the capability exists.
  // uv is a capability claim, not a bypass: an assertion only carries UV after
  // the PIN token verified, so a key with no PIN set answers PIN_NOT_SET and
  // the browser walks the user through creating one.
  s.options.plat = false;
  s.options.rk = true;
  s.options.client_pin = pin_->pin_set();
  s.options.uv = true;
  s.options.pin_uv_auth_token = true;
  s.pin_protocols = {2};
  s.remaining_discoverable = static_cast<std::uint32_t>(store_.remaining());
  return s;
}

std::shared_ptr<const compat::CompatProfile> Authenticator::profile() const {
  if (cfg_.identity) {
    return cfg_.identity->profile();
  }
  static const std::shared_ptr<const compat::CompatProfile> kFallback =
      std::make_shared<const compat::CompatProfile>(compat::default_profile());
  return kFallback;
}

std::array<std::uint8_t, 16> Authenticator::current_aaguid() const {
  if (cfg_.identity) {
    auto p = cfg_.identity->profile();
    if (p) {
      return p->aaguid;
    }
  }
  return cfg_.aaguid;
}

void Authenticator::set_profile(const compat::CompatProfile& profile) {
  std::lock_guard<std::mutex> lk(op_mu_);
  cfg_.aaguid = profile.aaguid;
  if (!cfg_.identity) {
    cfg_.identity = std::make_shared<compat::Identity>();
  }
  cfg_.identity->set(std::make_shared<const compat::CompatProfile>(profile));
  if (attester_) {
    attester_->invalidate();  // the leaf names the previous model
  }
  char vid[8];
  std::snprintf(vid, sizeof vid, "0x%04x", static_cast<unsigned>(profile.vid));
  log::warn("profile_switched",
            {{"profile", profile.id},
             {"aaguid", profile.aaguid_str},
             {"vid", vid},
             {"note", "credentials are kept; reset them to emulate a fresh key"}});
}

std::string Authenticator::attestation_summary() {
  std::lock_guard<std::mutex> lk(op_mu_);
  if (!attester_) {
    return "unavailable";
  }
  const auto prof = profile();
  const PackedAttestation* att = prof ? attester_->for_profile(*prof) : nullptr;
  if (att == nullptr) {
    return "unavailable";
  }
  std::string out = "source=" + att->source;
  out += " profile=" + (att->profile_id.empty() ? std::string("vendor-chain") : att->profile_id);
  out += " der_len=" + std::to_string(att->chain.empty() ? 0 : att->chain.front().size());
  out += " chain=" + std::to_string(att->chain.size());
  out += " subject=" + att->subject;
  out += " issuer=" + att->issuer;
  out += " sha256=" + att->leaf_sha256;
  return out;
}

void Authenticator::record_registration(const store::Credential& cred, std::uint8_t flags,
                                        const PackedAttestation* att, bool x5c_present) {
  if (cfg_.diag == nullptr) {
    return;
  }
  const auto prof = profile();
  diag::RegistrationRecord r;
  r.profile_id = prof ? prof->id : "unknown";
  r.profile_name = prof ? prof->name : "unknown";
  r.aaguid = prof ? prof->aaguid_str : compat::aaguid_to_string(current_aaguid());
  r.rp_id = cred.rp_id;
  r.cred_id_hex = [&] {
    std::string s;
    for (auto b : cred.cred_id) {
      char buf[3];
      std::snprintf(buf, sizeof buf, "%02x", static_cast<unsigned>(b));
      s += buf;
    }
    return s;
  }();
  r.attestation_format = "packed";
  r.x5c_present = x5c_present;
  if (att != nullptr) {
    r.attestation_source = att->source;
    r.x5c_len = att->chain.size();
    r.x5c_subject = att->subject;
    r.x5c_issuer = att->issuer;
    r.x5c_leaf_sha256 = att->leaf_sha256;
  } else {
    r.attestation_source = "none";
  }
  r.flag_up = (flags & detail::kFlagUp) != 0;
  r.flag_uv = (flags & detail::kFlagUv) != 0;
  r.flag_be = (flags & detail::kFlagBe) != 0;
  r.flag_bs = (flags & detail::kFlagBs) != 0;
  r.flag_at = (flags & detail::kFlagAt) != 0;
  r.flag_ed = (flags & detail::kFlagEd) != 0;
  r.sign_count = cred.sign_count;
  r.key_backend = primary_backend_name();
  r.timestamp = diag::iso8601_now();
  cfg_.diag->record(std::move(r));
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_get_info() {
  return encode_get_info(get_info());
}

ui::Decision Authenticator::confirm_up(ui::PresenceRequest::Kind kind, const std::string& rp_id,
                                       const std::string& user_display,
                                       std::span<const std::uint8_t, 32> rp_id_hash,
                                       CancelToken& cancel) {
  if (cancel.is_cancelled()) {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    ++metrics_.up_cancel;
    return ui::Decision::Cancelled;
  }
  ui::PresenceRequest req;
  req.kind = kind;
  req.rp_id = rp_id;
  req.user_display = user_display;
  std::copy(rp_id_hash.begin(), rp_id_hash.end(), req.rp_id_hash.begin());
  cancel.set_up_needed(true);
  const ui::Decision d = presence_.confirm(req, cancel, cfg_.up_timeout);
  cancel.set_up_needed(false);
  {
    std::lock_guard<std::mutex> lk(metrics_mu_);
    switch (d) {
      case ui::Decision::Allow:
        ++metrics_.up_allow;
        break;
      case ui::Decision::Deny:
        ++metrics_.up_deny;
        break;
      case ui::Decision::Timeout:
        ++metrics_.up_timeout;
        break;
      case ui::Decision::Cancelled:
        ++metrics_.up_cancel;
        break;
    }
  }
  return d;
}

bool Authenticator::pin_set() const { return pin_ != nullptr && pin_->pin_set(); }

Result<bool> Authenticator::check_pin_auth(const PinAuthIn& in,
                                           std::span<const std::uint8_t, 32> client_data_hash,
                                           std::uint8_t permission, const std::string& rp_id,
                                           std::span<const std::uint8_t, 32> rp_id_hash,
                                           bool is_make, CancelToken& cancel) {
  if (!in.param.has_value()) {
    if (is_make && pin_->pin_set()) {
      return std::unexpected(Status::PuattRequired);  // makeCredUvNotRqd=false
    }
    return false;  // getAssertion without PIN is allowed (alwaysUv=false): UV=0
  }
  if (!in.protocol.has_value()) {
    return std::unexpected(Status::MissingParameter);
  }
  if (*in.protocol != 2) {
    return std::unexpected(Status::InvalidParameter);
  }
  if (in.param->empty()) {
    // CTAP 2.1 §6.1.2 step 1 / §6.2.2 step 1: zero-length param → collect UP,
    // then report whether a PIN is set. Used by platforms to pick a device.
    const auto d = confirm_up(is_make ? ui::PresenceRequest::Kind::MakeCredential
                                      : ui::PresenceRequest::Kind::GetAssertion,
                              rp_id, "", rp_id_hash, cancel);
    if (d == ui::Decision::Cancelled) {
      return std::unexpected(Status::KeepaliveCancel);
    }
    if (d != ui::Decision::Allow) {
      return std::unexpected(Status::OperationDenied);
    }
    return std::unexpected(pin_->pin_set() ? Status::PinInvalid : Status::PinNotSet);
  }
  return pin_->verify(*in.param, *in.protocol, client_data_hash, permission, rp_id);
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_client_pin(std::span<const std::uint8_t> body,
                                                                CancelToken& cancel) {
  return pin_->handle(body, cancel);
}

Result<std::unique_ptr<crypto::SigningKey>> Authenticator::load_key(const store::Credential& c) {
  if (c.backend == crypto::BackendKind::Software) {
    return software_.load(c.priv, c.pub);
  }
  if (primary_.kind() != c.backend) {
    log::error("key_backend_unavailable", {{"rp", c.rp_id},
                                           {"row_backend", backend_name(c.backend)},
                                           {"probed", backend_name(primary_.kind())}});
    return std::unexpected(Status::InvalidCredential);
  }
  auto k = primary_.load(c.handle, c.pub);
  if (!k) {
    log::error("key_load_failed", {{"rp", c.rp_id}, {"backend", backend_name(c.backend)}});
    return std::unexpected(Status::InvalidCredential);
  }
  return k;
}

void Authenticator::destroy_key(const store::Credential& c) {
  if (c.backend == crypto::BackendKind::Software) {
    (void)software_.destroy(c.priv);
    (void)software_.destroy_secret(c.cred_random);
  } else if (primary_.kind() == c.backend) {
    (void)primary_.destroy(c.handle);
    (void)primary_.destroy_secret(c.cred_random);
  } else {
    log::warn("destroy_skipped_backend_unavailable", {{"backend", backend_name(c.backend)}});
  }
}

Result<std::vector<std::uint8_t>> Authenticator::cmd_reset(CancelToken& cancel) {
  static const std::array<std::uint8_t, 32> kZero{};
  const auto d = confirm_up(ui::PresenceRequest::Kind::Reset, "", "", kZero, cancel);
  if (d == ui::Decision::Cancelled) {
    return std::unexpected(Status::KeepaliveCancel);
  }
  if (d == ui::Decision::Timeout) {
    return std::unexpected(Status::UserActionTimeout);
  }
  if (d != ui::Decision::Allow) {
    return std::unexpected(Status::OperationDenied);
  }
  next_state_.reset();
  auto r = store_.factory_reset([this](const store::Credential& c) { destroy_key(c); });
  if (!r) {
    return std::unexpected(Status::Other);
  }
  (void)pin_->regenerate_key_agreement();  // drops the token and the ECDH key
  if (auto ri = primary_.reinit_after_reset(); !ri) {
    log::error("key_backend_reinit_failed", {{"backend", primary_backend_name()}});
    return std::unexpected(Status::Other);
  }
  log::warn("factory_reset");
  return std::vector<std::uint8_t>{};
}

// authenticatorSelection (0x0B): user presence only, empty response. Chrome
// uses it to let the user pick one of several plugged-in keys; answering
// INVALID_COMMAND makes Chrome drop this authenticator for the request.
Result<std::vector<std::uint8_t>> Authenticator::cmd_authenticator_selection(
    CancelToken& cancel) {
  static const std::array<std::uint8_t, 32> kZero{};
  const auto d = confirm_up(ui::PresenceRequest::Kind::Selection, "", "", kZero, cancel);
  if (d == ui::Decision::Cancelled) {
    return std::unexpected(Status::KeepaliveCancel);
  }
  if (d == ui::Decision::Timeout) {
    return std::unexpected(Status::UserActionTimeout);
  }
  if (d != ui::Decision::Allow) {
    return std::unexpected(Status::OperationDenied);
  }
  return std::vector<std::uint8_t>{};
}

Result<void> Authenticator::ctl_reset(CancelToken& cancel) {
  std::lock_guard<std::mutex> lk(op_mu_);
  auto r = cmd_reset(cancel);
  if (!r) {
    return std::unexpected(r.error());
  }
  return {};
}

Result<void> Authenticator::ctl_set_pin(std::string_view pin, CancelToken& cancel) {
  std::lock_guard<std::mutex> lk(op_mu_);
  static const std::array<std::uint8_t, 32> kZero{};
  const auto d = confirm_up(ui::PresenceRequest::Kind::SetPin, "", "", kZero, cancel);
  if (d == ui::Decision::Cancelled) {
    return std::unexpected(Status::KeepaliveCancel);
  }
  if (d == ui::Decision::Timeout) {
    return std::unexpected(Status::UserActionTimeout);
  }
  if (d != ui::Decision::Allow) {
    return std::unexpected(Status::OperationDenied);
  }
  return pin_->set_pin_local(pin);
}

Result<void> Authenticator::ctl_delete(std::span<const std::uint8_t> cred_id) {
  std::lock_guard<std::mutex> lk(op_mu_);
  auto row = store_.find_by_id(cred_id);
  if (!row) {
    return std::unexpected(Status::InvalidCredential);
  }
  destroy_key(*row);
  next_state_.reset();
  return store_.erase(cred_id);
}

Result<std::vector<std::uint8_t>> Authenticator::handle_cbor(
    std::span<const std::uint8_t> request, CancelToken& cancel) {
  std::lock_guard<std::mutex> lk(op_mu_);
  if (request.empty()) {
    return std::unexpected(Status::InvalidLength);
  }
  const std::uint8_t cmd = request[0];
  const auto body = request.subspan(1);
  const auto t0 = std::chrono::steady_clock::now();
  if (cmd != kCmdGetNextAssertion) {
    next_state_.reset();  // CTAP 2.1: any other command invalidates the pending list
  }
  Result<std::vector<std::uint8_t>> r;
  switch (cmd) {
    case kCmdGetInfo:
      r = cmd_get_info();
      break;
    case kCmdMakeCredential:
      r = cmd_make_credential(body, cancel);
      break;
    case kCmdGetAssertion:
      r = cmd_get_assertion(body, cancel);
      break;
    case kCmdGetNextAssertion:
      r = cmd_get_next_assertion();
      break;
    case kCmdReset:
      r = cmd_reset(cancel);
      break;
    case kCmdClientPin:
      r = cmd_client_pin(body, cancel);
      break;
    case kCmdAuthenticatorSelection:
      r = cmd_authenticator_selection(cancel);
      break;
    default:
      r = std::unexpected(Status::InvalidCommand);
      break;
  }
  const std::uint8_t status = r ? 0 : static_cast<std::uint8_t>(r.error());
  count_status(status);
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0);
  char cmd_hex[5];
  std::snprintf(cmd_hex, sizeof cmd_hex, "0x%02x", static_cast<unsigned>(cmd));
  log::info("ctap", {{"cmd", cmd_name(cmd)},
                     {"cmd_byte", cmd_hex},
                     {"status", std::to_string(status)},
                     {"ms", std::to_string(ms.count())}});
  return r;
}

}  // namespace swpk::ctap
