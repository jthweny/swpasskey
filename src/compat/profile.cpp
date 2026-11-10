#include "swpasskey/compat/profile.hpp"

#include <algorithm>
#include <cctype>

namespace swpk::compat {
namespace {

// AAGUID bytes spelled out as text so a reviewer can diff them against the
// FIDO MDS entry without decoding hex.
constexpr Aaguid kStockAaguid{0x6f, 0xb1, 0xdf, 0xdd, 0x51, 0xc0, 0x43, 0xa0,
                              0xa6, 0xf2, 0xf7, 0x48, 0x12, 0xcb, 0xf8, 0xfb};
constexpr Aaguid kYubicoSecurityKeyCNfc58{0x0f, 0x08, 0x3f, 0x18, 0x41, 0x05, 0x43, 0xa8,
                                          0xad, 0x69, 0x24, 0xe8, 0x12, 0xe3, 0x81, 0x41};
constexpr Aaguid kYubikey5cNfc58{0xf4, 0xce, 0x5f, 0xc0, 0x57, 0xd3, 0x46, 0xf5,
                                 0xa7, 0x36, 0xef, 0xb7, 0xd5, 0xbc, 0x63, 0xb5};
constexpr Aaguid kYubikey5cNfc57{0xa2, 0x53, 0x42, 0xc0, 0x3c, 0xdc, 0x44, 0x14,
                                 0x8e, 0x46, 0xf4, 0x80, 0x7f, 0xca, 0x51, 0x1c};
// YubiKey 5 NFC / 5C NFC from firmware 5.7.4 onwards: a separate MDS entry from
// the 5.7 model, and the one field reports put on the Daybreak allow-list.
constexpr Aaguid kYubikey5cNfc574{0xd7, 0x78, 0x1e, 0x5d, 0xe3, 0x53, 0x46, 0xaa,
                                   0xaf, 0xe2, 0x3c, 0xa4, 0x9f, 0x13, 0x33, 0x2a};

// YubiKey 5 Series (Enterprise Profile): same hardware, enterprise attestation
// entry. Kept for gate probing — its anchor set and AAGUID differ from consumer.
constexpr Aaguid kYubikey5Enterprise{0x45, 0x99, 0x06, 0x2e, 0x69, 0x26, 0x4f, 0xe7,
                                     0x95, 0x66, 0x9e, 0x8f, 0xb1, 0xae, 0xda, 0xa0};

// Securitag Assembly Group FIDO Authenticator NFC: a certified hardware model that
// OpenAI refuses at admission (row 10). Kept for the anchor-pool probe.
constexpr Aaguid kSecuritagSag{0x5d, 0xf6, 0x6f, 0x62, 0x5b, 0x47, 0x43, 0xd3,
                               0xaa, 0x1d, 0xa6, 0xe3, 0x1c, 0x8d, 0xbe, 0xb5};

constexpr Aaguid kGoogleTitanV2{0x42, 0xb4, 0xfb, 0x4a, 0x28, 0x66, 0x43, 0xb2,
                                0x9b, 0xf7, 0x6c, 0x66, 0x69, 0xc2, 0xe5, 0xd3};

// PIDs and iProduct strings are modelled from the vendors' published USB ID
// tables. They are cosmetic: no relying party sees the HID descriptor, and a
// mismatch here cannot turn a self-attested key into a certified one.
std::vector<CompatProfile> make_profiles() {
  std::vector<CompatProfile> v;

  {
    CompatProfile p;
    p.id = "stock-swpasskey";
    p.name = "swpasskey (stock)";
    p.aaguid = kStockAaguid;
    p.vid = 0x1209;  // pid.codes, development only
    p.pid = 0xF1D0;
    p.bcd_device = 0x0100;
    p.manufacturer = "swpasskey";
    p.product = "swpasskey Software Authenticator";
    p.serial = SerialStrategy::sidecar;
    // FIDO packed attestation requires C, O, OU and CN in the subject, even for
    // a key whose AAGUID is not in the MDS.
    p.att_cn = "swpasskey Software Authenticator";
    p.att_ou = "Authenticator Attestation";
    p.att_o = "swpasskey";
    p.att_c = "US";
    p.note = "Upstream identity. AAGUID is not in the FIDO MDS; RPs that require "
             "certified attestation reject it.";
    v.push_back(std::move(p));
  }
  {
    CompatProfile p;
    p.id = "yubico-security-key-c-nfc-5.8";
    p.name = "Security Key C NFC (5.8)";
    p.aaguid = kYubicoSecurityKeyCNfc58;
    p.vid = 0x1050;
    p.pid = 0x041F;
    p.bcd_device = 0x0580;
    p.manufacturer = "Yubico (www.yubico.com)";
    p.product = "Security Key by Yubico";
    p.serial = SerialStrategy::decimal8;
    p.att_cn = "Security Key by Yubico";
    p.att_ou = "Authenticator Attestation";
    p.att_o = "Yubico AB";
    p.att_c = "SE";
    p.note = "FIDO-only Security Key Series, firmware 5.8. MDS entry exists for the "
             "AAGUID; the certificate is still our own self-signed one.";
    v.push_back(std::move(p));
  }
  {
    CompatProfile p;
    p.id = "yubikey-5c-nfc-5.8";
    p.name = "YubiKey 5C NFC (5.8)";
    p.aaguid = kYubikey5cNfc58;
    p.vid = 0x1050;
    p.pid = 0x0407;
    p.bcd_device = 0x0580;
    p.manufacturer = "Yubico (www.yubico.com)";
    p.product = "YubiKey OTP+FIDO+CCID";
    p.serial = SerialStrategy::decimal8;
    p.att_cn = "YubiKey 5C NFC";
    p.att_ou = "Authenticator Attestation";
    p.att_o = "Yubico AB";
    p.att_c = "SE";
    p.note = "Multi-protocol YubiKey 5 Series, firmware 5.8. The model OpenAI is "
             "reported to accept.";
    v.push_back(std::move(p));
  }
  {
    CompatProfile p;
    p.id = "yubikey-5c-nfc-5.7";
    p.name = "YubiKey 5C NFC (5.7)";
    p.aaguid = kYubikey5cNfc57;
    p.vid = 0x1050;
    p.pid = 0x0407;
    p.bcd_device = 0x0571;
    p.manufacturer = "Yubico (www.yubico.com)";
    p.product = "YubiKey OTP+FIDO+CCID";
    p.serial = SerialStrategy::decimal8;
    p.att_cn = "YubiKey 5C NFC";
    p.att_ou = "Authenticator Attestation";
    p.att_o = "Yubico AB";
    p.att_c = "SE";
    p.note = "Same model on firmware 5.7: a second MDS AAGUID, useful to tell an "
             "allowlist from an MDS key-protection check.";
    v.push_back(std::move(p));
  }
  {
    CompatProfile p;
    p.id = "yubikey-5c-nfc-5.7.4+";
    p.name = "YubiKey 5C NFC (5.7.4+)";
    p.aaguid = kYubikey5cNfc574;
    p.vid = 0x1050;
    p.pid = 0x0407;
    p.bcd_device = 0x0574;
    p.manufacturer = "Yubico (www.yubico.com)";
    p.product = "YubiKey OTP+FIDO+CCID";
    p.serial = SerialStrategy::decimal8;
    p.att_cn = "YubiKey 5C NFC";
    p.att_ou = "Authenticator Attestation";
    p.att_o = "Yubico AB";
    p.att_c = "SE";
    p.note = "Firmware 5.7.4+ has its own MDS entry (d7781e5d). Reported by other "
             "virtual-key work as the model Daybreak files under Security key.";
    v.push_back(std::move(p));
  }
  {
    CompatProfile p;
    p.id = "yubikey-5-enterprise";
    p.name = "YubiKey 5 Series (Enterprise Profile)";
    p.aaguid = kYubikey5Enterprise;
    p.vid = 0x1050;
    p.pid = 0x0407;
    p.bcd_device = 0x0580;
    p.manufacturer = "Yubico (www.yubico.com)";
    p.product = "YubiKey OTP+FIDO+CCID";
    p.serial = SerialStrategy::decimal8;
    p.att_cn = "YubiKey 5 NFC";
    p.att_ou = "Authenticator Attestation";
    p.att_o = "Yubico AB";
    p.att_c = "SE";
    p.note = "Enterprise-profile entry (4599062e). Enterprise attestation is gated by "
             "an RP allowlist on the key itself, so this tests the gate, not the key.";
    v.push_back(std::move(p));
  }
  {
    CompatProfile p;
    p.id = "securitag-sag";
    p.name = "Securitag SAG FIDO";
    p.aaguid = kSecuritagSag;
    p.vid = 0x1050;
    p.pid = 0x0407;
    p.bcd_device = 0x0100;
    p.manufacturer = "Securitag Assembly Group";
    p.product = "SAG FIDO";
    p.serial = SerialStrategy::decimal8;
    p.att_cn = "SAG FIDO";
    p.att_ou = "Authenticator Attestation";
    p.att_o = "Securitag Assembly Group";
    p.att_c = "TW";
    p.note = "Refused at admission (row 10). Used for the anchor-pool probe: its own "
             "MDS entry anchors on a single end-entity certificate.";
    v.push_back(std::move(p));
  }
  {
    CompatProfile p;
    p.id = "google-titan-v2";
    p.name = "Google Titan v2";
    p.aaguid = kGoogleTitanV2;
    p.vid = 0x18D1;
    p.pid = 0x9470;
    p.bcd_device = 0x0100;
    p.manufacturer = "Google";
    p.product = "Titan Security Key";
    p.serial = SerialStrategy::decimal8;
    p.att_cn = "Titan Security Key v2";
    p.att_ou = "Authenticator Attestation";
    p.att_o = "Google LLC";
    p.att_c = "US";
    p.note = "K52T (USB-C/NFC). Different vendor, different MDS batch, same "
             "self-signed attestation.";
    v.push_back(std::move(p));
  }
  for (auto& p : v) {
    p.aaguid_str = aaguid_to_string(p.aaguid);
  }
  return v;
}

const char* kHex = "0123456789abcdef";

int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

std::string aaguid_to_string(const Aaguid& a) {
  std::string out;
  out.reserve(36);
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      out.push_back('-');
    }
    out.push_back(kHex[a[i] >> 4]);
    out.push_back(kHex[a[i] & 0x0F]);
  }
  return out;
}

std::optional<Aaguid> aaguid_from_string(std::string_view text) {
  std::string digits;
  digits.reserve(32);
  for (char c : text) {
    if (c == '-' || c == '{' || c == '}' || c == ' ') {
      continue;
    }
    if (hex_nibble(c) < 0) {
      return std::nullopt;
    }
    digits.push_back(c);
  }
  if (digits.size() != 32) {
    return std::nullopt;
  }
  Aaguid out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    const int hi = hex_nibble(digits[i * 2]);
    const int lo = hex_nibble(digits[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return std::nullopt;
    }
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return out;
}

const std::vector<CompatProfile>& all_profiles() {
  static const std::vector<CompatProfile> profiles = make_profiles();
  return profiles;
}

const CompatProfile* find_profile(std::string_view id) {
  const auto& all = all_profiles();
  auto it = std::find_if(all.begin(), all.end(),
                         [id](const CompatProfile& p) { return p.id == id; });
  return it == all.end() ? nullptr : &*it;
}

const CompatProfile& default_profile() { return all_profiles().front(); }

std::string serial_for(const CompatProfile& profile, std::string_view seed_hex) {
  std::string seed(seed_hex);
  if (seed.size() < 8) {
    seed.append(8 - seed.size(), '0');
  }
  if (profile.serial == SerialStrategy::sidecar) {
    return seed.substr(0, 16);
  }
  // decimal8: fold the seed into an eight-digit serial. Keeps a per-install
  // value that survives restarts and profile switches (the seed never changes).
  std::uint32_t v = 0;
  for (std::size_t i = 0; i < seed.size() && i < 16; ++i) {
    const int n = hex_nibble(seed[i]);
    v = v * 16u + static_cast<std::uint32_t>(n < 0 ? 0 : n);
  }
  v %= 100000000u;
  std::string digits = std::to_string(v);
  if (digits.size() < 8) {
    digits.insert(digits.begin(), 8 - digits.size(), '0');
  }
  return digits;
}

}  // namespace swpk::compat
