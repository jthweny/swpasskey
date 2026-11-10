// Registration diagnostics: every makeCredential must leave one record with the
// identity, attestation facts and authData flags a classifier would see.
#include "ctap_test_util.hpp"

#include "swpasskey/diag/registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

using namespace swpk;
using namespace swpk::test;

TEST_CASE("diagnostics: a registration is recorded with the emitted identity", "[diag]") {
  diag::Registry reg;
  Rig rig(false, false, ctap::AttestationMode::packed_x5c,
          [&reg](ctap::AuthenticatorConfig& cfg) { cfg.diag = &reg; });

  MakeCredOpts o;
  for (std::size_t i = 0; i < 32; ++i) o.client_data_hash[i] = static_cast<std::uint8_t>(i);
  auto r = rig.call(make_cred_request(o));
  REQUIRE(r.has_value());
  auto ad = parse_auth_data(as_bstr(split_int_map(*r)[2]));

  auto entries = reg.entries();
  REQUIRE(entries.size() == 1);
  const auto& e = entries.front();
  REQUIRE(e.profile_id == "stock-swpasskey");
  REQUIRE(e.aaguid == compat::aaguid_to_string(kAaguid));
  REQUIRE(e.rp_id == "example.com");
  REQUIRE(e.cred_id_hex.size() == 64);
  REQUIRE(e.attestation_format == "packed");
  REQUIRE(e.x5c_present);
  REQUIRE(e.x5c_len == 1);
  REQUIRE(e.attestation_source == "self-signed");
  REQUIRE(e.x5c_subject == e.x5c_issuer);  // self-signed
  REQUIRE(e.x5c_leaf_sha256.size() == 64);
  REQUIRE(e.flag_up);
  REQUIRE(e.flag_at);
  REQUIRE_FALSE(e.flag_uv);
  REQUIRE_FALSE(e.flag_be);  // device-bound: never backup eligible
  REQUIRE_FALSE(e.flag_bs);
  REQUIRE(e.sign_count == 1);
  REQUIRE(e.key_backend == "software");
  REQUIRE(e.timestamp.size() == 24);  // 2026-01-31T09:12:03.481Z
  REQUIRE(e.timestamp.back() == 'Z');
  // The credential id in the record is the one the host received.
  std::string hex;
  for (auto b : ad.cred_id) {
    char buf[3];
    std::snprintf(buf, sizeof buf, "%02x", static_cast<unsigned>(b));
    hex += buf;
  }
  REQUIRE(e.cred_id_hex == hex);
}

TEST_CASE("diagnostics: JSON export carries the fields and can be re-exported", "[diag]") {
  const auto dir = std::filesystem::temp_directory_path() /
                   ("swpk-diag-" + std::to_string(static_cast<long>(::getpid())));
  std::filesystem::remove_all(dir);
  const auto path = dir / "diagnostics.json";

  diag::Registry reg(path);
  Rig rig(false, false, ctap::AttestationMode::packed_x5c,
          [&reg](ctap::AuthenticatorConfig& cfg) { cfg.diag = &reg; });
  REQUIRE(rig.call(make_cred_request({})).has_value());

  // The registry rewrites the export on every record.
  REQUIRE(std::filesystem::exists(path));

  auto json = reg.to_json();
  REQUIRE(json.has_value());
  for (const char* key : {"\"count\":1", "\"records\":[{", "\"aaguid\":", "\"flags\":{",
                          "\"x5c_present\":true", "\"be\":false", "\"rp_id\":\"example.com\""}) {
    INFO(key);
    REQUIRE(json->find(key) != std::string::npos);
  }
  // No private material in the export.
  REQUIRE(json->find("\"priv\"") == std::string::npos);
  REQUIRE(json->find("scalar") == std::string::npos);

  std::ifstream in(path);
  std::string on_disk((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  REQUIRE(on_disk.find("\"records\"") != std::string::npos);
  REQUIRE(on_disk.find("stock-swpasskey") != std::string::npos);

  const auto other = dir / "copy.json";
  REQUIRE(reg.export_to(other).has_value());
  REQUIRE(std::filesystem::file_size(other) == std::filesystem::file_size(path));

  reg.clear();
  REQUIRE(reg.entries().empty());
  std::filesystem::remove_all(dir);
}

TEST_CASE("diagnostics: a second registration appends, a switch relabels", "[diag]") {
  diag::Registry reg;
  Rig rig(false, false, ctap::AttestationMode::packed_x5c,
          [&reg](ctap::AuthenticatorConfig& cfg) { cfg.diag = &reg; });
  REQUIRE(rig.call(make_cred_request({})).has_value());
  rig.auth->set_profile(*compat::find_profile("google-titan-v2"));
  MakeCredOpts o;
  o.user_id = bytes({9, 9});
  o.user_name = "other";
  REQUIRE(rig.call(make_cred_request(o)).has_value());

  auto entries = reg.entries();
  REQUIRE(entries.size() == 2);
  REQUIRE(entries[0].profile_id == "stock-swpasskey");
  REQUIRE(entries[1].profile_id == "google-titan-v2");
  REQUIRE(entries[1].aaguid == "42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3");
  REQUIRE(entries[1].x5c_subject.find("Google LLC") != std::string::npos);
}
