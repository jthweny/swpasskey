// Compatibility-profile registry: AAGUID parsing, the four modelled vendor
// identities from the experiment brief, serial derivation and persistence.
#include "swpasskey/compat/profile.hpp"
#include "swpasskey/compat/store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

using namespace swpk;

namespace {

std::filesystem::path temp_dir() {
  auto dir = std::filesystem::temp_directory_path() /
             ("swpk-compat-" + std::to_string(static_cast<long>(::getpid())));
  std::filesystem::create_directories(dir);
  return dir;
}

}  // namespace

TEST_CASE("compat: AAGUID text round-trip", "[compat]") {
  const auto a = compat::aaguid_from_string("0f083f18-4105-43a8-ad69-24e812e38141");
  REQUIRE(a.has_value());
  REQUIRE(compat::aaguid_to_string(*a) == "0f083f18-4105-43a8-ad69-24e812e38141");
  // Tolerates braces, no dashes and upper case.
  REQUIRE(compat::aaguid_from_string("{0F083F18410543A8AD6924E812E38141}") == a);
  REQUIRE_FALSE(compat::aaguid_from_string("0f083f18").has_value());
  REQUIRE_FALSE(compat::aaguid_from_string("zzzzzzzz-4105-43a8-ad69-24e812e38141").has_value());
}

TEST_CASE("compat: registry contains the briefed profiles", "[compat]") {
  const auto& all = compat::all_profiles();
  REQUIRE(all.size() == 5);
  const struct {
    const char* id;
    const char* aaguid;
    std::uint16_t vid;
  } expected[] = {
      {"yubico-security-key-c-nfc-5.8", "0f083f18-4105-43a8-ad69-24e812e38141", 0x1050},
      {"yubikey-5c-nfc-5.8", "f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5", 0x1050},
      {"yubikey-5c-nfc-5.7", "a25342c0-3cdc-4414-8e46-f4807fca511c", 0x1050},
      {"google-titan-v2", "42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3", 0x18D1},
  };
  for (const auto& e : expected) {
    const auto* p = compat::find_profile(e.id);
    REQUIRE(p != nullptr);
    REQUIRE(p->aaguid_str == e.aaguid);
    REQUIRE(p->aaguid == *compat::aaguid_from_string(e.aaguid));
    REQUIRE(p->vid == e.vid);
    REQUIRE_FALSE(p->stock());
    REQUIRE_FALSE(p->product.empty());
    REQUIRE_FALSE(p->manufacturer.empty());
    REQUIRE_FALSE(p->att_cn.empty());
  }
  // The stock identity stays first and is the fallback.
  REQUIRE(compat::all_profiles().front().stock());
  REQUIRE(compat::default_profile().stock());
  REQUIRE(compat::find_profile("nope") == nullptr);
}

TEST_CASE("compat: serial derivation is stable and profile-shaped", "[compat]") {
  const auto& stock = compat::default_profile();
  const auto* yubi = compat::find_profile("yubikey-5c-nfc-5.8");
  REQUIRE(yubi != nullptr);
  REQUIRE(compat::serial_for(stock, "0011223344556677") == "0011223344556677");
  const auto s = compat::serial_for(*yubi, "0011223344556677");
  REQUIRE(s.size() == 8);
  REQUIRE(s.find_first_not_of("0123456789") == std::string::npos);
  REQUIRE(compat::serial_for(*yubi, "0011223344556677") == s);            // stable
  REQUIRE(compat::serial_for(*yubi, "0011223344556678") != s);            // per install
  // Same installation seed ⇒ same decimal serial across models, so the host
  // does not see a new device number on every profile switch.
  const auto* titan = compat::find_profile("google-titan-v2");
  REQUIRE(titan != nullptr);
  REQUIRE(compat::serial_for(*titan, "0011223344556677") == s);
}

TEST_CASE("compat: Identity bumps its generation exactly once per switch", "[compat]") {
  compat::Identity id;
  REQUIRE(id.profile()->stock());
  const auto g0 = id.generation();
  auto yubi = std::make_shared<const compat::CompatProfile>(*compat::find_profile("google-titan-v2"));
  const auto g1 = id.set(yubi);
  REQUIRE(g1 > g0);
  REQUIRE(id.profile()->id == "google-titan-v2");
  // Re-selecting the same profile must not force a USB re-enumeration.
  REQUIRE(id.set(yubi) == g1);
}

TEST_CASE("compat: selection persists and rejects unknown ids", "[compat]") {
  const auto dir = temp_dir();
  const auto path = compat::selection_path(dir);
  REQUIRE(compat::load_selected_id(path).empty());

  REQUIRE(compat::save_selected_id(path, "yubikey-5c-nfc-5.7").has_value());
  REQUIRE(compat::load_selected_id(path) == "yubikey-5c-nfc-5.7");

  REQUIRE(compat::save_selected_id(path, "made-up-key").error() == Status::InvalidParameter);
  REQUIRE(compat::load_selected_id(path) == "yubikey-5c-nfc-5.7");  // untouched

  // An unknown value on disk degrades to the stock profile instead of failing.
  {
    FILE* f = std::fopen(path.c_str(), "w");
    REQUIRE(f != nullptr);
    std::fputs("not-a-profile\n", f);
    std::fclose(f);
  }
  REQUIRE(compat::load_selected_id(path).empty());
  std::filesystem::remove_all(dir);
}
