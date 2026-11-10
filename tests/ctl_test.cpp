#include "swpasskey/ctl/json.hpp"
#include "swpasskey/diag/registry.hpp"
#include "swpasskey/ctl/server.hpp"
#include "ctap_test_util.hpp"
#include "swpasskey/log/log.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <unistd.h>

using namespace swpk;
using namespace swpk::test;

TEST_CASE("json writer and flat parser", "[ctl]") {
  ctl::JsonWriter w;
  w.begin_object().boolean("ok", true).str("s", "a\"b\\c\n").num("n", 42).object("o").num("x", 1).end_object()
      .begin_array("arr").begin_object().str("k", "v").end_object().begin_object().str("k", "w").end_object().end_array()
      .end_object();
  const std::string out = w.finish();
  REQUIRE(out == R"({"ok":true,"s":"a\"b\\c\n","n":42,"o":{"x":1},"arr":[{"k":"v"},{"k":"w"}]})");
  auto r = ctl::parse_flat_json(R"({"op":"delete","cred_id":"abcd","n":7,"b":true,"e":"xAy"})");
  REQUIRE(r.ok);
  REQUIRE(r.get("op") == "delete");
  REQUIRE(r.get("cred_id") == "abcd");
  REQUIRE(r.get("n") == "7");
  REQUIRE(r.get("b") == "true");
  REQUIRE(r.get("e") == "xAy");
  REQUIRE(r.get("missing", "d") == "d");
  REQUIRE_FALSE(ctl::parse_flat_json("nope").ok);
  REQUIRE_FALSE(ctl::parse_flat_json(R"({"a":{"b":1}})").ok);
  REQUIRE(ctl::parse_flat_json("{}").ok);
}

TEST_CASE("ctl requests: stats, list, delete, set-pin, reset, log-level", "[ctl]") {
  Rig rig(true);
  auto id = rig.register_cred();
  ctl::ServerDeps deps;
  deps.auth = rig.auth.get();
  deps.store = rig.store.get();
  deps.key_backend = "tpm2";
  deps.probe_detail = "probe=ok";
  bool quit = false;
  deps.quit = [&] { quit = true; };

  auto stats = ctl::handle_request(R"({"op":"stats"})", deps);
  REQUIRE(stats.find("\"ok\":true") != std::string::npos);
  REQUIRE(stats.find("\"key_backend\":\"tpm2\"") != std::string::npos);
  REQUIRE(stats.find("\"tpm2\":1") != std::string::npos);
  REQUIRE(stats.find("\"make_cred_ok\":1") != std::string::npos);
  REQUIRE(stats.find("\"pin_set\":false") != std::string::npos);

  auto list = ctl::handle_request(R"({"op":"list"})", deps);
  REQUIRE(list.find("\"rp\":\"example.com\"") != std::string::npos);
  REQUIRE(list.find("\"backend\":\"tpm2\"") != std::string::npos);
  REQUIRE(list.find("\"cred_id\":\"" + hex(id) + "\"") != std::string::npos);

  REQUIRE(ctl::handle_request(R"({"op":"delete","cred_id":"zz"})", deps).find("\"ok\":false") != std::string::npos);
  REQUIRE(ctl::handle_request("{\"op\":\"delete\",\"cred_id\":\"" + std::string(64, '0') + "\"}", deps).find("no such credential") != std::string::npos);
  REQUIRE(ctl::handle_request("{\"op\":\"delete\",\"cred_id\":\"" + hex(id) + "\"}", deps).find("\"ok\":true") != std::string::npos);
  REQUIRE(rig.store->size() == 0);
  REQUIRE(static_cast<FakeHwBackend*>(rig.hw.get())->destroys == 1);

  REQUIRE(ctl::handle_request(R"({"op":"set-pin","pin":"123"})", deps).find("pin policy") != std::string::npos);
  rig.presence.next = ui::Decision::Deny;
  REQUIRE(ctl::handle_request(R"({"op":"set-pin","pin":"1234"})", deps).find("denied") != std::string::npos);
  rig.presence.next = ui::Decision::Allow;
  REQUIRE(ctl::handle_request(R"({"op":"set-pin","pin":"1234"})", deps).find("\"ok\":true") != std::string::npos);
  REQUIRE(rig.presence.seen.back().kind == ui::PresenceRequest::Kind::SetPin);
  REQUIRE(rig.auth->get_info().options.client_pin == true);
  REQUIRE(ctl::handle_request(R"({"op":"stats"})", deps).find("\"pin_set\":true") != std::string::npos);

  rig.register_cred();
  REQUIRE(ctl::handle_request(R"({"op":"reset"})", deps).find("\"ok\":true") != std::string::npos);
  REQUIRE(rig.store->size() == 0);
  REQUIRE(rig.auth->get_info().options.client_pin == false);

  REQUIRE(ctl::handle_request(R"({"op":"log-level","level":"debug"})", deps).find("\"ok\":true") != std::string::npos);
  REQUIRE(swpk::log::level() == swpk::log::Level::Debug);
  REQUIRE(ctl::handle_request(R"({"op":"log-level","level":"info"})", deps).find("\"ok\":true") != std::string::npos);
  REQUIRE(ctl::handle_request(R"({"op":"log-level","level":"loud"})", deps).find("\"ok\":false") != std::string::npos);
  REQUIRE(ctl::handle_request(R"({"op":"quit"})", deps).find("\"ok\":true") != std::string::npos);
  REQUIRE(quit);
  REQUIRE(ctl::handle_request(R"({"op":"bogus"})", deps).find("unknown op") != std::string::npos);
  REQUIRE(ctl::handle_request("garbage", deps).find("bad request") != std::string::npos);
}

TEST_CASE("ctl requests: profiles, set-profile, attestation, diagnostics", "[ctl]") {
  diag::Registry reg;
  Rig rig(false, false, ctap::AttestationMode::packed_x5c,
          [&reg](ctap::AuthenticatorConfig& cfg) { cfg.diag = &reg; });
  REQUIRE(rig.register_cred().size() == 32);

  auto identity = std::make_shared<compat::Identity>();
  ctl::ServerDeps deps;
  deps.auth = rig.auth.get();
  deps.store = rig.store.get();
  deps.key_backend = "software";
  deps.identity = identity.get();
  deps.diag = &reg;
  deps.attestation_summary = [&rig] { return rig.auth->attestation_summary(); };
  std::string applied;
  deps.apply_profile = [&](const std::string& id) -> std::string {
    const auto* p = compat::find_profile(id);
    if (p == nullptr) return "unknown profile: " + id;
    applied = id;
    identity->set(std::make_shared<const compat::CompatProfile>(*p));
    rig.auth->set_profile(*p);
    return {};
  };

  auto list = ctl::handle_request(R"({"op":"profiles"})", deps);
  REQUIRE(list.find("\"ok\":true") != std::string::npos);
  REQUIRE(list.find("\"current\":\"stock-swpasskey\"") != std::string::npos);
  REQUIRE(list.find("\"id\":\"yubikey-5c-nfc-5.8\"") != std::string::npos);
  REQUIRE(list.find("\"aaguid\":\"f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5\"") != std::string::npos);

  REQUIRE(ctl::handle_request(R"({"op":"set-profile","profile":"nope"})", deps).find("\"ok\":false") !=
          std::string::npos);
  REQUIRE(applied.empty());
  auto switched = ctl::handle_request(R"({"op":"set-profile","profile":"google-titan-v2"})", deps);
  REQUIRE(switched.find("\"ok\":true") != std::string::npos);
  REQUIRE(applied == "google-titan-v2");
  REQUIRE(identity->profile()->id == "google-titan-v2");
  REQUIRE(rig.auth->get_info().aaguid == compat::find_profile("google-titan-v2")->aaguid);
  REQUIRE(ctl::handle_request(R"({"op":"profiles"})", deps).find("\"current\":\"google-titan-v2\"") !=
          std::string::npos);

  auto att = ctl::handle_request(R"({"op":"attestation"})", deps);
  REQUIRE(att.find("\"ok\":true") != std::string::npos);
  REQUIRE(att.find("source=") != std::string::npos);

  auto diag = ctl::handle_request(R"({"op":"diagnostics"})", deps);
  REQUIRE(diag.find("\"ok\":true") != std::string::npos);
  REQUIRE(diag.find("\"records\":[") != std::string::npos);
  REQUIRE(diag.find("stock-swpasskey") != std::string::npos);

  const auto out = std::filesystem::temp_directory_path() /
                   ("swpk-diag-ctl-" + std::to_string(::getpid()) + ".json");
  auto written = ctl::handle_request("{\"op\":\"diagnostics\",\"out\":\"" + out.string() + "\"}", deps);
  REQUIRE(written.find("\"ok\":true") != std::string::npos);
  REQUIRE(std::filesystem::exists(out));
  std::filesystem::remove(out);
}

TEST_CASE("ctl unix socket round trip", "[ctl]") {
  Rig rig;
  ctl::ServerDeps deps;
  deps.auth = rig.auth.get();
  deps.store = rig.store.get();
  deps.key_backend = "software";
  const auto path = std::filesystem::temp_directory_path() / ("swpk-ctl-" + std::to_string(::getpid()) + ".sock");
  ctl::UnixServer server(path, deps);
  REQUIRE(server.start().has_value());
  auto r = ctl::request(path, R"({"op":"stats"})");
  REQUIRE(r.has_value());
  REQUIRE(r->find("\"key_backend\":\"software\"") != std::string::npos);
  auto l = ctl::request(path, R"({"op":"list"})");
  REQUIRE(l.has_value());
  REQUIRE(l->find("\"creds\":[]") != std::string::npos);
  server.stop();
  REQUIRE_FALSE(std::filesystem::exists(path));
  REQUIRE_FALSE(ctl::request(path, R"({"op":"stats"})").has_value());
}
