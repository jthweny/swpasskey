#include "swpasskey/compat/profile.hpp"
#include "swpasskey/compat/store.hpp"
#include "swpasskey/constants.hpp"
#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/ctl/server.hpp"
#include "swpasskey/diag/registry.hpp"
#include "swpasskey/daemon/loop.hpp"
#include "swpasskey/daemon/paths.hpp"
#include "swpasskey/hid/transport.hpp"
#include "swpasskey/log/log.hpp"
#include "swpasskey/store/credential.hpp"
#include "swpasskey/store/file_store.hpp"
#include "swpasskey/store/keychain.hpp"
#include "swpasskey/ui/keys_model.hpp"
#include "swpasskey/ui/menubar.hpp"
#include "swpasskey/ui/presence.hpp"

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

namespace {

constexpr std::string_view kUsage =
    "swpasskeyd — software USB-HID FIDO2 authenticator\n"
    "\n"
    "Usage: swpasskeyd [options]\n"
    "  --help                         Show this help\n"
    "  --version                      Print version and exit\n"
    "  --key-backend=auto|se|tpm|software\n"
    "  --store PATH                   Credential store path\n"
    "  --testing                      Enable test-only presence auto-allow\n"
    "                                 (refused in RelWithDebInfo/Release)\n"
    "  --dek-file                     Keep the store DEK in credentials.bin.dek\n"
    "                                 (0600) instead of the OS keychain\n"
    "  --ctl-socket PATH              Control socket for swpasskeyctl\n"
    "  --profile=ID                   Compatibility profile to present (default:\n"
    "                                 the persisted selection, else stock)\n"
    "\n"
    "Env: SWPASSKEY_LOG=error|warn|info|debug, SWPASSKEY_TESTING=1,\n"
    "     SWPASSKEY_PRESENCE=auto|stdin|notify|alert (default auto: desktop prompt,\n"
    "                        else the tty prompt; 'stdin' forces the tty prompt),\n"
    "     SWPASSKEY_TPM_UNSAFE_NOTPMRM=1, SWPASSKEY_TPM_TCTI=<tcti> (default device:/dev/tpmrm0),\n"
    "     SWPASSKEY_HID_SOCKET=PATH (dev: CTAPHID over a Unix socket, no HID device),\n"
    "     SWPASSKEY_ATTEST_CHAIN=DIR (use a real attestation chain: leaf.pem,\n"
    "                        leaf.key, optional chain.pem)\n"
    "\n"
    "This is a software authenticator. Hardware engines (TPM / Secure Enclave)\n"
    "protect private scalars from extraction, not from same-uid use. The\n"
    "Approve prompt is daemon UX, not on-chip user presence.\n";

#ifndef SWPASSKEY_VERSION
#define SWPASSKEY_VERSION "0.1.0-dev"
#endif

void print_version() { std::printf("swpasskeyd %s\n", SWPASSKEY_VERSION); }

swpk::daemon::Loop* g_loop = nullptr;

void on_signal(int) {
  if (g_loop != nullptr) {
    g_loop->request_stop();  // signal-safe; no locks
  }
}

struct Options {
  std::string key_backend{"auto"};
  std::string profile;  // empty = the persisted selection
  std::filesystem::path store;
  std::string presence{"auto"};
  bool testing{false};
  bool dek_file{false};
  std::filesystem::path ctl_socket;
};

}  // namespace

int main(int argc, char** argv) {
  swpk::daemon::redirect_detached_stderr();
  swpk::log::set_level_from_env();
  Options opt;
  if (const char* t = std::getenv("SWPASSKEY_TESTING"); t != nullptr && std::strcmp(t, "1") == 0) {
    opt.testing = true;
  }
  if (const char* p = std::getenv("SWPASSKEY_PRESENCE"); p != nullptr && *p != 0) {
    opt.presence = p;
  }

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg{argv[i]};
    if (arg == "--help" || arg == "-h") {
      std::fputs(kUsage.data(), stdout);
      return 0;
    }
    if (arg == "--version" || arg == "-V") {
      print_version();
      return 0;
    }
    if (arg.starts_with("--profile=")) {
      opt.profile = std::string(arg.substr(std::strlen("--profile=")));
      continue;
    }
    if (arg.starts_with("--key-backend=")) {
      opt.key_backend = std::string(arg.substr(std::strlen("--key-backend=")));
      continue;
    }
    if (arg == "--store") {
      if (i + 1 >= argc) {
        std::fputs("swpasskeyd: --store requires a path\n", stderr);
        return 2;
      }
      opt.store = argv[++i];
      continue;
    }
    if (arg.starts_with("--store=")) {
      opt.store = std::string(arg.substr(std::strlen("--store=")));
      continue;
    }
    if (arg == "--testing") {
      opt.testing = true;
      continue;
    }
    if (arg == "--dek-file") {
      opt.dek_file = true;
      continue;
    }
    if (arg == "--ctl-socket" && i + 1 < argc) {
      opt.ctl_socket = argv[++i];
      continue;
    }
    if (arg.starts_with("--ctl-socket=")) {
      opt.ctl_socket = std::string(arg.substr(std::strlen("--ctl-socket=")));
      continue;
    }
    std::fprintf(stderr, "swpasskeyd: unknown option '%s'\n", argv[i]);
    return 2;
  }

  if (opt.key_backend != "auto" && opt.key_backend != "se" && opt.key_backend != "tpm" &&
      opt.key_backend != "software") {
    std::fprintf(stderr, "swpasskeyd: --key-backend must be auto|se|tpm|software\n");
    return 2;
  }
  if (opt.store.empty()) {
    opt.store = swpk::daemon::default_store_path();
  }
  const auto data_dir = opt.store.parent_path();
  if (!swpk::daemon::ensure_dir(data_dir)) {
    return 1;
  }

  auto serial = swpk::daemon::load_or_create_serial(data_dir / "serial");
  if (!serial) {
    return 1;
  }

  // Compatibility profile: the CLI flag wins, then the persisted selection, then
  // the stock identity. Nothing here changes key custody.
  const auto identity_path = swpk::compat::selection_path(data_dir);
  std::string selected = opt.profile;
  if (selected.empty()) {
    selected = swpk::compat::load_selected_id(identity_path);
  }
  const swpk::compat::CompatProfile* chosen = swpk::compat::find_profile(selected);
  if (chosen == nullptr) {
    if (!opt.profile.empty()) {
      std::fprintf(stderr, "swpasskeyd: unknown profile '%s' (see swpasskeyctl profiles)\n",
                   opt.profile.c_str());
      return 2;
    }
    chosen = &swpk::compat::default_profile();
  }
  auto identity = std::make_shared<swpk::compat::Identity>();
  identity->set(std::make_shared<const swpk::compat::CompatProfile>(*chosen));
  if (auto r = swpk::compat::save_selected_id(identity_path, chosen->id); !r) {
    std::fputs("swpasskeyd: cannot persist the compatibility profile (see log)\n", stderr);
  }

  // Per-registration diagnostics, rewritten on every registration.
  swpk::diag::Registry diag_registry(data_dir / "diagnostics.json");

  swpk::crypto::Provider crypto;

  // DEK: OS keychain with a 0600-file fallback (K12). The store takes the
  // single-instance flock (credentials.bin.lock).
  auto file_kc = swpk::store::make_file_keychain(opt.store.string() + ".dek");
  std::unique_ptr<swpk::store::Keychain> keychain =
      opt.dek_file ? std::move(file_kc)
                   : swpk::store::make_fallback_keychain(swpk::store::make_os_keychain(),
                                                         std::move(file_kc));
  auto store_r = swpk::store::open_file_store(opt.store, crypto, *keychain);
  if (!store_r) {
    std::fputs("swpasskeyd: cannot open the credential store (already running, or see log)\n",
               stderr);
    return 1;
  }
  auto& store = *store_r;
  if (!store->set_serial(*serial)) {
    return 1;
  }

  // Key backend probe (after the store: the TPM primary needs the install seed).
  swpk::crypto::ProbeOptions popt;
  popt.pref = opt.key_backend;
  popt.tpm_params = [&]() -> swpk::Result<swpk::crypto::Tpm2Params> {
    auto t = store->tpm_state_or_create(crypto);
    if (!t) {
      return std::unexpected(t.error());
    }
    return swpk::crypto::Tpm2Params{t->srk_unique_seed, t->object_auth};
  };
  if (const char* t = std::getenv("SWPASSKEY_TPM_TCTI"); t != nullptr && *t != 0) {
    popt.tpm_tcti = t;
  }
  if (const char* u = std::getenv("SWPASSKEY_TPM_UNSAFE_NOTPMRM"); u != nullptr && std::strcmp(u, "1") == 0) {
    popt.tpm_allow_notpmrm = true;
  }
  std::string probe_detail;
  auto primary = swpk::crypto::probe_key_backend(popt, probe_detail);
  if (!primary) {
    std::fprintf(stderr, "swpasskeyd: key backend '%s' unavailable (%s)\n", opt.key_backend.c_str(),
                 probe_detail.c_str());
    return 1;
  }
  swpk::crypto::SoftwareKeyBackend software;
  swpk::crypto::KeyBackend& software_ref =
      primary->kind() == swpk::crypto::BackendKind::Software ? *primary : software;

  swpk::ui::PresenceConfig pcfg;
  pcfg.testing = opt.testing;
  pcfg.prefer = opt.presence;
  auto presence = swpk::ui::make_presence(pcfg);
  if (!presence) {
    std::fputs("swpasskeyd: --testing is not available in this build\n", stderr);
    return 1;
  }

  swpk::ctap::AuthenticatorConfig acfg;
  acfg.identity = identity;
  acfg.attestation_key_path = data_dir / "attestation.key";
  acfg.diag = &diag_registry;
  if (const char* chain = std::getenv("SWPASSKEY_ATTEST_CHAIN"); chain != nullptr && *chain != 0) {
    acfg.attestation_chain_dir = std::filesystem::path(chain);
  }
#if defined(SWPASSKEY_ENABLE_U2F) && SWPASSKEY_ENABLE_U2F
  acfg.u2f_enabled = true;  // HID caps become CBOR|WINK; getInfo lists U2F_V2
#endif
  swpk::ctap::Authenticator auth(acfg, crypto, *primary, software_ref, *store, *presence);

  // USB identity from the selected profile. `serial` stays derived from the
  // stored seed, so switching profiles does not renumber the installation.
  auto device_config_for = [&](const swpk::compat::CompatProfile& p) {
    swpk::hid::DeviceConfig d;
    d.vid = p.vid;
    d.pid = p.pid;
    d.version = p.bcd_device;
    d.manufacturer = p.manufacturer;
    d.product = p.product;
    d.serial = swpk::compat::serial_for(p, *serial);
    return d;
  };
  swpk::hid::DeviceConfig dcfg = device_config_for(*chosen);
  std::unique_ptr<swpk::hid::Transport> transport;
  if (const char* sock = std::getenv("SWPASSKEY_HID_SOCKET"); sock != nullptr && *sock != 0) {
    transport = swpk::hid::make_socket_transport(sock);  // development only
  } else {
    transport = swpk::hid::make_transport(dcfg);
  }
  if (!transport) {
    std::fputs("swpasskeyd: no HID transport on this platform\n", stderr);
    return 1;
  }
  std::string hid_status;
  if (!transport->open()) {
    // Do not exit: launchd restarts a failed agent, which reads as a flickering
    // app that never explains itself. Keep the menu bar and the control socket
    // alive and carry the reason into the UI instead.
    hid_status = transport->last_error();
    if (hid_status.empty()) {
      hid_status = "the virtual HID device could not be created";
    }
    std::fprintf(stderr, "swpasskeyd: no security key: %s\n", hid_status.c_str());
    swpk::log::error("hid_unavailable", {{"reason", hid_status}});
    transport = swpk::hid::make_unavailable_transport(hid_status);
    if (!transport->open()) {
      return 1;
    }
  }

  swpk::daemon::Loop loop(*transport, auth, crypto);
  g_loop = &loop;

  // Control socket (swpasskeyctl).
  if (opt.ctl_socket.empty()) {
    if (const char* e = std::getenv("SWPASSKEY_CTL_SOCKET"); e != nullptr && *e != 0) {
      opt.ctl_socket = e;
    } else {
      opt.ctl_socket = swpk::ctl::default_socket_path();
    }
  }
  swpk::ctl::ServerDeps deps;
  deps.auth = &auth;
  deps.store = store.get();
  deps.loop = &loop;
  deps.key_backend = auth.primary_backend_name();
  deps.probe_detail = probe_detail;
  deps.quit = [&loop] { loop.stop(); };
  deps.identity = identity.get();
  deps.diag = &diag_registry;
  deps.attestation_summary = [&auth] { return auth.attestation_summary(); };
  deps.apply_profile = [&](const std::string& id) -> std::string {
    const auto* p = swpk::compat::find_profile(id);
    if (p == nullptr) {
      return "unknown profile: " + id;
    }
    auto next = std::make_shared<const swpk::compat::CompatProfile>(*p);
    identity->set(next);
    auth.set_profile(*p);
    if (auto r = swpk::compat::save_selected_id(identity_path, id); !r) {
      return "cannot persist the selection";
    }
    // Re-enumerate so the host and any cached WebAuthn metadata see the new
    // USB identity; the AAGUID in getInfo changed already.
    loop.request_identity_rebind(device_config_for(*p));
    return {};
  };
  swpk::ctl::UnixServer ctl(opt.ctl_socket, std::move(deps));
  if (!ctl.start()) {
    std::fputs("swpasskeyd: cannot create the control socket (see log)\n", stderr);
    return 1;
  }
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  std::signal(SIGPIPE, SIG_IGN);

  swpk::log::info("startup", {{"version", SWPASSKEY_VERSION},
                              {"profile", chosen->id},
                              {"aaguid", chosen->aaguid_str},
                              {"attestation", auth.attestation_summary()},
                              {"key_backend", auth.primary_backend_name()},
                              {"probe", probe_detail},
                              {"transport", transport->describe()},
                              {"hid_status", hid_status.empty() ? "enumerating" : hid_status},
                              {"serial", *serial},
                              {"presence", presence->name()},
                              {"store", opt.store.string()},
                              {"keychain", keychain->name()}});
  bool ok = false;
  if (presence->needs_main_thread()) {
    // AppKit owns the main thread (NSAlert). Run the HID loop beside it and
    // let the presence event loop exit as soon as run() returns — including
    // when SIGINT/SIGTERM called loop.stop().
    swpk::ui::MenuBarDeps mdeps;
    mdeps.store = store.get();
    mdeps.delete_key = [&auth](std::span<const std::uint8_t> id) { return auth.ctl_delete(id); };
    mdeps.control_request = [path = ctl.path()](const std::string& line) {
      return swpk::ctl::request(path, line);
    };
    mdeps.quit = [&loop] { loop.stop(); };
    mdeps.version = SWPASSKEY_VERSION;
    mdeps.key_backend = swpk::ui::backend_label(primary->kind());
    mdeps.profile_label = chosen->name + " (" + chosen->aaguid_str + ")";
    mdeps.hid_status = hid_status;
    mdeps.serial = *serial;
    mdeps.store_path = opt.store.string();
    mdeps.ctl_socket = opt.ctl_socket.string();
    auto menubar = swpk::ui::make_menu_bar(std::move(mdeps));  // main thread; may be null
    std::atomic<bool> loop_done{false};
    std::thread io([&] {
      ok = loop.run();
      loop_done.store(true, std::memory_order_release);
    });
    presence->run_main_loop([&] { return loop_done.load(std::memory_order_acquire); });
    io.join();
    menubar.reset();
  } else {
    ok = loop.run();
  }
  g_loop = nullptr;
  ctl.stop();
  transport->close();
  swpk::log::info("shutdown", {{"clean", ok ? "true" : "false"}});
  return ok ? 0 : 1;
}
