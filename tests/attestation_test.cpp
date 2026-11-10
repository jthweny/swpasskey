// Packed attestation with x5c: the certificate in the response must name the
// selected profile, carry its AAGUID, be self-signed, and actually be the key
// that signed authData || clientDataHash. Also covers the vendor-chain path.
#include "ctap_test_util.hpp"

#include "swpasskey/ctap/attestation.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

using namespace swpk;
using namespace swpk::test;

namespace {

constexpr const char* kAaguidOid = "1.3.6.1.4.1.45724.1.1.4";

struct X509Deleter {
  void operator()(X509* x) const { X509_free(x); }
};
using Cert = std::unique_ptr<X509, X509Deleter>;

struct PkeyDeleter {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

Cert parse_cert(const std::vector<std::uint8_t>& der) {
  const unsigned char* p = der.data();
  return Cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
}

bool verify_with_pubkey(EVP_PKEY* pub, std::span<const std::uint8_t> msg,
                        std::span<const std::uint8_t> sig) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  const bool ok = ctx != nullptr &&
                  EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pub) == 1 &&
                  EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size()) == 1;
  EVP_MD_CTX_free(ctx);
  return ok;
}

std::string name_of(X509_NAME* n) {
  if (n == nullptr) return {};
  BIO* bio = BIO_new(BIO_s_mem());
  std::string out;
  if (X509_NAME_print_ex(bio, n, 0, XN_FLAG_RFC2253) >= 0) {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (len > 0 && data != nullptr) out.assign(data, static_cast<std::size_t>(len));
  }
  BIO_free(bio);
  return out;
}

// extnValue holds the DER of an OCTET STRING wrapping the 16 AAGUID bytes.
std::vector<std::uint8_t> aaguid_ext_of(X509* cert) {
  ASN1_OBJECT* obj = OBJ_txt2obj(kAaguidOid, 1);
  const int idx = X509_get_ext_by_OBJ(cert, obj, -1);
  ASN1_OBJECT_free(obj);
  if (idx < 0) return {};
  const ASN1_OCTET_STRING* extn = X509_EXTENSION_get_data(X509_get_ext(cert, idx));
  const unsigned char* p = ASN1_STRING_get0_data(extn);
  ASN1_OCTET_STRING* inner = d2i_ASN1_OCTET_STRING(nullptr, &p, ASN1_STRING_length(extn));
  if (inner == nullptr) return {};
  std::vector<std::uint8_t> out(ASN1_STRING_get0_data(inner),
                                ASN1_STRING_get0_data(inner) + ASN1_STRING_length(inner));
  ASN1_OCTET_STRING_free(inner);
  return out;
}

// x5c is a CBOR array of byte strings.
std::vector<std::vector<std::uint8_t>> parse_x5c(const std::vector<std::uint8_t>& cbor) {
  std::vector<std::vector<std::uint8_t>> out;
  cbor::Reader r(cbor);
  auto n = r.array();
  if (!n) return out;
  for (std::size_t i = 0; i < *n; ++i) {
    auto b = r.bstr();
    if (!b) return {};
    out.push_back(*b);
  }
  return out;
}

struct Registration {
  std::vector<std::uint8_t> auth_data;
  std::vector<std::uint8_t> client_data_hash;
  std::vector<std::vector<std::uint8_t>> x5c;
  std::vector<std::uint8_t> sig;
};

Registration register_and_split(Rig& rig, MakeCredOpts o = {}) {
  for (std::size_t i = 0; i < 32; ++i) o.client_data_hash[i] = static_cast<std::uint8_t>(i + 1);
  auto r = rig.call(make_cred_request(o));
  REQUIRE(r.has_value());
  auto m = split_int_map(*r);
  auto st = split_text_map(m[3]);
  REQUIRE(st.count("x5c") == 1);
  Registration out;
  out.auth_data = as_bstr(m[2]);
  out.client_data_hash.assign(o.client_data_hash.begin(), o.client_data_hash.end());
  out.x5c = parse_x5c(st["x5c"]);
  out.sig = as_bstr(st["sig"]);
  return out;
}

// ---- throwaway PKI for the vendor-chain path --------------------------------
Pkey gen_p256() {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY* key = nullptr;
  if (ctx == nullptr || EVP_PKEY_keygen_init(ctx) != 1 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) != 1 ||
      EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE) != 1 ||
      EVP_PKEY_keygen(ctx, &key) != 1) {
    EVP_PKEY_CTX_free(ctx);
    return Pkey(nullptr);
  }
  EVP_PKEY_CTX_free(ctx);
  return Pkey(key);
}

Cert make_cert(EVP_PKEY* subject_key, const char* cn, EVP_PKEY* issuer_key, X509* issuer_cert) {
  X509* c = X509_new();
  if (c == nullptr) return Cert(nullptr);
  X509_set_version(c, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(c), 1);
  X509_gmtime_adj(X509_getm_notBefore(c), 0);
  X509_gmtime_adj(X509_getm_notAfter(c), 3600);
  X509_NAME* subj = X509_get_subject_name(c);
  X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
  X509_set_pubkey(c, subject_key);
  if (issuer_cert != nullptr) {
    X509_set_issuer_name(c, X509_get_subject_name(issuer_cert));
  } else {
    X509_set_issuer_name(c, subj);
  }
  X509_sign(c, issuer_key, EVP_sha256());
  return Cert(c);
}

void write_cert_pem(X509* cert, const std::filesystem::path& path) {
  FILE* f = std::fopen(path.c_str(), "w");
  REQUIRE(f != nullptr);
  PEM_write_X509(f, cert);
  std::fclose(f);
}

void write_key_pem(EVP_PKEY* key, const std::filesystem::path& path) {
  FILE* f = std::fopen(path.c_str(), "w");
  REQUIRE(f != nullptr);
  PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
  std::fclose(f);
}

}  // namespace

TEST_CASE("packed attestation: x5c certificate is profile-aware and signs authData", "[attest]") {
  Rig rig;
  auto reg = register_and_split(rig);
  auto ad = parse_auth_data(reg.auth_data);
  REQUIRE(ad.aaguid == kAaguid);
  REQUIRE(reg.x5c.size() == 1);

  auto leaf = parse_cert(reg.x5c[0]);
  REQUIRE(leaf != nullptr);
  const std::string subject = name_of(X509_get_subject_name(leaf.get()));
  const std::string issuer = name_of(X509_get_issuer_name(leaf.get()));
  REQUIRE(subject == issuer);  // self-signed, and the record says so
  REQUIRE(subject.find("swpasskey Software Authenticator") != std::string::npos);

  // AAGUID extension inside the certificate matches authData.
  REQUIRE(aaguid_ext_of(leaf.get()) == std::vector<std::uint8_t>(kAaguid.begin(), kAaguid.end()));

  // The certificate is the key that signed authData || clientDataHash.
  std::vector<std::uint8_t> msg = reg.auth_data;
  msg.insert(msg.end(), reg.client_data_hash.begin(), reg.client_data_hash.end());
  REQUIRE(verify_with_pubkey(X509_get0_pubkey(leaf.get()), msg, reg.sig));

  // And it verifies against itself: a real self-signed leaf, not a stub.
  const unsigned char* der = reg.x5c[0].data();
  X509* reparsed = d2i_X509(nullptr, &der, static_cast<long>(reg.x5c[0].size()));
  REQUIRE(reparsed != nullptr);
  REQUIRE(X509_verify(reparsed, X509_get0_pubkey(reparsed)) == 1);
  X509_free(reparsed);
}

TEST_CASE("packed attestation: stored credentials keep signing after a profile switch",
          "[attest]") {
  Rig rig;
  auto before = register_and_split(rig);
  const auto ad_before = parse_auth_data(before.auth_data);
  REQUIRE(ad_before.aaguid == kAaguid);

  const auto* yubi = compat::find_profile("yubikey-5c-nfc-5.8");
  REQUIRE(yubi != nullptr);
  rig.auth->set_profile(*yubi);
  REQUIRE(rig.auth->get_info().aaguid == yubi->aaguid);

  MakeCredOpts o;
  o.user_id = bytes({0x42, 0x43});
  o.user_name = "second";
  auto after = register_and_split(rig, o);
  const auto ad_after = parse_auth_data(after.auth_data);
  REQUIRE(ad_after.aaguid == yubi->aaguid);

  auto leaf = parse_cert(after.x5c[0]);
  REQUIRE(leaf != nullptr);
  const std::string subject = name_of(X509_get_subject_name(leaf.get()));
  const std::string issuer = name_of(X509_get_issuer_name(leaf.get()));
  REQUIRE(subject.find("YubiKey 5C NFC") != std::string::npos);
  REQUIRE(subject.find("Yubico AB") != std::string::npos);
  REQUIRE(subject.find("Authenticator Attestation") != std::string::npos);
  REQUIRE(issuer.find("Yubico AB") != std::string::npos);
  REQUIRE(aaguid_ext_of(leaf.get()) == std::vector<std::uint8_t>(yubi->aaguid.begin(),
                                                                 yubi->aaguid.end()));
  // The first credential is untouched by the switch.
  REQUIRE(rig.store->find_by_id(ad_before.cred_id).has_value());
  REQUIRE(rig.store->size() == 2);
}

TEST_CASE("packed attestation: a supplied vendor chain is shipped verbatim", "[attest]") {
  const auto dir = std::filesystem::temp_directory_path() /
                   ("swpk-chain-" + std::to_string(static_cast<long>(::getpid())));
  std::filesystem::create_directories(dir);

  auto root_key = gen_p256();
  auto leaf_key = gen_p256();
  REQUIRE(root_key != nullptr);
  REQUIRE(leaf_key != nullptr);
  auto root = make_cert(root_key.get(), "Test Attestation Root", root_key.get(), nullptr);
  auto leaf = make_cert(leaf_key.get(), "Test Attestation Leaf", root_key.get(), root.get());
  REQUIRE(root != nullptr);
  REQUIRE(leaf != nullptr);
  write_cert_pem(leaf.get(), dir / "leaf.pem");
  write_cert_pem(root.get(), dir / "chain.pem");
  write_key_pem(leaf_key.get(), dir / "leaf.key");

  Rig rig(false, false, ctap::AttestationMode::packed_x5c,
          [&dir](ctap::AuthenticatorConfig& cfg) { cfg.attestation_chain_dir = dir; });
  auto reg = register_and_split(rig);
  REQUIRE(reg.x5c.size() == 2);  // leaf + one intermediate
  auto shipped = parse_cert(reg.x5c[0]);
  REQUIRE(shipped != nullptr);
  REQUIRE(name_of(X509_get_subject_name(shipped.get())) == "CN=Test Attestation Leaf");
  REQUIRE(name_of(X509_get_issuer_name(shipped.get())) == "CN=Test Attestation Root");

  // Signed by the supplied leaf key, not by the generated batch key.
  std::vector<std::uint8_t> msg = reg.auth_data;
  msg.insert(msg.end(), reg.client_data_hash.begin(), reg.client_data_hash.end());
  REQUIRE(verify_with_pubkey(X509_get0_pubkey(shipped.get()), msg, reg.sig));

  std::filesystem::remove_all(dir);
}
