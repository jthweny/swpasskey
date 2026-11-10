// PEM helpers for the optional vendor attestation chain. Kept separate from
// self_signed_cert.cpp so the common path links no PEM reader.
#include "swpasskey/crypto/provider.hpp"

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <memory>
#include <string>

namespace swpk::crypto {
namespace {

struct BioDel {
  void operator()(BIO* b) const { BIO_free(b); }
};
using Bio = std::unique_ptr<BIO, BioDel>;

struct X509Del {
  void operator()(X509* x) const { X509_free(x); }
};
using CertPtr = std::unique_ptr<X509, X509Del>;

struct PkeyDel {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;

struct MdCtxDel {
  void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDel>;

}  // namespace

Result<std::vector<std::vector<std::uint8_t>>> load_pem_certs(
    const std::filesystem::path& pem) {
  Bio bio(BIO_new_file(pem.c_str(), "r"));
  if (!bio) {
    return std::unexpected(Status::Other);
  }
  std::vector<std::vector<std::uint8_t>> out;
  for (;;) {
    CertPtr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert) {
      break;
    }
    unsigned char* der = nullptr;
    const int len = i2d_X509(cert.get(), &der);
    if (len <= 0 || der == nullptr) {
      OPENSSL_free(der);
      return std::unexpected(Status::Other);
    }
    out.emplace_back(der, der + len);
    OPENSSL_free(der);
  }
  ERR_clear_error();  // PEM_read_bio_X509 signals end-of-file with an error
  if (out.empty()) {
    return std::unexpected(Status::Other);
  }
  return out;
}

Result<std::vector<std::uint8_t>> sign_pem_ecdsa_sha256(
    const std::filesystem::path& key_pem, std::span<const std::uint8_t> msg) {
  Bio bio(BIO_new_file(key_pem.c_str(), "r"));
  if (!bio) {
    return std::unexpected(Status::Other);
  }
  Pkey key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!key) {
    return std::unexpected(Status::Other);
  }
  // Only P-256 is a valid attestation key for the packed format with ES256.
  if (EVP_PKEY_base_id(key.get()) != EVP_PKEY_EC) {
    return std::unexpected(Status::InvalidParameter);
  }
  char curve[64] = {};
  std::size_t curve_len = 0;
  if (EVP_PKEY_get_utf8_string_param(key.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve, sizeof curve,
                                     &curve_len) != 1 ||
      std::string(curve, curve_len) != "prime256v1") {
    return std::unexpected(Status::InvalidParameter);
  }
  MdCtx ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
    return std::unexpected(Status::Other);
  }
  std::size_t sig_len = 0;
  if (EVP_DigestSign(ctx.get(), nullptr, &sig_len, msg.data(), msg.size()) != 1) {
    return std::unexpected(Status::Other);
  }
  std::vector<std::uint8_t> sig(sig_len);
  if (EVP_DigestSign(ctx.get(), sig.data(), &sig_len, msg.data(), msg.size()) != 1) {
    return std::unexpected(Status::Other);
  }
  sig.resize(sig_len);
  return sig;
}

}  // namespace swpk::crypto
