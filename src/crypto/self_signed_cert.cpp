// X.509 helpers: the U2F attestation certificate (DESIGN.md "CTAP1/U2F"), the
// profile-aware packed-attestation certificate, and a subject/issuer summary
// for the diagnostics export. OpenSSL C API only, no exceptions.
#include "swpasskey/crypto/provider.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>
#include <string>
#include <utility>

namespace swpk::crypto {
namespace {

struct PkeyDel {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;

struct X509Del {
  void operator()(X509* x) const { X509_free(x); }
};
using CertPtr = std::unique_ptr<X509, X509Del>;

// FIDO's AAGUID certificate extension (id-fido-gen-ce-aaguid). Deliberately not
// spelled with a NID: OpenSSL does not register it, and the RP reads the DER.
constexpr const char* kAaguidOid = "1.3.6.1.4.1.45724.1.1.4";

// Same construction as SoftwareKeyBackend::load: OpenSSL 3 `EVP_PKEY_fromdata`
// with priv+pub is avoided deliberately (see STATUS.md "Deviations").
Pkey pkey_from_scalar_and_pub(std::span<const std::uint8_t, 32> scalar,
                              const P256PublicKey& pub) {
  EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM* d = BN_bin2bn(scalar.data(), 32, nullptr);
  BIGNUM* x = BN_bin2bn(pub.x.data(), 32, nullptr);
  BIGNUM* y = BN_bin2bn(pub.y.data(), 32, nullptr);
  const bool ok = ec != nullptr && d != nullptr && x != nullptr && y != nullptr &&
                  EC_KEY_set_private_key(ec, d) == 1 &&
                  EC_KEY_set_public_key_affine_coordinates(ec, x, y) == 1;
  BN_clear_free(d);
  BN_free(x);
  BN_free(y);
  if (!ok) {
    EC_KEY_free(ec);
    return nullptr;
  }
  EVP_PKEY* raw = EVP_PKEY_new();
  if (raw == nullptr || EVP_PKEY_assign_EC_KEY(raw, ec) != 1) {
    EVP_PKEY_free(raw);
    EC_KEY_free(ec);
    return nullptr;
  }
  return Pkey{raw};  // owns `ec`
}

bool add_name_field(X509_NAME* name, const char* field, const std::string& value) {
  if (value.empty()) {
    return true;
  }
  return X509_NAME_add_entry_by_txt(
             name, field, MBSTRING_ASC,
             reinterpret_cast<const unsigned char*>(value.c_str()), -1, -1, 0) == 1;
}

bool add_ext(X509* cert, X509V3_CTX& ctx, int nid, const char* value) {
  X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
  if (ex == nullptr) {
    return false;
  }
  const int rc = X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  return rc == 1;
}

// extnValue must be an OCTET STRING whose contents are the DER of another
// OCTET STRING holding the 16 AAGUID bytes (WebAuthn L2 §8.2.1 / FIDO).
bool add_aaguid_ext(X509* cert, const std::array<std::uint8_t, 16>& aaguid) {
  bool ok = false;
  ASN1_OCTET_STRING* inner = ASN1_OCTET_STRING_new();
  ASN1_OCTET_STRING* outer = ASN1_OCTET_STRING_new();
  ASN1_OBJECT* obj = OBJ_txt2obj(kAaguidOid, 1);
  unsigned char* der = nullptr;
  if (inner != nullptr && outer != nullptr && obj != nullptr &&
      ASN1_OCTET_STRING_set(inner, aaguid.data(), static_cast<int>(aaguid.size())) == 1) {
    const int n = i2d_ASN1_OCTET_STRING(inner, &der);
    if (n > 0 && ASN1_OCTET_STRING_set(outer, der, n) == 1) {
      X509_EXTENSION* ex = X509_EXTENSION_create_by_OBJ(nullptr, obj, 0, outer);
      if (ex != nullptr) {
        ok = X509_add_ext(cert, ex, -1) == 1;
        X509_EXTENSION_free(ex);
      }
    }
  }
  OPENSSL_free(der);
  ASN1_OCTET_STRING_free(inner);
  ASN1_OCTET_STRING_free(outer);
  ASN1_OBJECT_free(obj);
  return ok;
}

bool set_random_serial(X509* cert) {
  std::uint8_t raw[16];
  if (RAND_bytes(raw, static_cast<int>(sizeof(raw))) != 1) {
    return false;
  }
  raw[0] &= 0x7F;  // keep the INTEGER positive
  BIGNUM* bn = BN_bin2bn(raw, static_cast<int>(sizeof(raw)), nullptr);
  ASN1_INTEGER* sn = BN_to_ASN1_INTEGER(bn, nullptr);
  BN_free(bn);
  if (sn == nullptr) {
    return false;
  }
  const int rc = X509_set_serialNumber(cert, sn);
  ASN1_INTEGER_free(sn);
  return rc == 1;
}

}  // namespace

Result<std::vector<std::uint8_t>> make_self_signed_attestation_cert(
    std::span<const std::uint8_t, 32> scalar, const P256PublicKey& pub,
    const AttestationCertSpec& spec) {
  auto pkey = pkey_from_scalar_and_pub(scalar, pub);
  if (!pkey) {
    return std::unexpected(Status::Other);
  }
  CertPtr cert(X509_new());
  if (!cert) {
    return std::unexpected(Status::Other);
  }
  constexpr long kTwentyYears = 20L * 365L * 24L * 60L * 60L;
  X509_NAME* name = X509_get_subject_name(cert.get());
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);

  if (name == nullptr || X509_set_version(cert.get(), 2 /* v3 */) != 1 || !set_random_serial(cert.get()) ||
      X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) == nullptr ||
      X509_gmtime_adj(X509_getm_notAfter(cert.get()), kTwentyYears) == nullptr ||
      !add_name_field(name, "C", spec.subject_c) || !add_name_field(name, "O", spec.subject_o) ||
      !add_name_field(name, "OU", spec.subject_ou) || !add_name_field(name, "CN", spec.subject_cn) ||
      X509_set_issuer_name(cert.get(), name) != 1 || X509_set_pubkey(cert.get(), pkey.get()) != 1) {
    return std::unexpected(Status::Other);
  }
  // Shape of a vendor attestation leaf: a CA:FALSE signing certificate with a
  // key identifier, and the AAGUID duplicated inside the certificate.
  if (!add_ext(cert.get(), ctx, NID_basic_constraints, "critical,CA:FALSE") ||
      !add_ext(cert.get(), ctx, NID_key_usage, "critical,digitalSignature") ||
      !add_ext(cert.get(), ctx, NID_subject_key_identifier, "hash") ||
      !add_ext(cert.get(), ctx, NID_authority_key_identifier, "keyid:always") ||
      (spec.aaguid.has_value() && !add_aaguid_ext(cert.get(), *spec.aaguid)) ||
      X509_sign(cert.get(), pkey.get(), EVP_sha256()) == 0) {
    return std::unexpected(Status::Other);
  }
  unsigned char* der = nullptr;
  const int len = i2d_X509(cert.get(), &der);
  if (len <= 0 || der == nullptr) {
    OPENSSL_free(der);
    return std::unexpected(Status::Other);
  }
  std::vector<std::uint8_t> out(der, der + len);
  OPENSSL_free(der);
  return out;
}

Result<std::vector<std::uint8_t>> make_self_signed_p256_cert(
    std::span<const std::uint8_t, 32> scalar, const P256PublicKey& pub,
    std::string_view subject_cn) {
  AttestationCertSpec spec;
  spec.subject_cn = std::string(subject_cn);
  return make_self_signed_attestation_cert(scalar, pub, spec);
}

Result<std::pair<std::string, std::string>> x509_subject_issuer(
    std::span<const std::uint8_t> der) {
  const unsigned char* p = der.data();
  CertPtr cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
  if (!cert) {
    return std::unexpected(Status::Other);
  }
  auto render = [](X509_NAME* n) -> Result<std::string> {
    if (n == nullptr) {
      return std::unexpected(Status::Other);
    }
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
      return std::unexpected(Status::Other);
    }
    const unsigned long flags = XN_FLAG_RFC2253;
    std::string out;
    if (X509_NAME_print_ex(bio, n, 0, flags) >= 0) {
      char* data = nullptr;
      const long len = BIO_get_mem_data(bio, &data);
      if (len > 0 && data != nullptr) {
        out.assign(data, static_cast<std::size_t>(len));
      }
    }
    BIO_free(bio);
    if (out.empty()) {
      return std::unexpected(Status::Other);
    }
    return out;
  };
  auto subject = render(X509_get_subject_name(cert.get()));
  if (!subject) {
    return std::unexpected(subject.error());
  }
  auto issuer = render(X509_get_issuer_name(cert.get()));
  if (!issuer) {
    return std::unexpected(issuer.error());
  }
  return std::pair<std::string, std::string>{std::move(*subject), std::move(*issuer)};
}

}  // namespace swpk::crypto
