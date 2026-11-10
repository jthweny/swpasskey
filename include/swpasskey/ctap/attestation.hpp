// Packed attestation material for makeCredential.
//
// Two modes, chosen at runtime:
//   * self-signed (default) — a batch attestation key generated locally, whose
//     certificate names the selected compat profile and carries the AAGUID
//     extension. It does NOT chain to the vendor root: a relying party that
//     validates the chain or matches `attestationCertificateKeyIdentifiers`
//     against the FIDO MDS will reject it, which is the honest outcome.
//   * vendor-chain (opt-in) — SWPASSKEY_ATTEST_CHAIN=<dir> naming leaf.pem,
//     leaf.key and optional chain.pem. For an owner of a real attestation key,
//     e.g. to reproduce a captured chain byte for byte.
#pragma once

#include "swpasskey/compat/profile.hpp"
#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/status.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace swpk::ctap {

struct PackedAttestation {
  std::vector<std::vector<std::uint8_t>> chain;  // leaf first, DER
  std::string source;                            // "self-signed" | "vendor-chain"
  std::string subject;
  std::string issuer;
  std::string profile_id;     // profile the leaf was built for
  std::string leaf_sha256;    // hex; correlates a record with a certificate
  // Self-signed mode: the batch key, usable through the software backend.
  std::array<std::uint8_t, 32> scalar{};
  crypto::P256PublicKey pub{};
  // Vendor-chain mode: the leaf key on disk (never loaded into the store).
  std::optional<std::filesystem::path> pem_key;
};

// Owns the batch attestation key and caches one leaf per profile. Not
// thread-safe by itself: the authenticator calls it under its operation lock.
class BatchAttester {
public:
  // `key_path` empty ⇒ an ephemeral key for this process (tests, --testing).
  BatchAttester(crypto::Provider& crypto, std::filesystem::path key_path);

  // nullptr when no attestation can be produced (the caller then falls back to
  // packed self-attestation signed by the credential key, without x5c).
  const PackedAttestation* for_profile(const compat::CompatProfile& profile);

  // Opt into a real vendor chain instead of the self-signed leaf.
  Result<void> use_vendor_chain(const std::filesystem::path& dir);
  bool vendor_chain() const { return vendor_.has_value(); }

  void invalidate();

private:
  Result<void> load_vendor_chain(const std::filesystem::path& dir);
  Result<PackedAttestation> build_self_signed(const compat::CompatProfile& profile);

  crypto::Provider& crypto_;
  std::filesystem::path key_path_;
  std::array<std::uint8_t, 32> scalar_{};
  crypto::P256PublicKey pub_{};
  bool have_key_{false};
  bool have_pub_{false};
  std::optional<PackedAttestation> vendor_;
  std::optional<PackedAttestation> cached_;
};

// CTAP2 CBOR for the packed attestation statement, keys in canonical order
// (alg, sig, x5c). `chain` may be empty for self-attestation.
std::vector<std::uint8_t> encode_packed_att_stmt(std::span<const std::uint8_t> sig,
                                                std::span<const std::vector<std::uint8_t>> chain);

// Signs `msg` with the attestation key: the software backend for a self-signed
// batch key, the PEM file for a vendor chain.
Result<std::vector<std::uint8_t>> sign_attestation(const PackedAttestation& att,
                                                   crypto::KeyBackend& software,
                                                   std::span<const std::uint8_t> msg);

}  // namespace swpk::ctap
