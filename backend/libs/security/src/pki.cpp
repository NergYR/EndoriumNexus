#include "nexus/security/pki.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace nexus::security {

namespace {

template <typename T, auto FreeFn>
using openssl_ptr = std::unique_ptr<T, decltype(FreeFn)>;

using evp_pkey_ptr = openssl_ptr<EVP_PKEY, EVP_PKEY_free>;
using x509_ptr = openssl_ptr<X509, X509_free>;
using bio_ptr = openssl_ptr<BIO, BIO_free>;
using x509_name_ptr = openssl_ptr<X509_NAME, X509_NAME_free>;
using bn_ptr = openssl_ptr<BIGNUM, BN_free>;
using rsa_ptr = openssl_ptr<RSA, RSA_free>;

std::string current_error() {
    bio_ptr buffer(BIO_new(BIO_s_mem()), BIO_free);
    ERR_print_errors(buffer.get());
    char* data = nullptr;
    const long size = BIO_get_mem_data(buffer.get(), &data);
    return size > 0 ? std::string(data, static_cast<std::size_t>(size)) : "OpenSSL error";
}

void ensure(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(std::string(message) + ": " + current_error());
    }
}

std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    return size > 0 ? std::string(data, static_cast<std::size_t>(size)) : std::string{};
}

evp_pkey_ptr generate_key() {
    evp_pkey_ptr key(EVP_PKEY_new(), EVP_PKEY_free);
    bn_ptr exponent(BN_new(), BN_free);
    ensure(BN_set_word(exponent.get(), RSA_F4) == 1, "BN_set_word failed");

    rsa_ptr rsa(RSA_new(), RSA_free);
    ensure(RSA_generate_key_ex(rsa.get(), 3072, exponent.get(), nullptr) == 1, "RSA_generate_key_ex failed");
    ensure(EVP_PKEY_assign_RSA(key.get(), rsa.release()) == 1, "EVP_PKEY_assign_RSA failed");
    return key;
}

ASN1_INTEGER* random_serial() {
    std::array<unsigned char, 16> serial_bytes{};
    ensure(RAND_bytes(serial_bytes.data(), static_cast<int>(serial_bytes.size())) == 1, "RAND_bytes failed");
    serial_bytes[0] &= 0x7F;
    bn_ptr bn(BN_bin2bn(serial_bytes.data(), static_cast<int>(serial_bytes.size()), nullptr), BN_free);
    ensure(static_cast<bool>(bn), "BN_bin2bn failed");
    auto* serial = BN_to_ASN1_INTEGER(bn.get(), nullptr);
    ensure(serial != nullptr, "BN_to_ASN1_INTEGER failed");
    return serial;
}

void add_name_entry(X509_NAME* name, const char* field, const std::string& value) {
    if (!value.empty()) {
        ensure(
            X509_NAME_add_entry_by_txt(
                name,
                field,
                MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>(value.c_str()),
                -1,
                -1,
                0) == 1,
            "X509_NAME_add_entry_by_txt failed");
    }
}

void add_extension(X509* cert, X509* issuer, int nid, const std::string& value) {
    X509V3_CTX context;
    X509V3_set_ctx(&context, issuer, cert, nullptr, nullptr, 0);
    auto* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value.c_str()));
    ensure(extension != nullptr, "X509V3_EXT_conf_nid failed");
    ensure(X509_add_ext(cert, extension, -1) == 1, "X509_add_ext failed");
    X509_EXTENSION_free(extension);
}

std::string serial_hex(const ASN1_INTEGER* serial) {
    bn_ptr bn(ASN1_INTEGER_to_BN(serial, nullptr), BN_free);
    ensure(static_cast<bool>(bn), "ASN1_INTEGER_to_BN failed");
    char* text = BN_bn2hex(bn.get());
    if (text == nullptr) {
        throw std::runtime_error("BN_bn2hex failed");
    }
    std::string serial_string(text);
    OPENSSL_free(text);
    return serial_string;
}

std::string key_to_pem(EVP_PKEY* key) {
    bio_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
    ensure(PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1, "PEM_write_bio_PrivateKey failed");
    return bio_to_string(bio.get());
}

std::string cert_to_pem(X509* cert) {
    bio_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
    ensure(PEM_write_bio_X509(bio.get(), cert) == 1, "PEM_write_bio_X509 failed");
    return bio_to_string(bio.get());
}

evp_pkey_ptr read_private_key(const std::string& pem) {
    bio_ptr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    evp_pkey_ptr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    ensure(static_cast<bool>(key), "PEM_read_bio_PrivateKey failed");
    return key;
}

x509_ptr read_certificate(const std::string& pem) {
    bio_ptr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    x509_ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
    ensure(static_cast<bool>(cert), "PEM_read_bio_X509 failed");
    return cert;
}

X509* build_certificate(
    EVP_PKEY* subject_key,
    X509* issuer_cert,
    EVP_PKEY* issuer_key,
    const CertificateSubject& subject,
    int days_valid,
    bool is_ca) {
    auto cert = X509_new();
    ensure(cert != nullptr, "X509_new failed");
    ensure(X509_set_version(cert, 2) == 1, "X509_set_version failed");

    auto* serial = random_serial();
    ensure(serial != nullptr, "random serial failed");
    ensure(X509_set_serialNumber(cert, serial) == 1, "X509_set_serialNumber failed");
    ASN1_INTEGER_free(serial);

    ensure(X509_gmtime_adj(X509_getm_notBefore(cert), 0) != nullptr, "notBefore failed");
    ensure(
        X509_gmtime_adj(X509_getm_notAfter(cert), static_cast<long>(days_valid) * 24L * 60L * 60L) != nullptr,
        "notAfter failed");
    ensure(X509_set_pubkey(cert, subject_key) == 1, "X509_set_pubkey failed");

    X509_NAME* subject_name = X509_get_subject_name(cert);
    add_name_entry(subject_name, "O", subject.organization);
    add_name_entry(subject_name, "CN", subject.common_name);

    if (issuer_cert == nullptr) {
        ensure(X509_set_issuer_name(cert, subject_name) == 1, "X509_set_issuer_name self-signed failed");
    } else {
        ensure(X509_set_issuer_name(cert, X509_get_subject_name(issuer_cert)) == 1, "X509_set_issuer_name failed");
    }

    add_extension(cert, issuer_cert == nullptr ? cert : issuer_cert, NID_basic_constraints, is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add_extension(cert, issuer_cert == nullptr ? cert : issuer_cert, NID_key_usage, is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature,keyEncipherment");
    add_extension(cert, issuer_cert == nullptr ? cert : issuer_cert, NID_subject_key_identifier, "hash");
    if (issuer_cert != nullptr) {
        add_extension(cert, issuer_cert, NID_authority_key_identifier, "keyid:always");
    }

    if (!subject.dns_subject_alternative_names.empty()) {
        std::ostringstream sans;
        for (std::size_t index = 0; index < subject.dns_subject_alternative_names.size(); ++index) {
            if (index > 0) {
                sans << ",";
            }
            sans << "DNS:" << subject.dns_subject_alternative_names[index];
        }
        add_extension(cert, issuer_cert == nullptr ? cert : issuer_cert, NID_subject_alt_name, sans.str());
    }

    ensure(X509_sign(cert, issuer_key == nullptr ? subject_key : issuer_key, EVP_sha256()) > 0, "X509_sign failed");
    return cert;
}

}  // namespace

IssuedCertificate PkiService::create_root_ca(const CertificateSubject& subject, int days_valid) const {
    auto key = generate_key();
    x509_ptr cert(build_certificate(key.get(), nullptr, nullptr, subject, days_valid, true), X509_free);

    IssuedCertificate issued;
    issued.serial_hex = serial_hex(X509_get_serialNumber(cert.get()));
    issued.private_key_pem = key_to_pem(key.get());
    issued.certificate_pem = cert_to_pem(cert.get());
    return issued;
}

IssuedCertificate PkiService::issue_leaf_certificate(
    const IssuedCertificate& issuing_ca,
    const CertificateSubject& subject,
    int days_valid) const {
    auto ca_key = read_private_key(issuing_ca.private_key_pem);
    auto ca_cert = read_certificate(issuing_ca.certificate_pem);
    auto leaf_key = generate_key();
    x509_ptr cert(build_certificate(leaf_key.get(), ca_cert.get(), ca_key.get(), subject, days_valid, false), X509_free);

    IssuedCertificate issued;
    issued.serial_hex = serial_hex(X509_get_serialNumber(cert.get()));
    issued.private_key_pem = key_to_pem(leaf_key.get());
    issued.certificate_pem = cert_to_pem(cert.get());
    return issued;
}

}  // namespace nexus::security
