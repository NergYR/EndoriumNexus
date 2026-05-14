#pragma once

#include <string>
#include <vector>

namespace nexus::security {

struct CertificateSubject {
    std::string common_name;
    std::string organization;
    std::vector<std::string> dns_subject_alternative_names;
};

struct IssuedCertificate {
    std::string serial_hex;
    std::string certificate_pem;
    std::string private_key_pem;
};

class PkiService {
  public:
    [[nodiscard]] IssuedCertificate create_root_ca(const CertificateSubject& subject, int days_valid) const;
    [[nodiscard]] IssuedCertificate issue_leaf_certificate(
        const IssuedCertificate& issuing_ca,
        const CertificateSubject& subject,
        int days_valid) const;
};

}  // namespace nexus::security

