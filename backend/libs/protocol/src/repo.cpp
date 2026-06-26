#include "nexus/protocol/repo.hpp"

#include <zlib.h>

#include <array>
#include <sstream>
#include <stdexcept>

namespace nexus::protocol {

std::string render_packages_index(const nexus::core::AptRepository& repository) {
    std::ostringstream output;
    for (const auto& package : repository.packages) {
        output << "Package: " << package.name << "\n";
        output << "Version: " << package.version << "\n";
        output << "Architecture: " << package.architecture << "\n";
        output << "Filename: " << (package.storage_path.empty() ? package.filename : package.storage_path) << "\n";
        output << "Size: " << package.size << "\n";
        output << "SHA256: " << package.sha256 << "\n";
        output << "Section: " << repository.component << "\n\n";
    }
    return output.str();
}

std::string render_release_file(
    const nexus::core::AptRepository& repository,
    const std::string& origin,
    const std::string& suite,
    const std::string& packages_sha256,
    std::size_t packages_size) {
    std::ostringstream output;
    output << "Origin: " << origin << "\n";
    output << "Label: Endorium Nexus\n";
    output << "Suite: " << suite << "\n";
    output << "Codename: " << repository.distribution << "\n";
    output << "Components: " << repository.component << "\n";
    output << "Architectures: amd64\n";
    output << "SHA256:\n";
    output << " " << packages_sha256 << " " << packages_size << " "
           << repository.component << "/binary-amd64/Packages\n";
    return output.str();
}

std::vector<std::uint8_t> gzip_bytes(const std::string& payload) {
    z_stream stream{};
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("deflateInit2 failed");
    }

    std::vector<std::uint8_t> buffer(256);
    std::vector<std::uint8_t> output;

    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(payload.data()));
    stream.avail_in = static_cast<uInt>(payload.size());

    int rc = Z_OK;
    while (rc == Z_OK) {
        stream.next_out = buffer.data();
        stream.avail_out = static_cast<uInt>(buffer.size());
        rc = deflate(&stream, Z_FINISH);
        output.insert(output.end(), buffer.begin(), buffer.begin() + (buffer.size() - stream.avail_out));
    }

    deflateEnd(&stream);

    if (rc != Z_STREAM_END) {
        throw std::runtime_error("gzip compression failed");
    }

    return output;
}

}  // namespace nexus::protocol
