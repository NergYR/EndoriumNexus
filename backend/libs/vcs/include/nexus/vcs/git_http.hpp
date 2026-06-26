#pragma once

#include "nexus/vcs/repository.hpp"

#include <string>
#include <utility>
#include <vector>

namespace nexus::vcs {

enum class GitHttpMethod {
    get,
    post,
};

struct GitHttpRequest {
    GitHttpMethod method{GitHttpMethod::get};
    std::string repository_name;
    std::string path_info;
    std::string query_string;
    std::string content_type;
    std::string body;
    bool authenticated{false};
    bool can_read{false};
    bool can_write{false};
    std::string remote_user;
    std::string token_id;
};

struct GitHttpResponse {
    int status_code{200};
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

class GitSmartHttpService {
  public:
    explicit GitSmartHttpService(RepositoryService repositories);

    [[nodiscard]] GitHttpResponse handle(const GitHttpRequest& request) const;

  private:
    RepositoryService repositories_;
};

}  // namespace nexus::vcs
