#pragma once

#include "nexus/core/models.hpp"

#include <mutex>
#include <string>
#include <vector>

namespace nexus::jobs {

class JobQueue {
  public:
    JobQueue();

    nexus::core::JobSummary enqueue(const std::string& domain, const std::string& description);
    void mark_done(const std::string& id);
    [[nodiscard]] std::vector<nexus::core::JobSummary> list() const;
    [[nodiscard]] std::size_t pending_count() const;

  private:
    mutable std::mutex mutex_;
    std::vector<nexus::core::JobSummary> jobs_;
};

}  // namespace nexus::jobs

