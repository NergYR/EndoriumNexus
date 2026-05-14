#include "nexus/jobs/queue.hpp"

#include "nexus/core/time.hpp"

#include <algorithm>

namespace nexus::jobs {

namespace {

std::string next_job_id(std::size_t counter) {
    return "job-" + std::to_string(counter);
}

}  // namespace

JobQueue::JobQueue() {
    jobs_.push_back({"job-1", "pki", "running", "Publish CRL", nexus::core::utc_timestamp()});
    jobs_.push_back({"job-2", "repo", "pending", "Regenerate Release metadata", nexus::core::utc_timestamp()});
}

nexus::core::JobSummary JobQueue::enqueue(const std::string& domain, const std::string& description) {
    std::scoped_lock lock(mutex_);
    const nexus::core::JobSummary job{
        next_job_id(jobs_.size() + 1),
        domain,
        "pending",
        description,
        nexus::core::utc_timestamp()};
    jobs_.push_back(job);
    return job;
}

void JobQueue::mark_done(const std::string& id) {
    std::scoped_lock lock(mutex_);
    auto it = std::find_if(jobs_.begin(), jobs_.end(), [&](const auto& job) { return job.id == id; });
    if (it != jobs_.end()) {
        it->status = "done";
    }
}

std::vector<nexus::core::JobSummary> JobQueue::list() const {
    std::scoped_lock lock(mutex_);
    return jobs_;
}

std::size_t JobQueue::pending_count() const {
    std::scoped_lock lock(mutex_);
    return std::count_if(jobs_.begin(), jobs_.end(), [](const auto& job) { return job.status != "done"; });
}

}  // namespace nexus::jobs

