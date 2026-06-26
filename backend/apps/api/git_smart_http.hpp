#pragma once

#include <memory>

namespace nexus::api {

class PlatformState;

void register_git_smart_http(std::shared_ptr<PlatformState> state);

}  // namespace nexus::api
