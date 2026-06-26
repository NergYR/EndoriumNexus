#pragma once

#include <memory>

namespace nexus::api {

class PlatformState;

void register_vcs_handlers(std::shared_ptr<PlatformState> state);

}  // namespace nexus::api
