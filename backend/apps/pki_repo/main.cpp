#include "nexus/core/uv_runtime.hpp"

int main() {
    return nexus::core::run_uv_daemon("pki-repo", {});
}

