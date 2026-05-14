#include "nexus/core/uv_runtime.hpp"

#include <uv.h>

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>

namespace nexus::core {

namespace {

struct TcpServer {
    uv_tcp_t handle{};
    std::string label;
};

struct UdpServer {
    uv_udp_t handle{};
    std::string label;
};

void alloc_buffer(uv_handle_t*, std::size_t suggested_size, uv_buf_t* buf) {
    buf->base = static_cast<char*>(std::malloc(suggested_size));
    buf->len = suggested_size;
}

void on_client_closed(uv_handle_t* handle) {
    delete reinterpret_cast<uv_tcp_t*>(handle);
}

void on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        return;
    }

    auto* client = new uv_tcp_t;
    uv_tcp_init(server->loop, client);
    if (uv_accept(server, reinterpret_cast<uv_stream_t*>(client)) == 0) {
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_client_closed);
    } else {
        uv_close(reinterpret_cast<uv_handle_t*>(client), on_client_closed);
    }
}

void on_udp_read(uv_udp_t*, ssize_t nread, const uv_buf_t* buf, const sockaddr*, unsigned) {
    if (buf != nullptr && buf->base != nullptr) {
        std::free(buf->base);
    }
    if (nread < 0) {
        return;
    }
}

void on_signal(uv_signal_t* handle, int) {
    std::cout << "Stopping daemon..." << std::endl;
    uv_stop(handle->loop);
}

void on_heartbeat(uv_timer_t* timer) {
    auto* service_name = static_cast<std::string*>(timer->data);
    std::cout << *service_name << ": heartbeat" << std::endl;
}

}  // namespace

int run_uv_daemon(const std::string& service_name, const std::vector<UvListener>& listeners) {
    uv_loop_t loop;
    uv_loop_init(&loop);

    std::vector<std::unique_ptr<TcpServer>> tcp_servers;
    std::vector<std::unique_ptr<UdpServer>> udp_servers;

    for (const auto& listener : listeners) {
        sockaddr_in addr{};
        uv_ip4_addr(listener.host.c_str(), listener.port, &addr);

        if (listener.transport == UvTransport::tcp) {
            auto server = std::make_unique<TcpServer>();
            server->label = listener.label;
            uv_tcp_init(&loop, &server->handle);
            server->handle.data = server.get();
            uv_tcp_bind(&server->handle, reinterpret_cast<const sockaddr*>(&addr), 0);
            uv_listen(reinterpret_cast<uv_stream_t*>(&server->handle), 64, on_new_connection);
            std::cout << service_name << ": listening on tcp://" << listener.host << ":" << listener.port
                      << " (" << listener.label << ")" << std::endl;
            tcp_servers.push_back(std::move(server));
        } else {
            auto server = std::make_unique<UdpServer>();
            server->label = listener.label;
            uv_udp_init(&loop, &server->handle);
            server->handle.data = server.get();
            uv_udp_bind(&server->handle, reinterpret_cast<const sockaddr*>(&addr), 0);
            uv_udp_recv_start(&server->handle, alloc_buffer, on_udp_read);
            std::cout << service_name << ": listening on udp://" << listener.host << ":" << listener.port
                      << " (" << listener.label << ")" << std::endl;
            udp_servers.push_back(std::move(server));
        }
    }

    uv_signal_t sigint{};
    uv_signal_t sigterm{};
    uv_signal_init(&loop, &sigint);
    uv_signal_init(&loop, &sigterm);
    uv_signal_start(&sigint, on_signal, SIGINT);
    uv_signal_start(&sigterm, on_signal, SIGTERM);

    uv_timer_t heartbeat{};
    std::string heartbeat_name = service_name;
    uv_timer_init(&loop, &heartbeat);
    heartbeat.data = &heartbeat_name;
    uv_timer_start(&heartbeat, on_heartbeat, 0, 5000);

    const int result = uv_run(&loop, UV_RUN_DEFAULT);

    uv_timer_stop(&heartbeat);
    uv_close(reinterpret_cast<uv_handle_t*>(&heartbeat), nullptr);
    uv_signal_stop(&sigint);
    uv_signal_stop(&sigterm);
    uv_close(reinterpret_cast<uv_handle_t*>(&sigint), nullptr);
    uv_close(reinterpret_cast<uv_handle_t*>(&sigterm), nullptr);

    for (auto& server : tcp_servers) {
        uv_close(reinterpret_cast<uv_handle_t*>(&server->handle), nullptr);
    }
    for (auto& server : udp_servers) {
        uv_udp_recv_stop(&server->handle);
        uv_close(reinterpret_cast<uv_handle_t*>(&server->handle), nullptr);
    }

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
    return result;
}

}  // namespace nexus::core
