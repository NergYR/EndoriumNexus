#include "nexus/core/uv_runtime.hpp"

#include <uv.h>

#include <csignal>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>

namespace nexus::core {

namespace {

struct TcpServer {
    uv_tcp_t handle{};
    std::string label;
    UvPacketHandler handler;
};

struct UdpServer {
    uv_udp_t handle{};
    std::string label;
    UvPacketHandler handler;
};

struct TcpClient {
    uv_tcp_t handle{};
    std::string label;
    UvPacketHandler handler;
    uv_write_t write_request{};
    std::vector<std::uint8_t> write_buffer;
};

struct UdpWrite {
    uv_udp_send_t request{};
    std::vector<std::uint8_t> payload;
};

void alloc_buffer(uv_handle_t*, std::size_t suggested_size, uv_buf_t* buf) {
    buf->base = static_cast<char*>(std::malloc(suggested_size));
    buf->len = suggested_size;
}

void on_client_closed(uv_handle_t* handle) {
    delete reinterpret_cast<TcpClient*>(handle->data);
}

void on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        return;
    }

    const auto* tcp_server = static_cast<TcpServer*>(server->data);
    auto* client = new TcpClient;
    client->label = tcp_server->label;
    client->handler = tcp_server->handler;
    uv_tcp_init(server->loop, &client->handle);
    client->handle.data = client;
    if (uv_accept(server, reinterpret_cast<uv_stream_t*>(&client->handle)) == 0) {
        if (client->handler) {
            uv_read_start(reinterpret_cast<uv_stream_t*>(&client->handle), alloc_buffer, [](uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
                auto* tcp_client = static_cast<TcpClient*>(stream->data);
                if (nread > 0 && buf != nullptr && buf->base != nullptr) {
                    UvPacket request(
                        reinterpret_cast<std::uint8_t*>(buf->base),
                        reinterpret_cast<std::uint8_t*>(buf->base) + nread);
                    auto response = tcp_client->handler(tcp_client->label, request);
                    if (!response.empty()) {
                        tcp_client->write_buffer = std::move(response);
                        auto write_buffer = uv_buf_init(
                            reinterpret_cast<char*>(tcp_client->write_buffer.data()),
                            static_cast<unsigned int>(tcp_client->write_buffer.size()));
                        tcp_client->write_request.data = tcp_client;
                        const int write_status = uv_write(&tcp_client->write_request, stream, &write_buffer, 1, [](uv_write_t* request, int) {
                            auto* written_client = static_cast<TcpClient*>(request->data);
                            uv_close(reinterpret_cast<uv_handle_t*>(&written_client->handle), on_client_closed);
                        });
                        if (write_status < 0) {
                            uv_close(reinterpret_cast<uv_handle_t*>(&tcp_client->handle), on_client_closed);
                        }
                    } else {
                        uv_close(reinterpret_cast<uv_handle_t*>(&tcp_client->handle), on_client_closed);
                    }
                } else if (nread < 0) {
                    uv_close(reinterpret_cast<uv_handle_t*>(&tcp_client->handle), on_client_closed);
                }
                if (buf != nullptr && buf->base != nullptr) {
                    std::free(buf->base);
                }
            });
        } else {
            uv_close(reinterpret_cast<uv_handle_t*>(&client->handle), on_client_closed);
        }
    } else {
        uv_close(reinterpret_cast<uv_handle_t*>(&client->handle), on_client_closed);
    }
}

void on_udp_send(uv_udp_send_t* request, int) {
    delete static_cast<UdpWrite*>(request->data);
}

void on_udp_read(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const sockaddr* addr, unsigned) {
    auto* server = static_cast<UdpServer*>(handle->data);
    if (nread > 0 && addr != nullptr && buf != nullptr && buf->base != nullptr && server->handler) {
        UvPacket request(
            reinterpret_cast<std::uint8_t*>(buf->base),
            reinterpret_cast<std::uint8_t*>(buf->base) + nread);
        auto response = server->handler(server->label, request);
        if (!response.empty()) {
            auto* write = new UdpWrite;
            write->payload = std::move(response);
            write->request.data = write;
            auto write_buffer = uv_buf_init(
                reinterpret_cast<char*>(write->payload.data()),
                static_cast<unsigned int>(write->payload.size()));
            sockaddr_storage destination{};
            const auto address_size = addr->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
            std::memcpy(&destination, addr, address_size);
            const int send_status = uv_udp_send(
                &write->request,
                handle,
                &write_buffer,
                1,
                reinterpret_cast<const sockaddr*>(&destination),
                on_udp_send);
            if (send_status < 0) {
                delete write;
            }
        }
    }
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
            server->handler = listener.handler;
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
            server->handler = listener.handler;
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
