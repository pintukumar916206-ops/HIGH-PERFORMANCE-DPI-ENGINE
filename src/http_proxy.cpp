#include "http_proxy.h"
#include "utils/logger.h"
#include <iostream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define SHUT_RDWR SD_BOTH
#define close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#endif

HttpProxy::~HttpProxy()
{
  stop();
}

bool HttpProxy::init(const Config &cfg, TrafficCallback callback)
{
  config_ = cfg;
  callback_ = callback;

#ifdef _WIN32
  WSADATA wsa_data;
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
  {
    LOG_ERROR("WSAStartup failed");
    return false;
  }
#endif

  listen_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listen_socket_ < 0)
  {
    LOG_ERROR("Failed to create socket");
    return false;
  }

  int reuse = 1;
  if (setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR,
                 (const char *)&reuse, sizeof(reuse)) < 0)
  {
    LOG_WARN("setsockopt SO_REUSEADDR failed");
  }

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(config_.listen_port);

  if (inet_pton(AF_INET, config_.listen_host.c_str(), &server_addr.sin_addr) <= 0)
  {
    LOG_ERROR("Invalid listen address: %s", config_.listen_host.c_str());
    close(listen_socket_);
    return false;
  }

  if (bind(listen_socket_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
    LOG_ERROR("Failed to bind to %s:%d", config_.listen_host.c_str(), config_.listen_port);
    close(listen_socket_);
    return false;
  }

  if (listen(listen_socket_, config_.max_connections) < 0)
  {
    LOG_ERROR("listen() failed");
    close(listen_socket_);
    return false;
  }

  LOG_INFO("HTTP Proxy listening on %s:%d", config_.listen_host.c_str(), config_.listen_port);
  return true;
}

bool HttpProxy::start()
{
  running_ = true;
  server_thread_ = std::make_unique<std::thread>(&HttpProxy::accept_loop, this);
  LOG_INFO("HTTP Proxy server started");
  return true;
}

void HttpProxy::stop()
{
  running_ = false;
  if (listen_socket_ >= 0)
  {
    close(listen_socket_);
    listen_socket_ = -1;
  }
  if (server_thread_ && server_thread_->joinable())
  {
    server_thread_->join();
  }
}

void HttpProxy::accept_loop()
{
  while (running_)
  {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client_fd = accept(listen_socket_, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0)
    {
      if (running_)
      {
        LOG_ERROR("accept() failed");
      }
      continue;
    }

#ifdef _WIN32
    unsigned long timeout = config_.read_timeout_ms;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = config_.read_timeout_ms / 1000;
    tv.tv_usec = (config_.read_timeout_ms % 1000) * 1000;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    std::thread(&HttpProxy::handle_client, this, client_fd).detach();
  }
}

bool HttpProxy::handle_client(int client_fd)
{

  char buffer[8192];
  int bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

  if (bytes <= 0)
  {
    close(client_fd);
    return false;
  }

  buffer[bytes] = '\0';
  std::string request_data(buffer, bytes);

  std::string method, host, path, headers;
  if (!parse_http_request(request_data, method, host, path, headers))
  {
    LOG_WARN("Failed to parse HTTP request");
    close(client_fd);
    return false;
  }

  if (callback_)
  {
    callback_(method, host, path, headers);
  }

  if (!forward_request(client_fd, host, request_data))
  {
    close(client_fd);
    return false;
  }

  close(client_fd);
  return true;
}

bool HttpProxy::parse_http_request(const std::string &data,
                                   std::string &method,
                                   std::string &host,
                                   std::string &path,
                                   std::string &headers)
{

  std::istringstream stream(data);
  std::string line;

  if (!std::getline(stream, line))
    return false;

  std::istringstream first_line(line);
  first_line >> method >> path;

  while (std::getline(stream, line))
  {
    if (line == "\r" || line.empty())
      break;

    if (line.find("Host:") == 0)
    {
      host = line.substr(5);

      host.erase(0, host.find_first_not_of(" \t\r\n"));
      host.erase(host.find_last_not_of(" \t\r\n") + 1);
    }

    headers += line + "\n";
  }

  return !method.empty() && !host.empty();
}

bool HttpProxy::forward_request(int client_fd, const std::string &host,
                                const std::string &data)
{
  LOG_DEBUG("Forwarding %lu bytes to %s", data.size(), host.c_str());

  std::string hostname = host;
  std::string port_str = "80";

  size_t colon_pos = host.find(':');
  if (colon_pos != std::string::npos)
  {
    hostname = host.substr(0, colon_pos);
    port_str = host.substr(colon_pos + 1);
  }

  struct addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *result = nullptr;
  int addr_status = getaddrinfo(hostname.c_str(), port_str.c_str(), &hints, &result);
  if (addr_status != 0 || !result)
  {
    LOG_ERROR("DNS resolution failed for %s", hostname.c_str());
    return false;
  }

  int server_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if (server_fd < 0)
  {
    LOG_ERROR("Failed to create server socket");
    freeaddrinfo(result);
    return false;
  }

  if (connect(server_fd, result->ai_addr, result->ai_addrlen) < 0)
  {
    LOG_ERROR("Failed to connect to %s:%s", hostname.c_str(), port_str.c_str());
    close(server_fd);
    freeaddrinfo(result);
    return false;
  }

  freeaddrinfo(result);

  ssize_t bytes_sent = send(server_fd, data.c_str(), data.size(), 0);
  if (bytes_sent < 0)
  {
    LOG_ERROR("Failed to send request");
    close(server_fd);
    return false;
  }

  char buffer[4096];
  while (true)
  {
    ssize_t bytes_rcvd = recv(server_fd, buffer, sizeof(buffer), 0);
    if (bytes_rcvd <= 0)
      break;

    ssize_t sent = send(client_fd, buffer, bytes_rcvd, 0);
    if (sent < 0)
      break;
  }

  close(server_fd);
  return true;
}

HttpProxy::Stats HttpProxy::get_stats() const
{
  return {};
}