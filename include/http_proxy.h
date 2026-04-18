#ifndef HTTP_PROXY_H
#define HTTP_PROXY_H

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <vector>
#include <memory>

class HttpProxy
{
public:
  struct Config
  {
    std::string listen_host = "127.0.0.1";
    int listen_port = 8080;
    int max_connections = 100;
    int read_timeout_ms = 30000;
    int write_timeout_ms = 30000;
    bool enable_mitm = false;
  };

  using TrafficCallback = std::function<void(const std::string &method,
                                             const std::string &host,
                                             const std::string &path,
                                             const std::string &headers)>;

  HttpProxy() = default;
  ~HttpProxy();

  bool init(const Config &cfg, TrafficCallback callback);

  bool start();

  void stop();

  struct Stats
  {
    uint64_t connections_total = 0;
    uint64_t requests_total = 0;
    uint64_t requests_blocked = 0;
    uint64_t bytes_proxied = 0;
    std::vector<std::pair<std::string, int>> top_hosts;
  };
  Stats get_stats() const;

private:
  Config config_;
  TrafficCallback callback_;
  std::atomic<bool> running_{false};
  int listen_socket_ = -1;
  std::unique_ptr<std::thread> server_thread_;

  void accept_loop();
  bool handle_client(int client_fd);
  bool parse_http_request(const std::string &data,
                          std::string &method,
                          std::string &host,
                          std::string &path,
                          std::string &headers);
  bool forward_request(int client_fd, const std::string &host,
                       const std::string &data);
};

#endif