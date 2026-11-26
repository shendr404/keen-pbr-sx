#pragma once

#include <nlohmann/json.hpp>

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct ParsedProxyLink {
    std::string protocol;
    std::string name;
    std::string server;
    int port{0};
    // Full sing-box 1.14 outbound, including credentials. Never log this.
    nlohmann::json outbound;
    // Non-fatal notes, such as a vless encryption value that was ignored.
    std::vector<std::string> warnings;
};

// sing-box 1.14 accepts tcp, ws, grpc, http, httpupgrade and quic.
// xhttp, splithttp and anything else are rejected by `sing-box check`.
class UnsupportedProxyTransport : public std::runtime_error {
public:
    explicit UnsupportedProxyTransport(std::string transport)
        : std::runtime_error("transport " + transport + " is not supported by sing-box"),
          transport_(std::move(transport)) {}

    const std::string& transport() const noexcept { return transport_; }

private:
    std::string transport_;
};

// sing-box 1.14 has no VLESS Encryption (ML-KEM). The node must not become an outbound.
class UnsupportedVlessEncryption : public std::runtime_error {
public:
    UnsupportedVlessEncryption(std::string scheme, std::string name, std::string server, int port)
        : std::runtime_error("VLESS Encryption (" + scheme + ") не поддерживается sing-box"),
          name_(std::move(name)), server_(std::move(server)), port_(port) {}

    const std::string& name() const noexcept { return name_; }
    const std::string& server() const noexcept { return server_; }
    int port() const noexcept { return port_; }

private:
    std::string name_;
    std::string server_;
    int port_;
};

struct SkippedSubscriptionNode {
    std::string name;
    std::string protocol;
    std::string server;
    int port{0};
    std::string reason;
};

struct SubscriptionParseInfo {
    std::size_t skipped{0};
    // Transport name -> number of nodes skipped because sing-box cannot use it.
    std::map<std::string, std::size_t> unsupported_transports;
    std::size_t encryption_ignored{0};
    std::vector<SkippedSubscriptionNode> skipped_nodes;
};

struct SubscriptionNode {
    ParsedProxyLink link;
    std::string id;
    // The original share link when the subscription is a link list. Empty for
    // sing-box or Clash JSON. Kept so the node can be rebuilt for either core.
    std::string raw;
};

// Throws std::runtime_error with a message that does not contain the secret.
ParsedProxyLink parse_proxy_link(const std::string& link);

// base64 list, plain list, sing-box JSON, or Clash JSON. Unsupported lines are
// counted and skipped. Throws if nothing usable is found.
// core is "sing-box" (default) or "xray". Xray accepts VLESS only, including
// xhttp and VLESS Encryption. Other protocols are skipped and name Xray.
std::vector<SubscriptionNode> parse_subscription(const std::string& body,
                                                 SubscriptionParseInfo* info,
                                                 const std::string& core = "sing-box");

std::string proxy_node_id(const ParsedProxyLink& link);

// Public fields only: protocol, name, server, port.
nlohmann::json public_proxy_fields(const ParsedProxyLink& link);

}  // namespace keen_pbr3
