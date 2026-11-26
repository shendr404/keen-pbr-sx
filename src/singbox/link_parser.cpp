#include "link_parser.hpp"
#include "xray_config.hpp"

#include <cctype>
#include <cstdint>
#include <sstream>
#include <stdexcept>

namespace keen_pbr3 {
namespace {

std::string trim(std::string text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
        text.erase(text.begin());
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
        text.pop_back();
    }
    return text;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string percent_decode(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '%' && i + 2 < text.size()) {
            const int hi = hex_value(text[i + 1]);
            const int lo = hex_value(text[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        if (text[i] == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(text[i]);
    }
    return out;
}

std::string base64_decode(std::string text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
        text.pop_back();
    }
    for (char& c : text) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (text.size() % 4 != 0) text.push_back('=');
    static const int kMap[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    std::string out;
    int val = 0;
    int valb = -8;
    for (unsigned char c : text) {
        if (c == '=') break;
        const int d = c < 128 ? kMap[c] : -1;
        if (d < 0) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::string query_value(const std::string& query, const std::string& key) {
    std::size_t pos = 0;
    while (pos < query.size()) {
        const auto amp = query.find('&', pos);
        const auto part = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        const auto eq = part.find('=');
        const auto name = percent_decode(eq == std::string::npos ? part : part.substr(0, eq));
        if (name == key) {
            return percent_decode(eq == std::string::npos ? std::string{} : part.substr(eq + 1));
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return {};
}

struct Authority {
    std::string user;
    std::string host;
    int port{0};
};

Authority split_authority(const std::string& body) {
    std::string user;
    std::string hostport = body;
    const auto at = body.rfind('@');
    if (at != std::string::npos) {
        user = percent_decode(body.substr(0, at));
        hostport = body.substr(at + 1);
    }
    std::string host;
    std::string port_text;
    if (!hostport.empty() && hostport.front() == '[') {
        const auto end = hostport.find(']');
        if (end == std::string::npos) throw std::runtime_error("proxy link host is invalid");
        host = hostport.substr(1, end - 1);
        if (end + 1 < hostport.size() && hostport[end + 1] == ':') {
            port_text = hostport.substr(end + 2);
        }
    } else {
        const auto colon = hostport.rfind(':');
        if (colon == std::string::npos) throw std::runtime_error("proxy link has no port");
        host = hostport.substr(0, colon);
        port_text = hostport.substr(colon + 1);
    }
    if (host.empty() || port_text.empty()) throw std::runtime_error("proxy link host is invalid");
    int port = 0;
    for (char c : port_text) {
        if (c < '0' || c > '9') throw std::runtime_error("proxy link port is invalid");
        port = port * 10 + (c - '0');
    }
    if (port <= 0 || port > 65535) throw std::runtime_error("proxy link port is invalid");
    return {user, host, port};
}

bool supported_transport(const std::string& type) {
    return type.empty() || type == "tcp" || type == "none" || type == "ws" || type == "grpc" ||
           type == "http" || type == "httpupgrade" || type == "quic";
}

void ensure_reality_utls(nlohmann::json& tls) {
    if (!tls.contains("utls")) {
        tls["utls"] = {{"enabled", true}, {"fingerprint", "chrome"}};
    }
}

nlohmann::json tls_object(const std::string& query, bool enabled) {
    nlohmann::json tls{{"enabled", enabled}};
    const auto sni = query_value(query, "sni");
    const auto peer = sni.empty() ? query_value(query, "peer") : sni;
    if (!peer.empty()) tls["server_name"] = peer;
    const auto fp = query_value(query, "fp");
    if (!fp.empty()) tls["utls"] = {{"enabled", true}, {"fingerprint", fp}};
    const auto insecure = query_value(query, "allowInsecure");
    if (insecure == "1" || insecure == "true") tls["insecure"] = true;
    const auto security = query_value(query, "security");
    const auto pbk = query_value(query, "pbk");
    if (security == "reality" || !pbk.empty()) {
        nlohmann::json reality{{"enabled", true}, {"public_key", pbk}};
        const auto sid = query_value(query, "sid");
        if (!sid.empty()) reality["short_id"] = sid;
        tls["reality"] = std::move(reality);
        tls["enabled"] = true;
        // sing-box reality requires uTLS. Share links often omit fp.
        ensure_reality_utls(tls);
    }
    return tls;
}

void add_transport(nlohmann::json& outbound, const std::string& query) {
    const auto type = query_value(query, "type");
    if (!supported_transport(type)) throw UnsupportedProxyTransport(type);
    if (type.empty() || type == "tcp" || type == "none") return;
    nlohmann::json transport{{"type", type}};
    const auto path = query_value(query, "path");
    if (!path.empty() && type != "quic") transport["path"] = path;
    const auto host = query_value(query, "host");
    if (type == "ws" && !host.empty()) {
        transport["headers"] = {{"Host", host}};
    } else if (type == "http" && !host.empty()) {
        transport["host"] = nlohmann::json::array({host});
    } else if (type == "httpupgrade" && !host.empty()) {
        transport["host"] = host;
    }
    if (type == "grpc") {
        const auto service = query_value(query, "serviceName");
        if (!service.empty()) transport["service_name"] = service;
    }
    outbound["transport"] = std::move(transport);
}

std::string encryption_scheme(const std::string& encryption) {
    const auto dot = encryption.find('.');
    auto scheme = dot == std::string::npos ? encryption : encryption.substr(0, dot);
    if (scheme.empty()) scheme = encryption;
    if (scheme.size() > 64) scheme.resize(64);
    return scheme;
}

void reject_vless_encryption(const std::string& encryption, const std::string& name, const std::string& server,
                             int port) {
    if (encryption.empty() || encryption == "none") return;
    throw UnsupportedVlessEncryption(encryption_scheme(encryption), name, server, port);
}

ParsedProxyLink finish(ParsedProxyLink parsed, const std::string& name, const std::string& fallback) {
    parsed.name = name.empty() ? fallback : name;
    if (parsed.name.empty()) parsed.name = parsed.server;
    parsed.outbound["tag"] = "node";
    return parsed;
}

ParsedProxyLink parse_standard(const std::string& protocol, const std::string& rest) {
    const auto hash = rest.find('#');
    const auto main = hash == std::string::npos ? rest : rest.substr(0, hash);
    const auto name = hash == std::string::npos ? std::string{} : percent_decode(rest.substr(hash + 1));
    const auto qpos = main.find('?');
    const auto authority_text = qpos == std::string::npos ? main : main.substr(0, qpos);
    const auto query = qpos == std::string::npos ? std::string{} : main.substr(qpos + 1);
    std::string raw = authority_text;
    if (protocol == "shadowsocks" && raw.find('@') == std::string::npos) {
        raw = base64_decode(raw);
    }
    const auto authority = split_authority(raw);
    ParsedProxyLink parsed;
    parsed.protocol = protocol;
    parsed.server = authority.host;
    parsed.port = authority.port;
    nlohmann::json outbound{
        {"type", protocol},
        {"server", authority.host},
        {"server_port", authority.port},
    };
    if (protocol == "vless") {
        if (authority.user.empty()) throw std::runtime_error("vless link has no uuid");
        outbound["uuid"] = authority.user;
        const auto flow = query_value(query, "flow");
        if (!flow.empty()) outbound["flow"] = flow;
        const auto security = query_value(query, "security");
        if (security != "none") outbound["tls"] = tls_object(query, security != "none" && !security.empty() ? true : !query_value(query, "sni").empty());
        if (security == "tls" || security == "reality") outbound["tls"]["enabled"] = true;
        add_transport(outbound, query);
        const auto node_name = name.empty() ? authority.host : name;
        reject_vless_encryption(query_value(query, "encryption"), node_name, authority.host, authority.port);
    } else if (protocol == "trojan") {
        if (authority.user.empty()) throw std::runtime_error("trojan link has no password");
        outbound["password"] = authority.user;
        outbound["tls"] = tls_object(query, true);
        add_transport(outbound, query);
    } else if (protocol == "hysteria2") {
        if (authority.user.empty()) throw std::runtime_error("hysteria2 link has no password");
        outbound["password"] = authority.user;
        outbound["tls"] = tls_object(query, true);
        const auto obfs = query_value(query, "obfs");
        const auto obfs_password = query_value(query, "obfs-password");
        if (!obfs.empty()) {
            outbound["obfs"] = {{"type", obfs}, {"password", obfs_password}};
        }
    } else if (protocol == "shadowsocks") {
        const auto colon = authority.user.find(':');
        if (colon == std::string::npos) throw std::runtime_error("shadowsocks link has no method");
        outbound["method"] = authority.user.substr(0, colon);
        outbound["password"] = authority.user.substr(colon + 1);
    } else {
        throw std::runtime_error("unsupported proxy link");
    }
    parsed.outbound = std::move(outbound);
    return finish(std::move(parsed), name, authority.host);
}

ParsedProxyLink parse_shadowsocks(const std::string& rest) {
    const auto hash = rest.find('#');
    const auto main = hash == std::string::npos ? rest : rest.substr(0, hash);
    const auto name = hash == std::string::npos ? std::string{} : percent_decode(rest.substr(hash + 1));
    if (main.find('@') == std::string::npos) {
        const auto decoded = base64_decode(main);
        if (decoded.find('@') != std::string::npos) {
            return parse_standard("shadowsocks", decoded + (name.empty() ? "" : "#" + name));
        }
    }
    const auto qpos = main.find('?');
    const auto authority = qpos == std::string::npos ? main : main.substr(0, qpos);
    const auto at = authority.rfind('@');
    if (at != std::string::npos) {
        auto user = authority.substr(0, at);
        if (user.find(':') == std::string::npos) {
            user = base64_decode(percent_decode(user));
        }
        std::string rebuilt = user + "@" + authority.substr(at + 1);
        if (qpos != std::string::npos) rebuilt += main.substr(qpos);
        if (!name.empty()) rebuilt += "#" + name;
        return parse_standard("shadowsocks", rebuilt);
    }
    throw std::runtime_error("shadowsocks link is invalid");
}

ParsedProxyLink parse_vmess(const std::string& rest) {
    const auto hash = rest.find('#');
    const auto body = hash == std::string::npos ? rest : rest.substr(0, hash);
    nlohmann::json raw;
    try {
        raw = nlohmann::json::parse(base64_decode(body));
    } catch (const std::exception&) {
        throw std::runtime_error("vmess link is not valid JSON");
    }
    if (!raw.is_object() || !raw.contains("add") || !raw.contains("port") || !raw.contains("id")) {
        throw std::runtime_error("vmess link is missing server fields");
    }
    ParsedProxyLink parsed;
    parsed.protocol = "vmess";
    parsed.server = raw.at("add").get<std::string>();
    if (raw.at("port").is_string()) parsed.port = std::stoi(raw.at("port").get<std::string>());
    else parsed.port = raw.at("port").get<int>();
    parsed.outbound = {
        {"type", "vmess"},
        {"server", parsed.server},
        {"server_port", parsed.port},
        {"uuid", raw.at("id").get<std::string>()},
        {"security", "auto"},
        {"alter_id", 0},
    };
    const auto net = raw.value("net", "tcp");
    if (!supported_transport(net)) throw UnsupportedProxyTransport(net);
    if (net != "tcp" && net != "none") {
        nlohmann::json transport{{"type", net}};
        if (raw.contains("path") && raw["path"].is_string() && !raw["path"].get<std::string>().empty()) {
            transport["path"] = raw["path"];
        }
        if (net == "ws" && raw.contains("host") && raw["host"].is_string()) {
            transport["headers"] = {{"Host", raw["host"]}};
        } else if (net == "http" && raw.contains("host") && raw["host"].is_string()) {
            transport["host"] = nlohmann::json::array({raw["host"]});
        } else if (net == "httpupgrade" && raw.contains("host") && raw["host"].is_string()) {
            transport["host"] = raw["host"];
        }
        parsed.outbound["transport"] = std::move(transport);
    }
    const auto tls = raw.value("tls", "");
    if (tls == "tls") {
        nlohmann::json tls_json{{"enabled", true}};
        const auto sni = raw.value("sni", raw.value("host", ""));
        if (!sni.empty()) tls_json["server_name"] = sni;
        parsed.outbound["tls"] = std::move(tls_json);
    }
    const auto name = raw.value("ps", "");
    return finish(std::move(parsed), name, parsed.server);
}

nlohmann::json clash_proxy_to_outbound(const nlohmann::json& proxy) {
    const auto type = proxy.value("type", "");
    nlohmann::json outbound{
        {"type", type == "ss" ? "shadowsocks" : type},
        {"server", proxy.at("server").get<std::string>()},
        {"server_port", proxy.at("port").get<int>()},
    };
    if (type == "ss") {
        outbound["method"] = proxy.at("cipher").get<std::string>();
        outbound["password"] = proxy.at("password").get<std::string>();
    } else if (type == "vmess" || type == "vless") {
        if (type == "vless") {
            reject_vless_encryption(proxy.value("encryption", ""), proxy.value("name", proxy.value("server", "")),
                                    proxy.value("server", ""), proxy.value("port", 0));
        }
        outbound["uuid"] = proxy.value("uuid", proxy.value("password", ""));
        if (proxy.contains("alterId")) outbound["alter_id"] = proxy["alterId"];
    } else if (type == "trojan" || type == "hysteria2") {
        outbound["password"] = proxy.value("password", "");
    } else {
        throw std::runtime_error("unsupported clash proxy");
    }
    const bool tls = proxy.value("tls", false) || proxy.value("skip-cert-verify", false) || type == "trojan" || type == "hysteria2";
    if (tls && type != "ss") {
        nlohmann::json tls_json{{"enabled", true}};
        if (proxy.contains("sni")) tls_json["server_name"] = proxy["sni"];
        else if (proxy.contains("servername")) tls_json["server_name"] = proxy["servername"];
        if (proxy.value("skip-cert-verify", false)) tls_json["insecure"] = true;
        const bool reality = proxy.contains("reality-opts") && proxy["reality-opts"].is_object();
        if (reality) {
            tls_json["reality"] = {
                {"enabled", true},
                {"public_key", proxy["reality-opts"].value("public-key", "")},
                {"short_id", proxy["reality-opts"].value("short-id", "")},
            };
        }
        if (proxy.contains("client-fingerprint") && proxy["client-fingerprint"].is_string()) {
            tls_json["utls"] = {{"enabled", true}, {"fingerprint", proxy["client-fingerprint"]}};
        } else if (reality) {
            ensure_reality_utls(tls_json);
        }
        outbound["tls"] = std::move(tls_json);
    }
    const auto network = proxy.value("network", "");
    if (!supported_transport(network)) throw UnsupportedProxyTransport(network);
    if (!network.empty() && network != "tcp" && network != "none") {
        nlohmann::json transport{{"type", network}};
        if (proxy.contains("ws-opts") && proxy["ws-opts"].is_object()) {
            if (proxy["ws-opts"].contains("path")) transport["path"] = proxy["ws-opts"]["path"];
            if (proxy["ws-opts"].contains("headers")) transport["headers"] = proxy["ws-opts"]["headers"];
        }
        outbound["transport"] = std::move(transport);
    }
    return outbound;
}

bool looks_like_base64_list(const std::string& body) {
    if (body.find("://") != std::string::npos) return false;
    int usable = 0;
    for (unsigned char c : body) {
        if (std::isspace(c)) continue;
        const bool ok = std::isalnum(c) || c == '+' || c == '/' || c == '=' || c == '-' || c == '_';
        if (!ok) return false;
        ++usable;
    }
    return usable > 16;
}

}  // namespace

std::string proxy_node_id(const ParsedProxyLink& link) {
    const std::string material = link.protocol + "|" + link.server + "|" +
                                 std::to_string(link.port) + "|" + link.name;
    std::uint64_t hash = 1469598103934665603ull;
    for (unsigned char c : material) {
        hash ^= c;
        hash *= 1099511628211ull;
    }
    std::ostringstream out;
    out << std::hex << hash;
    return out.str();
}

nlohmann::json public_proxy_fields(const ParsedProxyLink& link) {
    return {
        {"protocol", link.protocol},
        {"name", link.name},
        {"server", link.server},
        {"port", link.port},
    };
}

ParsedProxyLink parse_proxy_link(const std::string& raw_link) {
    const auto link = trim(raw_link);
    const auto scheme_end = link.find("://");
    if (scheme_end == std::string::npos || scheme_end == 0) {
        throw std::runtime_error("proxy link needs a scheme such as vless://");
    }
    auto scheme = link.substr(0, scheme_end);
    for (char& c : scheme) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const auto rest = link.substr(scheme_end + 3);
    try {
        if (scheme == "vless") return parse_standard("vless", rest);
        if (scheme == "trojan") return parse_standard("trojan", rest);
        if (scheme == "hysteria2" || scheme == "hy2") return parse_standard("hysteria2", rest);
        if (scheme == "ss") return parse_shadowsocks(rest);
        if (scheme == "vmess") return parse_vmess(rest);
    } catch (const std::runtime_error&) {
        throw;
    } catch (const std::exception&) {
        throw std::runtime_error("proxy link could not be parsed");
    }
    throw std::runtime_error("unsupported proxy scheme");
}

static void note_skip(SubscriptionParseInfo& info, const std::string& transport, SkippedSubscriptionNode node = {}) {
    ++info.skipped;
    if (!transport.empty()) ++info.unsupported_transports[transport];
    if (node.reason.empty()) {
        node.reason = transport.empty() ? "subscription line was skipped"
                                        : "transport " + transport + " is not supported by sing-box";
    }
    info.skipped_nodes.push_back(std::move(node));
}

static std::string link_fragment(const std::string& line) {
    const auto hash = line.rfind('#');
    if (hash == std::string::npos) return {};
    return percent_decode(line.substr(hash + 1));
}

static std::string transport_of(const nlohmann::json& outbound) {
    if (!outbound.contains("transport") || !outbound["transport"].is_object()) return {};
    return outbound["transport"].value("type", "");
}

std::vector<SubscriptionNode> parse_subscription(const std::string& body, SubscriptionParseInfo* info,
                                                  const std::string& core) {
    SubscriptionParseInfo local;
    std::vector<SubscriptionNode> nodes;
    const auto add_link = [&](const std::string& line) {
        if (core == "xray") {
            const auto view = classify_link_for_core(line, "xray");
            if (!view.supported) {
                note_skip(local, {},
                          SkippedSubscriptionNode{view.name.empty() ? link_fragment(line) : view.name, view.protocol,
                                                  view.server, view.port, view.reason});
                return;
            }
            SubscriptionNode node;
            node.link.protocol = view.protocol;
            node.link.name = view.name;
            node.link.server = view.server;
            node.link.port = view.port;
            node.link.outbound = view.outbound;
            node.id = proxy_node_id(node.link);
            node.raw = trim(line);
            nodes.push_back(std::move(node));
            return;
        }
        try {
            SubscriptionNode node;
            node.link = parse_proxy_link(line);
            node.id = proxy_node_id(node.link);
            node.raw = trim(line);
            for (const auto& warning : node.link.warnings) {
                if (warning.find("encryption") != std::string::npos) ++local.encryption_ignored;
            }
            nodes.push_back(std::move(node));
        } catch (const UnsupportedVlessEncryption& error) {
            auto skipped_name = error.name().empty() ? link_fragment(line) : error.name();
            note_skip(local, {}, SkippedSubscriptionNode{std::move(skipped_name), "vless", error.server(), error.port(),
                                                         error.what()});
        } catch (const UnsupportedProxyTransport& error) {
            note_skip(local, error.transport(), SkippedSubscriptionNode{link_fragment(line), {}, {}, 0, error.what()});
        } catch (const std::runtime_error& error) {
            note_skip(local, {}, SkippedSubscriptionNode{link_fragment(line), {}, {}, 0, error.what()});
        }
    };
    const auto trimmed = trim(body);
    if (!trimmed.empty() && trimmed.front() == '{') {
        nlohmann::json doc = nlohmann::json::parse(trimmed);
        if (doc.contains("outbounds") && doc["outbounds"].is_array()) {
            for (const auto& outbound : doc["outbounds"]) {
                const auto type = outbound.value("type", "");
                if (type != "vless" && type != "vmess" && type != "trojan" &&
                    type != "shadowsocks" && type != "hysteria2") {
                    note_skip(local, {},
                              SkippedSubscriptionNode{outbound.value("tag", ""), type, outbound.value("server", ""),
                                                      outbound.value("server_port", 0), "subscription line was skipped"});
                    continue;
                }
                const auto transport = transport_of(outbound);
                if (!supported_transport(transport)) {
                    note_skip(local, transport,
                              SkippedSubscriptionNode{outbound.value("tag", ""), type, outbound.value("server", ""),
                                                      outbound.value("server_port", 0), {}});
                    continue;
                }
                if (!outbound.contains("server") || !outbound.contains("server_port")) {
                    note_skip(local, {},
                              SkippedSubscriptionNode{outbound.value("tag", ""), type, {}, 0,
                                                      "subscription line was skipped"});
                    continue;
                }
                if (type == "vless" && outbound.contains("encryption") && outbound["encryption"].is_string()) {
                    const auto encryption = outbound["encryption"].get<std::string>();
                    if (!encryption.empty() && encryption != "none") {
                        note_skip(local, {},
                                  SkippedSubscriptionNode{outbound.value("tag", ""), "vless", outbound.value("server", ""),
                                                          outbound.value("server_port", 0),
                                                          UnsupportedVlessEncryption(encryption_scheme(encryption), {}, {}, 0)
                                                              .what()});
                        continue;
                    }
                }
                auto copy = outbound;
                copy.erase("encryption");
                SubscriptionNode node;
                node.link.protocol = type;
                node.link.server = copy.at("server").get<std::string>();
                node.link.port = copy.at("server_port").get<int>();
                node.link.name = copy.value("tag", node.link.server);
                node.link.outbound = std::move(copy);
                node.id = proxy_node_id(node.link);
                nodes.push_back(std::move(node));
            }
        } else if (doc.contains("proxies") && doc["proxies"].is_array()) {
            for (const auto& proxy : doc["proxies"]) {
                try {
                    if (!proxy.is_object() || !proxy.contains("server") || !proxy.contains("port")) {
                        note_skip(local, {},
                                  SkippedSubscriptionNode{proxy.is_object() ? proxy.value("name", "") : "",
                                                          proxy.is_object() ? proxy.value("type", "") : "",
                                                          proxy.is_object() ? proxy.value("server", "") : "",
                                                          proxy.is_object() ? proxy.value("port", 0) : 0,
                                                          "subscription line was skipped"});
                        continue;
                    }
                    SubscriptionNode node;
                    node.link.outbound = clash_proxy_to_outbound(proxy);
                    node.link.protocol = node.link.outbound.at("type").get<std::string>();
                    node.link.server = node.link.outbound.at("server").get<std::string>();
                    node.link.port = node.link.outbound.at("server_port").get<int>();
                    node.link.name = proxy.value("name", node.link.server);
                    node.id = proxy_node_id(node.link);
                    nodes.push_back(std::move(node));
                } catch (const UnsupportedVlessEncryption& error) {
                    note_skip(local, {},
                              SkippedSubscriptionNode{error.name().empty() ? proxy.value("name", "") : error.name(),
                                                      "vless", error.server().empty() ? proxy.value("server", "") : error.server(),
                                                      error.port() == 0 ? proxy.value("port", 0) : error.port(), error.what()});
                } catch (const UnsupportedProxyTransport& error) {
                    note_skip(local, error.transport(),
                              SkippedSubscriptionNode{proxy.value("name", ""), proxy.value("type", ""),
                                                      proxy.value("server", ""), proxy.value("port", 0), error.what()});
                } catch (const std::exception& error) {
                    note_skip(local, {},
                              SkippedSubscriptionNode{proxy.value("name", ""), proxy.value("type", ""),
                                                      proxy.value("server", ""), proxy.value("port", 0), error.what()});
                }
            }
        } else {
            throw std::runtime_error("subscription JSON has no outbounds or proxies");
        }
    } else {
        std::string text = trimmed;
        if (looks_like_base64_list(text)) text = base64_decode(text);
        std::size_t pos = 0;
        while (pos < text.size()) {
            auto end = text.find('\n', pos);
            auto line = trim(text.substr(pos, end == std::string::npos ? std::string::npos : end - pos));
            if (!line.empty() && line.front() != '#' && line.front() != ';') add_link(line);
            if (end == std::string::npos) break;
            pos = end + 1;
        }
    }
    if (info != nullptr) *info = local;
    if (nodes.empty()) throw std::runtime_error("subscription did not contain a usable proxy");
    return nodes;
}

}  // namespace keen_pbr3
