#include "xray_config.hpp"

#include "link_parser.hpp"
#include "link_store.hpp"

#include <cctype>
#include <fstream>
#include <set>
#include <sstream>

namespace keen_pbr3 {
namespace {

std::string trim_copy(std::string text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.erase(text.begin());
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.pop_back();
    return text;
}

std::string percent_decode(const std::string& text) {
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '%' && i + 2 < text.size()) {
            auto hex = [](char c) {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int hi = hex(text[i + 1]);
            const int lo = hex(text[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        if (text[i] == '+') out.push_back(' ');
        else out.push_back(text[i]);
    }
    return out;
}

std::string query_value(const std::string& query, const std::string& key) {
    std::size_t pos = 0;
    while (pos < query.size()) {
        auto end = query.find('&', pos);
        auto part = query.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        auto eq = part.find('=');
        auto name = percent_decode(eq == std::string::npos ? part : part.substr(0, eq));
        if (name == key) return percent_decode(eq == std::string::npos ? std::string{} : part.substr(eq + 1));
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return {};
}

int parse_port(const std::string& text) {
    if (text.empty()) return 0;
    int port = 0;
    for (unsigned char c : text) {
        if (c < '0' || c > '9') return 0;
        port = port * 10 + (c - '0');
    }
    if (port <= 0 || port > 65535) return 0;
    return port;
}

bool parse_version(const std::string& text, int* major, int* minor, int* patch) {
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] < '0' || text[i] > '9') continue;
        int parts[3] = {0, 0, 0};
        int part = 0;
        bool any = false;
        for (; i < text.size() && part < 3; ++i) {
            if (text[i] >= '0' && text[i] <= '9') {
                parts[part] = parts[part] * 10 + (text[i] - '0');
                any = true;
            } else if (text[i] == '.' && part < 2) {
                ++part;
            } else {
                break;
            }
        }
        if (!any) continue;
        *major = parts[0];
        *minor = parts[1];
        *patch = parts[2];
        return true;
    }
    return false;
}

std::string token_of(const std::string& raw) {
    std::string token;
    for (unsigned char c : raw) {
        if (c >= 'A' && c <= 'Z') token.push_back(static_cast<char>(c - 'A' + 'a'));
        else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) token.push_back(static_cast<char>(c));
        else if (token.empty() || token.back() != '_') token.push_back('_');
    }
    while (!token.empty() && token.back() == '_') token.pop_back();
    while (!token.empty() && token.front() == '_') token.erase(token.begin());
    return token.empty() ? "n" : token;
}

XrayLinkView unsupported_protocol(const std::string& protocol) {
    XrayLinkView view;
    view.protocol = protocol;
    view.reason = "protocol " + (protocol.empty() ? "unknown" : protocol) + " is not supported by Xray";
    return view;
}

XrayLinkView parse_vless_for_xray(const std::string& rest) {
    const auto hash = rest.find('#');
    const auto main = hash == std::string::npos ? rest : rest.substr(0, hash);
    const auto name = hash == std::string::npos ? std::string{} : percent_decode(rest.substr(hash + 1));
    const auto qpos = main.find('?');
    const auto authority = qpos == std::string::npos ? main : main.substr(0, qpos);
    const auto query = qpos == std::string::npos ? std::string{} : main.substr(qpos + 1);
    const auto at = authority.rfind('@');
    if (at == std::string::npos) throw std::runtime_error("vless link has no server");
    auto user = percent_decode(authority.substr(0, at));
    auto hostport = authority.substr(at + 1);
    if (!hostport.empty() && hostport.front() == '[') {
        const auto end = hostport.find(']');
        if (end == std::string::npos) throw std::runtime_error("vless link address is invalid");
        // [ipv6]:port — keep the host, port follows.
    }
    std::string host;
    std::string port_text;
    if (!hostport.empty() && hostport.front() == '[') {
        const auto end = hostport.find(']');
        host = hostport.substr(1, end - 1);
        if (end + 1 < hostport.size() && hostport[end + 1] == ':') port_text = hostport.substr(end + 2);
    } else {
        const auto colon = hostport.rfind(':');
        if (colon == std::string::npos) throw std::runtime_error("vless link has no port");
        host = hostport.substr(0, colon);
        port_text = hostport.substr(colon + 1);
    }
    const int port = parse_port(port_text);
    if (host.empty() || port == 0) throw std::runtime_error("vless link address is invalid");
    if (user.empty()) throw std::runtime_error("vless link has no uuid");

    const auto network_raw = query_value(query, "type");
    const auto network = network_raw.empty() || network_raw == "none" ? "tcp" : network_raw;
    if (network != "tcp" && network != "ws" && network != "grpc" && network != "xhttp") {
        XrayLinkView view;
        view.protocol = "vless";
        view.name = name.empty() ? host : name;
        view.server = host;
        view.port = port;
        view.reason = "transport " + network + " is not supported by Xray";
        return view;
    }

    const auto encryption = query_value(query, "encryption");
    const auto flow = query_value(query, "flow");
    nlohmann::json user_json{{"id", user}, {"encryption", encryption.empty() ? "none" : encryption}};
    if (!flow.empty()) user_json["flow"] = flow;

    const auto security = query_value(query, "security");
    const auto pbk = query_value(query, "pbk");
    const auto sni = query_value(query, "sni");
    const auto fp = query_value(query, "fp");
    const auto sid = query_value(query, "sid");
    const auto spx = query_value(query, "spx");
    const auto pqv = query_value(query, "pqv");
    std::string security_value = "none";
    if (security == "reality" || !pbk.empty()) security_value = "reality";
    else if (security == "tls" || !sni.empty()) security_value = "tls";

    nlohmann::json stream{{"network", network}, {"security", security_value}};
    const auto path = query_value(query, "path");
    const auto host_header = query_value(query, "host");
    const auto mode = query_value(query, "mode");
    if (network == "ws") {
        nlohmann::json ws = nlohmann::json::object();
        if (!path.empty()) ws["path"] = path;
        // WebSocketConfig.Host; a "Host" key in headers is deprecated.
        if (!host_header.empty()) ws["host"] = host_header;
        if (!ws.empty()) stream["wsSettings"] = std::move(ws);
    } else if (network == "grpc") {
        const auto service = query_value(query, "serviceName");
        if (!service.empty()) stream["grpcSettings"] = {{"serviceName", service}};
    } else if (network == "xhttp") {
        nlohmann::json xhttp = nlohmann::json::object();
        if (!path.empty()) xhttp["path"] = path;
        if (!host_header.empty()) xhttp["host"] = host_header;
        if (!mode.empty()) xhttp["mode"] = mode;
        if (!xhttp.empty()) stream["xhttpSettings"] = std::move(xhttp);
    }
    if (security_value == "reality") {
        nlohmann::json reality{{"serverName", sni.empty() ? host : sni},
                               {"fingerprint", fp.empty() ? "chrome" : fp},
                               {"publicKey", pbk},
                               {"shortId", sid}};
        if (!spx.empty()) reality["spiderX"] = spx;
        // Xray 26.10 negotiates X25519MLKEM768. pqv is the optional ML-DSA verify key.
        if (!pqv.empty()) reality["mldsa65Verify"] = pqv;
        stream["realitySettings"] = std::move(reality);
    } else if (security_value == "tls") {
        nlohmann::json tls{{"serverName", sni.empty() ? host : sni}};
        if (!fp.empty()) tls["fingerprint"] = fp;
        const auto insecure = query_value(query, "allowInsecure");
        if (insecure == "1" || insecure == "true") tls["allowInsecure"] = true;
        stream["tlsSettings"] = std::move(tls);
    }

    XrayLinkView view;
    view.supported = true;
    view.protocol = "vless";
    view.name = name.empty() ? host : name;
    view.server = host;
    view.port = port;
    view.outbound = {{"protocol", "vless"},
                     {"settings",
                      {{"vnext",
                        nlohmann::json::array(
                            {{{"address", host}, {"port", port}, {"users", nlohmann::json::array({user_json})}}})}}},
                     {"streamSettings", std::move(stream)}};
    return view;
}

std::string json_string(const nlohmann::json& object, const char* key) {
    if (!object.is_object() || !object.contains(key) || !object.at(key).is_string()) return {};
    return object.at(key).get<std::string>();
}

int json_port(const nlohmann::json& object, const char* key) {
    if (!object.is_object() || !object.contains(key)) return 0;
    const auto& value = object.at(key);
    if (value.is_number_integer()) {
        const auto port = value.get<long long>();
        return port > 0 && port <= 65535 ? static_cast<int>(port) : 0;
    }
    if (value.is_string()) return parse_port(value.get<std::string>());
    return 0;
}

bool json_enabled(const nlohmann::json& object) {
    return object.is_object() && object.contains("enabled") && object.at("enabled").is_boolean() &&
           object.at("enabled").get<bool>();
}

// sing-box keeps HTTP headers as {"Host": "a"} or {"Host": ["a", "b"]}; host lists as a string or array.
std::string first_text(const nlohmann::json& value) {
    if (value.is_string()) return value.get<std::string>();
    if (value.is_array()) {
        for (const auto& item : value) {
            if (item.is_string() && !item.get<std::string>().empty()) return item.get<std::string>();
        }
    }
    return {};
}

std::string header_host(const nlohmann::json& transport) {
    if (!transport.contains("headers") || !transport.at("headers").is_object()) return {};
    for (const auto& item : transport.at("headers").items()) {
        auto key = item.key();
        for (char& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (key == "host") return first_text(item.value());
    }
    return {};
}

nlohmann::json xray_stream_from_singbox(const nlohmann::json& outbound, const std::string& server) {
    std::string network = "tcp";
    nlohmann::json stream = nlohmann::json::object();
    if (outbound.contains("transport") && outbound.at("transport").is_object()) {
        const auto& transport = outbound.at("transport");
        const auto type = json_string(transport, "type");
        const auto path = json_string(transport, "path");
        if (type.empty() || type == "tcp") {
            network = "tcp";
        } else if (type == "ws") {
            network = "ws";
            nlohmann::json ws = nlohmann::json::object();
            if (!path.empty()) ws["path"] = path;
            const auto host = header_host(transport);
            if (!host.empty()) ws["host"] = host;
            if (!ws.empty()) stream["wsSettings"] = std::move(ws);
        } else if (type == "grpc") {
            network = "grpc";
            const auto service = json_string(transport, "service_name");
            if (!service.empty()) stream["grpcSettings"] = {{"serviceName", service}};
        } else if (type == "httpupgrade") {
            network = "httpupgrade";
            nlohmann::json upgrade = nlohmann::json::object();
            if (!path.empty()) upgrade["path"] = path;
            auto host = transport.contains("host") ? first_text(transport.at("host")) : std::string{};
            if (host.empty()) host = header_host(transport);
            if (!host.empty()) upgrade["host"] = host;
            if (!upgrade.empty()) stream["httpupgradeSettings"] = std::move(upgrade);
        } else if (type == "http" || type == "xhttp") {
            // Xray removed the HTTP (h2) transport; its replacement is XHTTP stream-one.
            network = "xhttp";
            nlohmann::json xhttp = nlohmann::json::object();
            if (!path.empty()) xhttp["path"] = path;
            auto host = transport.contains("host") ? first_text(transport.at("host")) : std::string{};
            if (host.empty()) host = header_host(transport);
            if (!host.empty()) xhttp["host"] = host;
            auto mode = json_string(transport, "mode");
            if (mode.empty() && type == "http") mode = "stream-one";
            if (!mode.empty()) xhttp["mode"] = mode;
            if (!xhttp.empty()) stream["xhttpSettings"] = std::move(xhttp);
        } else {
            throw std::runtime_error("transport " + type + " is not supported by Xray");
        }
    }
    stream["network"] = network;
    std::string security = "none";
    const nlohmann::json tls = outbound.contains("tls") ? outbound.at("tls") : nlohmann::json::object();
    if (json_enabled(tls)) {
        const auto sni = json_string(tls, "server_name");
        std::string fingerprint;
        if (tls.contains("utls") && json_enabled(tls.at("utls"))) fingerprint = json_string(tls.at("utls"), "fingerprint");
        const nlohmann::json reality = tls.contains("reality") ? tls.at("reality") : nlohmann::json::object();
        if (json_enabled(reality)) {
            security = "reality";
            const auto public_key = json_string(reality, "public_key");
            if (public_key.empty()) throw std::runtime_error("reality public_key is missing");
            stream["realitySettings"] = {{"serverName", sni.empty() ? server : sni},
                                         {"fingerprint", fingerprint.empty() ? "chrome" : fingerprint},
                                         {"publicKey", public_key},
                                         {"shortId", json_string(reality, "short_id")}};
        } else {
            security = "tls";
            nlohmann::json settings{{"serverName", sni.empty() ? server : sni}};
            if (!fingerprint.empty()) settings["fingerprint"] = fingerprint;
            if (tls.contains("insecure") && tls.at("insecure").is_boolean() && tls.at("insecure").get<bool>()) {
                settings["allowInsecure"] = true;
            }
            if (tls.contains("alpn")) {
                nlohmann::json alpn = nlohmann::json::array();
                if (tls.at("alpn").is_string()) alpn.push_back(tls.at("alpn"));
                if (tls.at("alpn").is_array()) {
                    for (const auto& item : tls.at("alpn")) {
                        if (item.is_string()) alpn.push_back(item);
                    }
                }
                if (!alpn.empty()) settings["alpn"] = std::move(alpn);
            }
            stream["tlsSettings"] = std::move(settings);
        }
    }
    stream["security"] = security;
    return stream;
}

std::string first_cidr(const std::string& text) {
    std::string token;
    for (char c : text) {
        if (c == ',' || std::isspace(static_cast<unsigned char>(c))) {
            if (!token.empty()) return token;
        } else {
            token.push_back(c);
        }
    }
    return token;
}

}  // namespace

const char* tun_prefix_for_core(const std::string& core) { return core == "xray" ? "xrtun" : "sbtun"; }

std::string resolve_xray_binary(const std::string& configured) {
    if (!configured.empty()) return configured;
    for (const char* path : {"/opt/bin/xray", "/opt/usr/bin/xray", "/usr/bin/xray", "/usr/local/bin/xray"}) {
        std::ifstream probe(path);
        if (probe) return path;
    }
    return "xray";
}

bool xray_version_at_least(const std::string& text, int major, int minor, int patch) {
    int got_major = 0;
    int got_minor = 0;
    int got_patch = 0;
    if (!parse_version(text, &got_major, &got_minor, &got_patch)) return false;
    if (got_major != major) return got_major > major;
    if (got_minor != minor) return got_minor > minor;
    return got_patch >= patch;
}

long ram_total_kib(const std::string& meminfo) {
    std::istringstream input(meminfo);
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind("MemTotal:", 0) != 0) continue;
        long value = 0;
        for (unsigned char c : line) {
            if (c >= '0' && c <= '9') value = value * 10 + (c - '0');
        }
        return value;
    }
    return 0;
}

bool ram_below_xray_comfort(long kib) { return kib > 0 && kib < 384L * 1024L; }

XrayLinkView classify_link_for_core(const std::string& link, const std::string& core) {
    if (core != "xray") {
        XrayLinkView view;
        try {
            const auto parsed = parse_proxy_link(trim_copy(link));
            view.supported = true;
            view.protocol = parsed.protocol;
            view.name = parsed.name;
            view.server = parsed.server;
            view.port = parsed.port;
            view.outbound = parsed.outbound;
        } catch (const std::exception& error) {
            view.reason = error.what();
        }
        return view;
    }
    const auto trimmed = trim_copy(link);
    const auto scheme_end = trimmed.find("://");
    if (scheme_end == std::string::npos) {
        XrayLinkView view;
        view.reason = "protocol unknown is not supported by Xray";
        return view;
    }
    auto scheme = trimmed.substr(0, scheme_end);
    for (char& c : scheme) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (scheme != "vless") return unsupported_protocol(scheme);
    try {
        return parse_vless_for_xray(trimmed.substr(scheme_end + 3));
    } catch (const std::exception& error) {
        XrayLinkView view;
        view.protocol = "vless";
        view.reason = error.what();
        return view;
    }
}

nlohmann::json singbox_outbound_to_xray(const nlohmann::json& outbound) {
    if (!outbound.is_object()) throw std::runtime_error("saved node has no proxy data");
    const auto type = json_string(outbound, "type");
    if (type != "vless") {
        throw std::runtime_error("protocol " + (type.empty() ? std::string("unknown") : type) +
                                 " is not supported by Xray");
    }
    const auto server = json_string(outbound, "server");
    const int port = json_port(outbound, "server_port");
    const auto uuid = json_string(outbound, "uuid");
    if (server.empty() || port == 0) throw std::runtime_error("vless outbound address is invalid");
    if (uuid.empty()) throw std::runtime_error("vless outbound has no uuid");
    nlohmann::json user{{"id", uuid}, {"encryption", "none"}};
    const auto flow = json_string(outbound, "flow");
    if (!flow.empty()) user["flow"] = flow;
    // packet_encoding: Xray VLESS uses XUDP for UDP by default, which is what
    // sing-box "xudp" asks for. "packetaddr" has no Xray client equivalent.
    const auto packet_encoding = json_string(outbound, "packet_encoding");
    if (packet_encoding == "packetaddr") {
        throw std::runtime_error("packet_encoding packetaddr is not supported by Xray");
    }
    return {{"protocol", "vless"},
            {"settings",
             {{"vnext", nlohmann::json::array(
                            {{{"address", server}, {"port", port}, {"users", nlohmann::json::array({user})}}})}}},
            {"streamSettings", xray_stream_from_singbox(outbound, server)}};
}

XrayLinkView classify_node_for_core(const SingboxNode& node, const std::string& core) {
    if (!trim_copy(node.link).empty()) return classify_link_for_core(node.link, core);
    XrayLinkView view;
    view.name = node.name;
    view.server = node.server;
    view.port = node.port;
    const auto& outbound = node.outbound;
    const auto type = json_string(outbound, "type");
    const auto xray_protocol = json_string(outbound, "protocol");
    view.protocol = !type.empty() ? type : (!xray_protocol.empty() ? xray_protocol : node.protocol);
    if (!outbound.is_object()) {
        view.reason = "protocol " + (view.protocol.empty() ? std::string("unknown") : view.protocol) +
                      " has no saved proxy data";
        return view;
    }
    if (core != "xray") {
        // sing-box reads its own outbound. An Xray-only outbound needs the link.
        if (!type.empty()) {
            view.supported = true;
            view.outbound = outbound;
        } else {
            view.reason = "protocol " + (view.protocol.empty() ? std::string("unknown") : view.protocol) +
                          " has no sing-box data; refresh the subscription";
        }
        return view;
    }
    if (type.empty() && xray_protocol == "vless") {
        view.supported = true;
        view.outbound = outbound;
        view.outbound.erase("tag");
        return view;
    }
    try {
        view.outbound = singbox_outbound_to_xray(outbound);
        view.supported = true;
    } catch (const std::exception& error) {
        view.outbound = nullptr;
        view.reason = error.what();
    }
    return view;
}

std::vector<std::string> xray_tun_interfaces(const nlohmann::json& config) {
    std::vector<std::string> names;
    if (!config.is_object() || !config.contains("inbounds") || !config.at("inbounds").is_array()) return names;
    for (const auto& inbound : config.at("inbounds")) {
        if (!inbound.is_object() || json_string(inbound, "protocol") != "tun") continue;
        if (!inbound.contains("settings")) continue;
        const auto name = json_string(inbound.at("settings"), "name");
        if (!name.empty()) names.push_back(name);
    }
    return names;
}

nlohmann::json render_xray_config(const std::vector<SingboxNode>& nodes, bool allow_empty) {
    nlohmann::json inbounds = nlohmann::json::array();
    nlohmann::json outbounds = nlohmann::json::array();
    nlohmann::json rules = nlohmann::json::array();
    std::set<int> used_octets;
    auto take_octet = [&](const std::string& cidr) {
        // 172.19.X.1/30
        const auto second = cidr.find('.', cidr.find('.') + 1);
        if (second == std::string::npos) return;
        int octet = 0;
        for (std::size_t i = second + 1; i < cidr.size() && cidr[i] >= '0' && cidr[i] <= '9'; ++i) {
            octet = octet * 10 + (cidr[i] - '0');
        }
        if (octet > 0) used_octets.insert(octet);
    };
    for (const auto& node : nodes) {
        if (node.unsupported) continue;
        take_octet(first_cidr(node.tun_address));
    }
    int fallback_octet = 1;
    for (const auto& node : nodes) {
        if (node.unsupported || node.interface_name.empty()) continue;
        const auto view = classify_node_for_core(node, "xray");
        if (!view.supported) {
            // Never write a config that silently drops a TUN keen-pbr-sx routes to.
            throw std::runtime_error("Xray config has no outbound for " + node.tag + " (" + node.interface_name +
                                     "): " + (view.reason.empty() ? std::string("unsupported") : view.reason));
        }
        const auto id = token_of(node.id);
        const auto inbound_tag = "kpbr-tun-" + id;
        const auto outbound_tag = "kpbr-n-" + id;
        std::string gateway = first_cidr(node.tun_address);
        if (gateway.empty()) {
            while (used_octets.count(fallback_octet) && fallback_octet < 200) ++fallback_octet;
            gateway = "172.19." + std::to_string(fallback_octet) + ".1/30";
            used_octets.insert(fallback_octet);
            ++fallback_octet;
        }
        const int mtu = node.tun_mtu > 0 ? node.tun_mtu : 1400;
        inbounds.push_back({{"port", 0},
                            {"protocol", "tun"},
                            {"tag", inbound_tag},
                            {"settings",
                             {{"name", node.interface_name},
                              {"mtu", mtu},
                              // TunConfig.Gateway is []string. keen-pbr-sx routes into the
                              // TUN itself, so autoSystemRoutingTable (also []string, not a
                              // bool) and autoSystemDnsToGateway are left out.
                              {"gateway", nlohmann::json::array({gateway})}}}});
        auto outbound = view.outbound;
        outbound["tag"] = outbound_tag;
        outbounds.push_back(std::move(outbound));
        rules.push_back({{"type", "field"},
                         {"inboundTag", nlohmann::json::array({inbound_tag})},
                         {"outboundTag", outbound_tag}});
    }
    if (inbounds.empty() && !allow_empty) {
        throw std::runtime_error("Xray config has no TUN inbounds: no node can be carried by Xray");
    }
    outbounds.push_back({{"protocol", "freedom"}, {"tag", "direct"}});
    return {{"log", {{"loglevel", "warning"}, {"error", kXrayLogPath}, {"access", "none"}}},
            {"inbounds", std::move(inbounds)},
            {"outbounds", std::move(outbounds)},
            {"routing", {{"domainStrategy", "AsIs"}, {"rules", std::move(rules)}}}};
}

}  // namespace keen_pbr3
