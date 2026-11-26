#include "link_store.hpp"
#include "xray_config.hpp"
#include "link_parser.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

std::string trim(std::string text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.erase(text.begin());
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.pop_back();
    return text;
}

std::string lower_copy(std::string text) {
    for (char& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text;
}

bool blank(const std::string& text) {
    for (unsigned char c : text) {
        if (!std::isspace(c)) return false;
    }
    return true;
}

std::string read_file(const std::string& path) {
    std::ifstream input(path);
    if (!input) return {};
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

void mkdir_parents(const std::string& dir) {
    std::string current;
    for (char c : dir) {
        current.push_back(c);
        if (c == '/' && current.size() > 1) ::mkdir(current.c_str(), 0750);
    }
    if (!dir.empty()) ::mkdir(dir.c_str(), 0750);
}

void write_private(const std::string& path, const std::string& body) {
    const auto slash = path.find_last_of('/');
    if (slash != std::string::npos) mkdir_parents(path.substr(0, slash));
    const auto temp = path + ".tmp";
    const int fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0) throw std::runtime_error("cannot write " + path);
    struct stat info{};
    bool ok = ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1 &&
              ::fchmod(fd, 0600) == 0 && ::ftruncate(fd, 0) == 0;
    for (std::size_t offset = 0; ok && offset < body.size();) {
        const auto count = ::write(fd, body.data() + offset, body.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) ok = false;
        else offset += static_cast<std::size_t>(count);
    }
    if (::close(fd) != 0) ok = false;
    if (!ok) {
        ::unlink(temp.c_str());
        throw std::runtime_error("cannot write " + path);
    }
    if (::rename(temp.c_str(), path.c_str()) != 0) {
        ::unlink(temp.c_str());
        throw std::runtime_error("cannot replace " + path);
    }
}

// Xray infers config format from the extension; sidecar names must end in .json.
std::string json_sidecar(const std::string& path, const std::string& role) {
    static const std::string ext = ".json";
    if (path.size() >= ext.size() && path.compare(path.size() - ext.size(), ext.size(), ext) == 0) {
        return path.substr(0, path.size() - ext.size()) + "." + role + ".json";
    }
    return path + "." + role + ".json";
}

std::string path_basename(const std::string& path) {
    const auto slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

// Only Xray sidecars need a trailing .json; sing-box check accepts any name, and
// existing routers already have config.json.bak-keenpbr.
bool xray_json_path(const std::string& path) { return path_basename(path) == "xray.json"; }

std::string backup_of(const std::string& path) {
    return xray_json_path(path) ? json_sidecar(path, "bak-keenpbr") : path + ".bak-keenpbr";
}

std::string original_backup_of(const std::string& path) {
    return xray_json_path(path) ? json_sidecar(path, "bak-keenpbr-original")
                                : path + ".bak-keenpbr-original";
}

std::string candidate_of(const std::string& path) {
    return xray_json_path(path) ? json_sidecar(path, "candidate") : path + ".candidate";
}

bool backup_file(const std::string& path) {
    const auto body = read_file(path);
    if (!body.empty() || ::access(path.c_str(), F_OK) == 0) {
        write_private(backup_of(path), body);
        return true;
    }
    return false;
}

void preserve_original_config(const std::string& path) {
    const auto original = original_backup_of(path);
    if (::access(original.c_str(), F_OK) == 0) return;
    if (::access(path.c_str(), F_OK) != 0) return;
    const auto body = read_file(path);
    if (body.empty()) return;
    write_private(original, body);
}

void restore_backup(const std::string& path, bool had_config) {
    if (!had_config) {
        if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
            throw std::runtime_error("cannot remove candidate sing-box config");
        }
        return;
    }
    const auto body = read_file(backup_of(path));
    write_private(path, body);
}

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool is_hex(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }

bool is_uuid_at(const std::string& text, std::size_t index) {
    if (index + 36 > text.size()) return false;
    const int groups[] = {8, 4, 4, 4, 12};
    std::size_t cursor = index;
    for (int group = 0; group < 5; ++group) {
        if (group != 0) {
            if (text[cursor] != '-') return false;
            ++cursor;
        }
        for (int digit = 0; digit < groups[group]; ++digit) {
            if (!is_hex(text[cursor])) return false;
            ++cursor;
        }
    }
    return true;
}

void redact_uuids(std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size();) {
        if (is_uuid_at(text, i)) {
            out += "***";
            i += 36;
        } else {
            out.push_back(text[i]);
            ++i;
        }
    }
    text.swap(out);
}

void redact_json_field(std::string& text, const std::string& key) {
    const std::string pattern = "\"" + key + "\"";
    std::size_t pos = 0;
    while ((pos = text.find(pattern, pos)) != std::string::npos) {
        const auto colon = text.find(':', pos + pattern.size());
        if (colon == std::string::npos || colon > pos + pattern.size() + 8) {
            pos += pattern.size();
            continue;
        }
        const auto open = text.find('"', colon + 1);
        if (open == std::string::npos) return;
        const auto close = text.find('"', open + 1);
        if (close == std::string::npos) return;
        text.replace(open + 1, close - open - 1, "***");
        pos = open + 4;
    }
}

void redact_query_param(std::string& text, const std::string& key) {
    const std::string pattern = key + "=";
    std::size_t pos = 0;
    while ((pos = text.find(pattern, pos)) != std::string::npos) {
        if (pos > 0) {
            const unsigned char previous = static_cast<unsigned char>(text[pos - 1]);
            if (std::isalnum(previous) || previous == '_' || previous == '-') {
                pos += pattern.size();
                continue;
            }
        }
        const auto start = pos + pattern.size();
        auto end = start;
        while (end < text.size() && text[end] != '&' && !std::isspace(static_cast<unsigned char>(text[end])) &&
               text[end] != '"' && text[end] != '\'') {
            ++end;
        }
        text.replace(start, end - start, "***");
        pos = start + 3;
    }
}

void redact_urls(std::string& text) {
    for (const char* scheme : {"https://", "http://"}) {
        const auto length = std::char_traits<char>::length(scheme);
        std::size_t pos = 0;
        while ((pos = text.find(scheme, pos)) != std::string::npos) {
            auto end = pos + length;
            while (end < text.size() && !std::isspace(static_cast<unsigned char>(text[end])) && text[end] != '"' &&
                   text[end] != '\'') {
                ++end;
            }
            text.replace(pos + length, end - (pos + length), "***");
            pos += length + 3;
        }
    }
}

std::string redact_secrets(std::string text) {
    redact_urls(text);
    redact_uuids(text);
    for (const char* key : {"password", "uuid", "public_key", "private_key", "short_id", "token", "auth"}) {
        redact_json_field(text, key);
    }
    for (const char* key : {"password", "obfs-password", "pbk", "sid", "encryption"}) {
        redact_query_param(text, key);
    }
    if (text.size() > 500) text.resize(500);
    return text;
}

std::string prominent_line(const std::string& output) {
    std::string first;
    std::size_t pos = 0;
    while (pos < output.size()) {
        const auto end = output.find('\n', pos);
        auto line = trim(output.substr(pos, end == std::string::npos ? std::string::npos : end - pos));
        if (line.find("FATAL") != std::string::npos || line.find("ERROR") != std::string::npos) return line;
        if (first.empty() && !line.empty()) first = std::move(line);
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return first.empty() ? "invalid configuration" : first;
}

void require_stack(const std::string& stack) {
    if (stack != "gvisor" && stack != "system") throw std::runtime_error("TUN stack must be gvisor or system");
}

void require_mtu(int mtu) {
    if (mtu < 576 || mtu > 65535) throw std::runtime_error("TUN MTU must be between 576 and 65535");
}

bool safe_cidr(const std::string& cidr) {
    if (cidr.size() < 3 || cidr.size() > 64) return false;
    int slashes = 0;
    for (unsigned char c : cidr) {
        const bool ok = std::isxdigit(c) || c == '.' || c == ':' || c == '/';
        if (!ok) return false;
        if (c == '/') ++slashes;
    }
    return slashes == 1;
}

int tun_subnet_octet(const std::string& cidr) {
    const std::string prefix = "172.19.";
    if (cidr.rfind(prefix, 0) != 0) return 0;
    int octet = 0;
    std::size_t index = prefix.size();
    if (index >= cidr.size() || !std::isdigit(static_cast<unsigned char>(cidr[index]))) return 0;
    while (index < cidr.size() && std::isdigit(static_cast<unsigned char>(cidr[index]))) {
        octet = octet * 10 + (cidr[index] - '0');
        if (octet > 255) return 0;
        ++index;
    }
    return octet >= 1 && octet <= 200 ? octet : 0;
}

void note_tun_address(std::set<int>& used, const nlohmann::json& address) {
    if (address.is_string()) {
        const int octet = tun_subnet_octet(address.get<std::string>());
        if (octet > 0) used.insert(octet);
    } else if (address.is_array()) {
        for (const auto& item : address) {
            if (!item.is_string()) continue;
            const int octet = tun_subnet_octet(item.get<std::string>());
            if (octet > 0) used.insert(octet);
        }
    }
}

std::vector<std::string> split_addresses(const std::string& text) {
    std::vector<std::string> out;
    std::string token;
    for (char c : text) {
        if (c == ',' || std::isspace(static_cast<unsigned char>(c))) {
            if (!token.empty()) {
                out.push_back(token);
                token.clear();
            }
        } else {
            token.push_back(c);
        }
    }
    if (!token.empty()) out.push_back(token);
    return out;
}

void require_addresses(const std::string& text) {
    for (const auto& cidr : split_addresses(text)) {
        if (!safe_cidr(cidr)) throw std::runtime_error("TUN address is invalid");
    }
}

std::string singbox_token(const std::string& raw);

std::string next_free_interface(const nlohmann::json& existing, const std::vector<SingboxNode>& nodes,
                                const std::string& self_id, const std::string& prefix) {
    std::set<std::string> used;
    for (const auto& node : nodes) {
        if (node.id == self_id || node.interface_name.empty()) continue;
        used.insert(node.interface_name);
    }
    if (existing.contains("inbounds") && existing["inbounds"].is_array()) {
        for (const auto& inbound : existing["inbounds"]) {
            if (!inbound.is_object()) continue;
            const auto tag = inbound.value("tag", "");
            if (!self_id.empty() && tag == "kpbr-tun-" + singbox_token(self_id)) continue;
            const auto iface = inbound.value("interface_name", "");
            if (!iface.empty()) used.insert(iface);
        }
    }
    if (!used.count(prefix)) return prefix;
    for (int number = 2; number < 1000; ++number) {
        const auto name = prefix + std::to_string(number);
        if (name.size() > 15) break;
        if (!used.count(name)) return name;
    }
    throw std::runtime_error("no free TUN interface name");
}

int next_free_tun_octet(std::set<int>& used) {
    for (int octet = 1; octet <= 200; ++octet) {
        if (!used.count(octet)) {
            used.insert(octet);
            return octet;
        }
    }
    throw std::runtime_error("no free TUN address in 172.19.0.0/16");
}

std::string interface_taken_message(const std::string& iface) {
    return "TUN interface " + iface +
           " already exists in the sing-box config and is not managed by keen-pbr-sx. "
           "The existing config was not changed. Choose another interface name.";
}

std::string singbox_token(const std::string& raw) {
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

std::string node_outbound_tag(const SingboxNode& node) { return "kpbr-n-" + singbox_token(node.id); }

std::string node_inbound_tag(const SingboxNode& node) { return "kpbr-tun-" + singbox_token(node.id); }

bool is_managed_tag(const std::string& tag) { return tag.rfind("kpbr-", 0) == 0; }

std::string endpoint_identity(const std::string& protocol, const std::string& server, int port) {
    return "endpoint:" + lower_copy(protocol) + "|" + lower_copy(server) + "|" + std::to_string(port);
}

std::string name_identity(const std::string& name) { return "name:" + lower_copy(trim(name)); }

std::string fnv_hex(const std::string& text) {
    std::uint64_t hash = 1469598103934665603ull;
    for (unsigned char c : text) {
        hash ^= c;
        hash *= 1099511628211ull;
    }
    std::ostringstream out;
    out << std::hex << hash;
    return out.str();
}

bool tag_used(const std::vector<SingboxNode>& nodes, const std::string& tag, const std::string& self_id) {
    return std::any_of(nodes.begin(), nodes.end(), [&](const SingboxNode& node) {
        return node.id != self_id && node.tag == tag;
    });
}

std::string allocate_tag(const std::string& name, const std::vector<SingboxNode>& nodes, const std::string& self_id) {
    const auto base = sanitize_keenetic_tag(name.empty() ? "node" : name);
    if (!tag_used(nodes, base, self_id)) return base;
    for (int number = 2; number < 1000; ++number) {
        const auto suffix = "_" + std::to_string(number);
        auto candidate = base;
        if (candidate.size() + suffix.size() > 24) {
            candidate.resize(24 - suffix.size());
            while (!candidate.empty() && candidate.back() == '_') candidate.pop_back();
        }
        if (candidate.empty() || candidate.front() < 'a' || candidate.front() > 'z') candidate = "n";
        candidate += suffix;
        if (!tag_used(nodes, candidate, self_id)) return candidate;
    }
    throw std::runtime_error("keen-pbr-sx tag is already used");
}

std::string allocate_id(const std::string& material, const std::string& prefix,
                        const std::vector<SingboxNode>& nodes) {
    const auto hex = fnv_hex(material);
    const auto base = prefix + hex.substr(0, std::min<std::size_t>(10, hex.size()));
    const auto used = [&](const std::string& id) {
        return std::any_of(nodes.begin(), nodes.end(), [&](const SingboxNode& node) { return node.id == id; });
    };
    if (!used(base)) return base;
    for (int number = 2; number < 1000; ++number) {
        const auto candidate = base + std::to_string(number);
        if (!used(candidate)) return candidate;
    }
    throw std::runtime_error("could not allocate a node id");
}

void assign_identities(std::vector<SingboxNode>& nodes) {
    std::set<std::string> used;
    for (auto& node : nodes) {
        auto identity = trim(node.name).empty() ? endpoint_identity(node.protocol, node.server, node.port)
                                                 : name_identity(node.name);
        if (used.count(identity)) identity = endpoint_identity(node.protocol, node.server, node.port);
        const auto base = identity;
        for (int number = 2; used.count(identity) && number < 1000; ++number) {
            identity = base + "#" + std::to_string(number);
        }
        used.insert(identity);
        node.identity = identity;
    }
}

const SingboxNode* match_fresh(const SingboxNode& have, const std::vector<SingboxNode>& fresh,
                               std::set<std::size_t>& used) {
    const auto take = [&](auto pred) -> const SingboxNode* {
        for (std::size_t i = 0; i < fresh.size(); ++i) {
            if (used.count(i) || !pred(fresh[i])) continue;
            used.insert(i);
            return &fresh[i];
        }
        return nullptr;
    };
    if (auto* found = take([&](const SingboxNode& node) { return node.identity == have.identity; })) return found;
    if (!trim(have.name).empty()) {
        const auto name = lower_copy(trim(have.name));
        if (auto* found = take([&](const SingboxNode& node) { return lower_copy(trim(node.name)) == name; })) {
            return found;
        }
    }
    return take([&](const SingboxNode& node) {
        return lower_copy(node.protocol) == lower_copy(have.protocol) &&
               lower_copy(node.server) == lower_copy(have.server) && node.port == have.port;
    });
}

nlohmann::json outbound_for(const SingboxNode& node) {
    nlohmann::json outbound;
    if (!node.link.empty()) {
        try {
            outbound = parse_proxy_link(node.link).outbound;
        } catch (const std::exception&) {
            if (node.outbound.is_object()) outbound = node.outbound;
            else throw;
        }
    } else if (node.outbound.is_object()) outbound = node.outbound;
    else throw std::runtime_error("saved node has no proxy data");
    outbound["tag"] = node_outbound_tag(node);
    return outbound;
}

bool unmanaged_remains(const nlohmann::json& original) {
    for (const char* key : {"dns", "experimental", "endpoints", "services"}) {
        if (original.contains(key) && !original.at(key).is_null()) return true;
    }
    const auto kept = [](const nlohmann::json& value, const char* tag_key) {
        return !value.is_object() || !is_managed_tag(value.value(tag_key, ""));
    };
    if (original.contains("inbounds") && original["inbounds"].is_array()) {
        for (const auto& inbound : original["inbounds"]) {
            if (kept(inbound, "tag")) return true;
        }
    }
    if (original.contains("outbounds") && original["outbounds"].is_array()) {
        for (const auto& outbound : original["outbounds"]) {
            if (kept(outbound, "tag")) return true;
        }
    }
    if (original.contains("route") && original["route"].is_object() && original["route"].contains("rules") &&
        original["route"]["rules"].is_array()) {
        for (const auto& rule : original["route"]["rules"]) {
            if (!rule.is_object()) return true;
            if (!is_managed_tag(rule.value("inbound", "")) && !is_managed_tag(rule.value("outbound", ""))) return true;
        }
    }
    for (auto it = original.begin(); it != original.end(); ++it) {
        const std::string key = it.key();
        if (key != "log" && key != "inbounds" && key != "outbounds" && key != "route") return true;
    }
    return false;
}

nlohmann::json merge_singbox_config(const nlohmann::json& existing, const std::vector<SingboxNode>& live,
                                    bool* remove_file) {
    nlohmann::json kept_inbounds = nlohmann::json::array();
    if (existing.contains("inbounds") && existing["inbounds"].is_array()) {
        for (const auto& inbound : existing["inbounds"]) {
            if (!inbound.is_object() || !is_managed_tag(inbound.value("tag", ""))) kept_inbounds.push_back(inbound);
        }
    }
    for (const auto& node : live) {
        for (const auto& inbound : kept_inbounds) {
            if (!inbound.is_object()) continue;
            if (inbound.value("interface_name", "") == node.interface_name) {
                throw std::runtime_error(interface_taken_message(node.interface_name));
            }
        }
    }
    nlohmann::json kept_outbounds = nlohmann::json::array();
    if (existing.contains("outbounds") && existing["outbounds"].is_array()) {
        for (const auto& outbound : existing["outbounds"]) {
            if (!outbound.is_object() || !is_managed_tag(outbound.value("tag", ""))) kept_outbounds.push_back(outbound);
        }
    }
    nlohmann::json kept_rules = nlohmann::json::array();
    nlohmann::json route = existing.contains("route") && existing["route"].is_object() ? existing["route"]
                                                                                        : nlohmann::json::object();
    if (route.contains("rules") && route["rules"].is_array()) {
        for (const auto& rule : route["rules"]) {
            if (!rule.is_object()) {
                kept_rules.push_back(rule);
                continue;
            }
            if (is_managed_tag(rule.value("inbound", "")) || is_managed_tag(rule.value("outbound", ""))) continue;
            kept_rules.push_back(rule);
        }
    }

    nlohmann::json managed_inbounds = nlohmann::json::array();
    nlohmann::json managed_outbounds = nlohmann::json::array();
    std::set<int> used_octets;
    for (const auto& inbound : kept_inbounds) {
        if (inbound.is_object() && inbound.contains("address")) note_tun_address(used_octets, inbound["address"]);
    }
    for (const auto& node : live) {
        for (const auto& cidr : split_addresses(node.tun_address)) {
            const int octet = tun_subnet_octet(cidr);
            if (octet > 0) used_octets.insert(octet);
        }
    }
    for (const auto& node : live) {
        managed_outbounds.push_back(outbound_for(node));
        const auto inbound = node_inbound_tag(node);
        kept_rules.push_back({{"inbound", inbound}, {"outbound", node_outbound_tag(node)}});
        auto addresses = split_addresses(node.tun_address);
        nlohmann::json address_json = nlohmann::json::array();
        if (addresses.empty()) {
            const int octet = next_free_tun_octet(used_octets);
            address_json.push_back("172.19." + std::to_string(octet) + ".1/30");
        } else {
            for (const auto& cidr : addresses) address_json.push_back(cidr);
        }
        const int mtu = node.tun_mtu > 0 ? node.tun_mtu : 1400;
        managed_inbounds.push_back({
            {"type", "tun"},
            {"tag", inbound},
            {"interface_name", node.interface_name},
            {"address", std::move(address_json)},
            {"mtu", mtu},
            {"auto_route", false},
            {"strict_route", false},
            {"stack", node.tun_stack == "system" ? "system" : "gvisor"},
        });
    }
    const bool live_nodes = !live.empty();
    if (remove_file != nullptr) *remove_file = !live_nodes && !unmanaged_remains(existing);

    nlohmann::json result = existing.is_object() ? existing : nlohmann::json::object();
    nlohmann::json inbounds = kept_inbounds;
    for (auto& inbound : managed_inbounds) inbounds.push_back(std::move(inbound));
    nlohmann::json outbounds = kept_outbounds;
    for (auto& outbound : managed_outbounds) outbounds.push_back(std::move(outbound));
    if (route.contains("final") && route["final"].is_string() && is_managed_tag(route["final"].get<std::string>())) {
        route.erase("final");
    }
    if (live_nodes && kept_outbounds.empty() && !route.contains("final")) {
        outbounds.push_back({{"type", "direct"}, {"tag", "kpbr-direct"}});
        route["final"] = "kpbr-direct";
    }
    if (live_nodes && !route.contains("auto_detect_interface")) route["auto_detect_interface"] = true;
    route["rules"] = std::move(kept_rules);
    if (!inbounds.empty()) result["inbounds"] = std::move(inbounds);
    else result.erase("inbounds");
    if (!outbounds.empty()) result["outbounds"] = std::move(outbounds);
    else result.erase("outbounds");
    if ((route.contains("rules") && route["rules"].is_array() && !route["rules"].empty()) || route.contains("final") ||
        route.contains("auto_detect_interface")) {
        result["route"] = std::move(route);
    } else {
        result.erase("route");
    }
    if (live_nodes && !result.contains("log")) result["log"] = {{"level", "warn"}, {"timestamp", true}};
    return result;
}

std::vector<std::string> split_links(const std::vector<std::string>& links) {
    std::vector<std::string> lines;
    for (const auto& chunk : links) {
        std::size_t pos = 0;
        while (pos < chunk.size()) {
            const auto end = chunk.find('\n', pos);
            auto line = trim(chunk.substr(pos, end == std::string::npos ? std::string::npos : end - pos));
            if (!line.empty()) lines.push_back(std::move(line));
            if (end == std::string::npos) break;
            pos = end + 1;
        }
    }
    return lines;
}

bool is_http_url(const std::string& line) {
    return line.rfind("http://", 0) == 0 || line.rfind("https://", 0) == 0;
}

std::string host_of(const std::string& url) {
    auto rest = url;
    const auto scheme = rest.find("://");
    if (scheme != std::string::npos) rest = rest.substr(scheme + 3);
    const auto slash = rest.find('/');
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    const auto at = rest.rfind('@');
    if (at != std::string::npos) rest = rest.substr(at + 1);
    const auto colon = rest.find(':');
    if (colon != std::string::npos) rest = rest.substr(0, colon);
    return rest.empty() ? "subscription" : rest;
}

void apply_tun(SingboxNode& node, const SingboxTunOptions& tun) {
    const auto stack = tun.tun_stack.empty() ? "gvisor" : tun.tun_stack;
    require_stack(stack);
    const int mtu = tun.tun_mtu == 0 ? 1400 : tun.tun_mtu;
    require_mtu(mtu);
    require_addresses(tun.tun_address);
    node.tun_stack = stack;
    node.tun_mtu = mtu;
    node.tun_address = tun.tun_address;
}

SingboxNode node_from_parsed(ParsedProxyLink parsed, std::string link) {
    SingboxNode node;
    node.name = parsed.name.empty() ? parsed.server : parsed.name;
    node.protocol = parsed.protocol;
    node.server = parsed.server;
    node.port = parsed.port;
    node.link = std::move(link);
    node.outbound = std::move(parsed.outbound);
    return node;
}

nlohmann::json catalog_json(const SingboxCatalogEntry& entry) {
    return {{"identity", entry.identity},
            {"name", entry.name},
            {"protocol", entry.protocol},
            {"server", entry.server},
            {"port", entry.port},
            {"skipped", entry.skipped},
            {"reason", entry.reason}};
}

SingboxCatalogEntry catalog_from_json(const nlohmann::json& json) {
    SingboxCatalogEntry entry;
    entry.identity = json.value("identity", "");
    entry.name = json.value("name", "");
    entry.protocol = json.value("protocol", "");
    entry.server = json.value("server", "");
    entry.port = json.value("port", 0);
    entry.skipped = json.value("skipped", false);
    entry.reason = json.value("reason", "");
    return entry;
}

nlohmann::json node_json(const SingboxNode& node, bool with_secret) {
    nlohmann::json json{{"id", node.id},
                        {"name", node.name},
                        {"tag", node.tag},
                        {"protocol", node.protocol},
                        {"server", node.server},
                        {"port", node.port},
                        {"interface", node.interface_name},
                        {"tun_stack", node.tun_stack},
                        {"tun_mtu", node.tun_mtu},
                        {"tun_address", node.tun_address},
                        {"subscription_id", node.subscription_id},
                        {"identity", node.identity},
                        {"missing", node.missing},
                        {"unsupported", node.unsupported},
                        {"unsupported_reason", node.unsupported_reason},
                        {"source", node.subscription_id.empty() ? "link" : "subscription"}};
    if (with_secret) {
        if (!node.link.empty()) json["link"] = node.link;
        if (!node.outbound.is_null()) json["outbound"] = node.outbound;
    }
    return json;
}

SingboxNode node_from_json(const nlohmann::json& json) {
    SingboxNode node;
    node.id = json.value("id", "");
    node.name = json.value("name", "");
    node.tag = json.value("tag", "");
    node.protocol = json.value("protocol", "");
    node.server = json.value("server", "");
    node.port = json.value("port", 0);
    node.interface_name = json.value("interface", "");
    node.tun_stack = json.value("tun_stack", "gvisor");
    node.tun_mtu = json.value("tun_mtu", 1400);
    node.tun_address = json.value("tun_address", "");
    node.subscription_id = json.value("subscription_id", "");
    node.identity = json.value("identity", "");
    node.missing = json.value("missing", false);
    node.unsupported = json.value("unsupported", false);
    node.unsupported_reason = json.value("unsupported_reason", "");
    node.link = json.value("link", "");
    if (json.contains("outbound")) node.outbound = json["outbound"];
    if (node.identity.empty()) {
        node.identity = trim(node.name).empty() ? endpoint_identity(node.protocol, node.server, node.port)
                                                 : name_identity(node.name);
    }
    return node;
}

nlohmann::json subscription_json(const SingboxSubscription& subscription, bool with_secret) {
    nlohmann::json catalog = nlohmann::json::array();
    for (const auto& entry : subscription.catalog) catalog.push_back(catalog_json(entry));
    nlohmann::json json{{"id", subscription.id},
                        {"name", subscription.name},
                        {"interval_hours", subscription.interval_hours},
                        {"last_refresh", subscription.last_refresh},
                        {"last_error", subscription.last_error},
                        {"selected", subscription.selected},
                        {"new_nodes", subscription.new_nodes},
                        {"catalog", std::move(catalog)}};
    if (with_secret) json["url"] = subscription.url;
    return json;
}

SingboxSubscription subscription_from_json(const nlohmann::json& json) {
    SingboxSubscription subscription;
    subscription.id = json.value("id", "");
    subscription.url = json.value("url", "");
    subscription.name = json.value("name", host_of(subscription.url));
    subscription.interval_hours = json.value("interval_hours", 0);
    subscription.last_refresh = json.value("last_refresh", static_cast<std::int64_t>(0));
    subscription.last_error = json.value("last_error", "");
    subscription.new_nodes = json.value("new_nodes", 0);
    if (json.contains("selected") && json["selected"].is_array()) {
        for (const auto& item : json["selected"]) {
            if (item.is_string()) subscription.selected.push_back(item.get<std::string>());
        }
    }
    if (json.contains("catalog") && json["catalog"].is_array()) {
        for (const auto& item : json["catalog"]) subscription.catalog.push_back(catalog_from_json(item));
    }
    return subscription;
}

nlohmann::json store_json(const SingboxStore& store, bool with_secret) {
    nlohmann::json nodes = nlohmann::json::array();
    nlohmann::json subscriptions = nlohmann::json::array();
    for (const auto& node : store.nodes) nodes.push_back(node_json(node, with_secret));
    for (const auto& subscription : store.subscriptions) {
        subscriptions.push_back(subscription_json(subscription, with_secret));
    }
    return {{"nodes", std::move(nodes)}, {"subscriptions", std::move(subscriptions)}};
}

SingboxNode migrate_connection(const nlohmann::json& json) {
    SingboxNode node = node_from_json(json);
    if (node.id.empty()) node.id = allocate_id(node.link.empty() ? node.name : node.link, "n", {});
    return node;
}

SingboxStore migrate_profiles(const nlohmann::json& profiles) {
    SingboxStore store;
    for (const auto& profile : profiles) {
        if (!profile.is_object()) continue;
        const auto profile_tag = profile.value("keenetic_tag", profile.value("id", ""));
        const auto profile_iface = profile.value("interface", "");
        const auto stack = profile.value("tun_stack", "gvisor");
        const int mtu = profile.value("tun_mtu", 1400);
        const auto address = profile.value("tun_address", "");
        std::map<std::string, std::string> subscription_ids;
        if (profile.contains("subscriptions") && profile["subscriptions"].is_array()) {
            for (const auto& item : profile["subscriptions"]) {
                auto subscription = subscription_from_json(item);
                if (subscription.id.empty()) subscription.id = "s" + fnv_hex(subscription.url).substr(0, 8);
                const auto previous = item.value("id", subscription.id);
                subscription_ids[previous] = subscription.id;
                store.subscriptions.push_back(std::move(subscription));
            }
        } else if (profile.contains("subscription_url") && profile["subscription_url"].is_string() &&
                   !profile["subscription_url"].get<std::string>().empty()) {
            SingboxSubscription subscription;
            subscription.url = profile["subscription_url"].get<std::string>();
            subscription.id = "s" + fnv_hex(subscription.url).substr(0, 8);
            subscription.name = host_of(subscription.url);
            subscription.interval_hours = profile.value("interval_hours", 0);
            subscription.last_refresh = profile.value("last_refresh", static_cast<std::int64_t>(0));
            subscription.last_error = profile.value("last_error", "");
            subscription_ids["sub"] = subscription.id;
            store.subscriptions.push_back(std::move(subscription));
        }
        bool first = true;
        if (!profile.contains("connections") || !profile["connections"].is_array()) continue;
        for (const auto& item : profile["connections"]) {
            auto node = migrate_connection(item);
            if (node.tag.empty()) {
                node.tag = first && !profile_tag.empty() ? sanitize_keenetic_tag(profile_tag)
                                                         : allocate_tag(node.name, store.nodes, node.id);
            }
            if (tag_used(store.nodes, node.tag, node.id)) node.tag = allocate_tag(node.name, store.nodes, node.id);
            if (first && !profile_iface.empty()) node.interface_name = profile_iface;
            else if (node.interface_name.empty()) node.interface_name = next_free_interface({}, store.nodes, node.id, "sbtun");
            node.tun_stack = node.tun_stack.empty() ? stack : node.tun_stack;
            if (node.tun_mtu <= 0) node.tun_mtu = mtu;
            if (node.tun_address.empty()) node.tun_address = address;
            const auto old_subscription = item.value("subscription_id", "");
            if (!old_subscription.empty() && subscription_ids.count(old_subscription)) {
                node.subscription_id = subscription_ids[old_subscription];
            } else if (item.value("source", "") == "subscription" && store.subscriptions.size() == 1 &&
                       node.subscription_id.empty()) {
                node.subscription_id = store.subscriptions.back().id;
            }
            if (node.identity.empty()) {
                node.identity = trim(node.name).empty() ? endpoint_identity(node.protocol, node.server, node.port)
                                                        : name_identity(node.name);
            }
            if (!node.subscription_id.empty()) {
                for (auto& subscription : store.subscriptions) {
                    if (subscription.id != node.subscription_id) continue;
                    subscription.selected.push_back(node.identity);
                }
            }
            store.nodes.push_back(std::move(node));
            first = false;
        }
    }
    return store;
}

SingboxStore store_from_json(const nlohmann::json& json) {
    if (json.contains("nodes") || json.contains("subscriptions")) {
        SingboxStore store;
        if (json.contains("nodes") && json["nodes"].is_array()) {
            for (const auto& item : json["nodes"]) store.nodes.push_back(node_from_json(item));
        }
        if (json.contains("subscriptions") && json["subscriptions"].is_array()) {
            for (const auto& item : json["subscriptions"]) store.subscriptions.push_back(subscription_from_json(item));
        }
        return store;
    }
    if (json.contains("profiles") && json["profiles"].is_array()) return migrate_profiles(json["profiles"]);
    return {};
}

void validate_unique(const std::vector<SingboxNode>& nodes) {
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i].interface_name.empty() || !safe_interface_name(nodes[i].interface_name)) {
            throw std::runtime_error("interface name is invalid");
        }
        if (nodes[i].tag.empty()) throw std::runtime_error("keen-pbr-sx tag is required");
        for (std::size_t j = i + 1; j < nodes.size(); ++j) {
            if (nodes[i].tag == nodes[j].tag) throw std::runtime_error("keen-pbr-sx tag is already used");
            if (nodes[i].interface_name == nodes[j].interface_name) {
                throw std::runtime_error("TUN interface is already used");
            }
        }
    }
}

constexpr std::int64_t kSubscriptionRetrySeconds = std::int64_t{5} * 60;

std::string subscription_warning(const SubscriptionParseInfo& info) {
    std::size_t transport_count = 0;
    std::string names;
    for (const auto& item : info.unsupported_transports) {
        transport_count += item.second;
        if (!names.empty()) names += ", ";
        names += item.first;
    }
    std::string text;
    if (transport_count > 0) {
        text = std::to_string(transport_count) + " nodes skipped: transport " + names +
               " is not supported by sing-box";
    }
    const auto other = info.skipped > transport_count ? info.skipped - transport_count : 0;
    if (other > 0) {
        if (!text.empty()) text += ". ";
        text += std::to_string(other) + " subscription lines were skipped";
    }
    if (info.encryption_ignored > 0) {
        if (!text.empty()) text += ". ";
        text += "vless encryption is ignored; sing-box does not support it";
    }
    return text;
}

void attach_skips(SingboxApplyResult& result, const SubscriptionParseInfo& info) {
    std::size_t transport_count = 0;
    for (const auto& item : info.unsupported_transports) {
        transport_count += item.second;
        result.skipped_transports.push_back(item.first);
    }
    result.skipped = transport_count > 0 ? transport_count : info.skipped;
    result.encryption_ignored = info.encryption_ignored > 0;
    const auto other = info.skipped > transport_count ? info.skipped - transport_count : 0;
    if (other > 0) {
        if (!result.warning.empty()) result.warning += " ";
        result.warning += std::to_string(other) + " subscription lines were skipped";
    }
}

struct FetchedSubscription {
    std::vector<SingboxNode> nodes;
    std::vector<SingboxCatalogEntry> catalog;
    SubscriptionParseInfo info;
};

SingboxCatalogEntry entry_from_node(const SingboxNode& node) {
    SingboxCatalogEntry entry;
    entry.identity = node.identity;
    entry.name = node.name;
    entry.protocol = node.protocol;
    entry.server = node.server;
    entry.port = node.port;
    return entry;
}

FetchedSubscription parse_fetched(const std::string& body, const std::string& core) {
    FetchedSubscription fetched;
    std::vector<SubscriptionNode> parsed;
    try {
        parsed = parse_subscription(body, &fetched.info, core);
    } catch (const std::runtime_error&) {
        if (fetched.info.skipped == 0) {
            auto message = subscription_warning(fetched.info);
            if (message.empty()) message = "subscription did not contain usable proxy data";
            throw std::runtime_error(message);
        }
    }
    for (auto& item : parsed) fetched.nodes.push_back(node_from_parsed(std::move(item.link), {}));
    assign_identities(fetched.nodes);
    for (const auto& node : fetched.nodes) fetched.catalog.push_back(entry_from_node(node));
    for (const auto& skipped : fetched.info.skipped_nodes) {
        SingboxCatalogEntry entry;
        entry.name = skipped.name;
        entry.protocol = skipped.protocol;
        entry.server = skipped.server;
        entry.port = skipped.port;
        entry.skipped = true;
        entry.reason = skipped.reason;
        fetched.catalog.push_back(std::move(entry));
    }
    return fetched;
}

bool proxy_equal(const SingboxNode& left, const SingboxNode& right) {
    return left.link == right.link && left.outbound == right.outbound && left.protocol == right.protocol &&
           left.server == right.server && left.port == right.port && left.name == right.name &&
           left.identity == right.identity && left.missing == right.missing;
}

}  // namespace

std::string format_singbox_check_error(int exit_code, bool timed_out, const std::string& output) {
    if (timed_out) return "sing-box check failed: timed out";
    if (exit_code == 127 || exit_code == -1) return "sing-box binary is not available";
    return "sing-box check failed: " + redact_secrets(prominent_line(output));
}

bool safe_interface_name(const std::string& name) {
    if (name.empty() || name.size() > 15) return false;
    for (char c : name) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

namespace {

bool next_code_point(const std::string& text, std::size_t& index, char32_t& code) {
    if (index >= text.size()) return false;
    const auto lead = static_cast<unsigned char>(text[index]);
    if (lead < 0x80) {
        code = lead;
        ++index;
        return true;
    }
    std::size_t need = 0;
    char32_t value = 0;
    if ((lead & 0xE0) == 0xC0) {
        need = 1;
        value = lead & 0x1F;
    } else if ((lead & 0xF0) == 0xE0) {
        need = 2;
        value = lead & 0x0F;
    } else if ((lead & 0xF8) == 0xF0) {
        need = 3;
        value = lead & 0x07;
    } else {
        ++index;
        code = 0;
        return true;
    }
    if (index + need >= text.size()) {
        index = text.size();
        code = 0;
        return true;
    }
    for (std::size_t extra = 1; extra <= need; ++extra) {
        const auto cont = static_cast<unsigned char>(text[index + extra]);
        if ((cont & 0xC0) != 0x80) {
            ++index;
            code = 0;
            return true;
        }
        value = (value << 6) | (cont & 0x3F);
    }
    index += need + 1;
    code = value;
    return true;
}

std::string transliterate(char32_t code) {
    if (code >= 'A' && code <= 'Z') return std::string(1, static_cast<char>(code - 'A' + 'a'));
    if ((code >= 'a' && code <= 'z') || (code >= '0' && code <= '9')) return std::string(1, static_cast<char>(code));
    if (code < 128) return "_";
    switch (code) {
    case 0x0410: case 0x0430: return "a";
    case 0x0411: case 0x0431: return "b";
    case 0x0412: case 0x0432: return "v";
    case 0x0413: case 0x0433: return "g";
    case 0x0414: case 0x0434: return "d";
    case 0x0415: case 0x0435: return "e";
    case 0x0401: case 0x0451: return "yo";
    case 0x0416: case 0x0436: return "zh";
    case 0x0417: case 0x0437: return "z";
    case 0x0418: case 0x0438: return "i";
    case 0x0419: case 0x0439: return "y";
    case 0x041A: case 0x043A: return "k";
    case 0x041B: case 0x043B: return "l";
    case 0x041C: case 0x043C: return "m";
    case 0x041D: case 0x043D: return "n";
    case 0x041E: case 0x043E: return "o";
    case 0x041F: case 0x043F: return "p";
    case 0x0420: case 0x0440: return "r";
    case 0x0421: case 0x0441: return "s";
    case 0x0422: case 0x0442: return "t";
    case 0x0423: case 0x0443: return "u";
    case 0x0424: case 0x0444: return "f";
    case 0x0425: case 0x0445: return "kh";
    case 0x0426: case 0x0446: return "ts";
    case 0x0427: case 0x0447: return "ch";
    case 0x0428: case 0x0448: return "sh";
    case 0x0429: case 0x0449: return "shch";
    case 0x042A: case 0x044A: return "";
    case 0x042B: case 0x044B: return "y";
    case 0x042C: case 0x044C: return "";
    case 0x042D: case 0x044D: return "e";
    case 0x042E: case 0x044E: return "yu";
    case 0x042F: case 0x044F: return "ya";
    default: return "";
    }
}

}  // namespace

std::string sanitize_keenetic_tag(const std::string& name) {
    std::string tag;
    std::size_t index = 0;
    char32_t code = 0;
    while (next_code_point(name, index, code)) tag += transliterate(code);
    std::string collapsed;
    for (char c : tag) {
        if (c == '_' && !collapsed.empty() && collapsed.back() == '_') continue;
        collapsed.push_back(c);
    }
    while (!collapsed.empty() && collapsed.front() == '_') collapsed.erase(collapsed.begin());
    while (!collapsed.empty() && collapsed.back() == '_') collapsed.pop_back();
    if (collapsed.empty() || collapsed.front() < 'a' || collapsed.front() > 'z') collapsed.insert(0, "n_");
    if (collapsed.size() > 24) {
        collapsed.resize(24);
        while (!collapsed.empty() && collapsed.back() == '_') collapsed.pop_back();
    }
    if (collapsed.empty() || collapsed.front() < 'a' || collapsed.front() > 'z') return "n_";
    return collapsed;
}

std::string outbound_reference_message(const nlohmann::json& config, const std::string& tag) {
    std::vector<std::string> refs;
    if (config.contains("route") && config["route"].is_object() && config["route"].contains("rules") &&
        config["route"]["rules"].is_array()) {
        int index = 0;
        for (const auto& rule : config["route"]["rules"]) {
            ++index;
            if (rule.is_object() && rule.value("outbound", "") == tag) {
                refs.push_back("route rule " + std::to_string(index));
            }
        }
    }
    if (config.contains("outbounds") && config["outbounds"].is_array()) {
        for (const auto& outbound : config["outbounds"]) {
            if (!outbound.is_object()) continue;
            const auto type = outbound.value("type", "");
            if (type != "urltest" && type != "icmptest") continue;
            bool used = false;
            if (outbound.contains("outbound_groups") && outbound["outbound_groups"].is_array()) {
                for (const auto& group : outbound["outbound_groups"]) {
                    if (!group.is_object()) continue;
                    if (group.contains("members") && group["members"].is_array()) {
                        for (const auto& member : group["members"]) {
                            if (member.is_object() && member.value("outbound", "") == tag) used = true;
                            if (member.is_string() && member.get<std::string>() == tag) used = true;
                        }
                    }
                    if (group.contains("outbounds") && group["outbounds"].is_array()) {
                        for (const auto& item : group["outbounds"]) {
                            if (item.is_string() && item.get<std::string>() == tag) used = true;
                        }
                    }
                }
            }
            if (used) refs.push_back(type + " " + outbound.value("tag", ""));
        }
    }
    if (refs.empty()) return {};
    std::string message = "outbound " + tag + " is used by ";
    for (std::size_t i = 0; i < refs.size(); ++i) {
        if (i != 0) message += ", ";
        message += refs[i];
    }
    return message;
}

nlohmann::json SingboxLinkService::render_singbox_config(const std::vector<SingboxNode>& nodes) {
    bool remove_file = false;
    return merge_singbox_config(nlohmann::json::object(), nodes, &remove_file);
}

SingboxStore SingboxLinkService::load_store(const std::string& path) {
    const auto body = read_file(path);
    if (body.empty()) return {};
    return store_from_json(nlohmann::json::parse(body));
}

SingboxLinkService::SingboxLinkService(SingboxPaths paths, SingboxCheck check, KeeneticSyncFn keenetic,
                                       SingboxReloadFn reload, SubscriptionDownloadFn download,
                                       SubscriptionClock clock, CoreProcessFn process, XrayTestFn test,
                                       XrayVersionFn version, RamFn ram)
    : paths_(std::move(paths)), check_(std::move(check)), keenetic_(std::move(keenetic)),
      reload_(std::move(reload)), download_(std::move(download)),
      clock_(clock ? std::move(clock) : now_unix), core_process_(std::move(process)),
      xray_test_(std::move(test)), xray_version_(std::move(version)), ram_(std::move(ram)) {
    const auto slash = paths_.store.find_last_of('/');
    if (slash != std::string::npos) xray_config_ = paths_.store.substr(0, slash) + "/xray.json";
}

SingboxStore SingboxLinkService::read() const {
    try {
        return load_store(paths_.store);
    } catch (const std::exception&) {
        throw std::runtime_error("could not read the sing-box subscription store");
    }
}

nlohmann::json SingboxLinkService::read_config_object() const {
    const auto body = read_file(paths_.singbox_config);
    if (blank(body)) return nlohmann::json::object();
    try {
        auto json = nlohmann::json::parse(body);
        if (!json.is_object()) {
            throw std::runtime_error("existing sing-box config is not a JSON object; it was not modified");
        }
        return json;
    } catch (const std::runtime_error&) {
        throw;
    } catch (const std::exception&) {
        throw std::runtime_error("existing sing-box config is not valid JSON; it was not modified");
    }
}

std::unique_lock<std::mutex> SingboxLinkService::begin_mutation() {
    std::unique_lock<std::mutex> lock(mutation_mutex_, std::try_to_lock);
    if (!lock) throw SingboxBusy();
    return lock;
}

void SingboxLinkService::update_refresh_status(const std::string& id, RefreshStatus status) {
    std::lock_guard<std::mutex> lock(status_mutex_);
    if (status.last_refresh == 0 && status.retry_at == 0 && status.error.empty()) refresh_status_.erase(id);
    else refresh_status_[id] = std::move(status);
}

SingboxLinkService::RefreshStatus SingboxLinkService::refresh_status(const SingboxSubscription& subscription) const {
    std::lock_guard<std::mutex> lock(status_mutex_);
    const auto it = refresh_status_.find(subscription.id);
    if (it == refresh_status_.end()) return RefreshStatus{subscription.last_refresh, 0, subscription.last_error};
    return it->second;
}

std::int64_t SingboxLinkService::next_refresh(const SingboxSubscription& subscription, const RefreshStatus& status) {
    if (subscription.url.empty() || subscription.interval_hours <= 0) return 0;
    if (status.retry_at != 0) return status.retry_at;
    if (status.last_refresh <= 0) return 0;
    return status.last_refresh + static_cast<std::int64_t>(subscription.interval_hours) * 3600;
}

nlohmann::json SingboxLinkService::public_state(const SingboxStore& store) const {
    nlohmann::json nodes = nlohmann::json::array();
    for (const auto& node : store.nodes) {
        auto json = node_json(node, false);
        if (!node.subscription_id.empty()) {
            for (const auto& subscription : store.subscriptions) {
                if (subscription.id == node.subscription_id) json["subscription_name"] = subscription.name;
            }
        }
        nodes.push_back(std::move(json));
    }
    nlohmann::json subscriptions = nlohmann::json::array();
    for (const auto& subscription : store.subscriptions) {
        auto json = subscription_json(subscription, false);
        const auto status = refresh_status(subscription);
        json["last_refresh"] = status.last_refresh;
        json["last_error"] = status.error;
        const auto next = next_refresh(subscription, status);
        json["next_refresh"] = subscription.interval_hours <= 0 ? nlohmann::json(nullptr)
                                                                : nlohmann::json(next == 0 ? clock_() : next);
        subscriptions.push_back(std::move(json));
    }
    nlohmann::json existing = nlohmann::json::object();
    try {
        existing = read_config_object();
    } catch (const std::exception&) {
        existing = nlohmann::json::object();
    }
    return {{"nodes", std::move(nodes)},
            {"subscriptions", std::move(subscriptions)},
            {"suggested_interface", next_free_interface(existing, store.nodes, "", tun_prefix())},
            {"core", proxy_core_},
            {"xray_bin", xray_bin_},
            {"xray_version", xray_version_ ? xray_version_(resolve_xray_binary(xray_bin_)) : ""},
            {"ram_kib", ram_ ? ram_() : 0},
            {"ram_warning", ram_below_xray_comfort(ram_ ? ram_() : 0)}};
}

nlohmann::json SingboxLinkService::state() const { return public_state(read()); }

std::map<std::string, std::string> SingboxLinkService::subscription_errors() const {
    std::map<std::string, std::string> errors;
    std::lock_guard<std::mutex> lock(status_mutex_);
    for (const auto& entry : refresh_status_) {
        if (!entry.second.error.empty()) errors.emplace(entry.first, entry.second.error);
    }
    return errors;
}

nlohmann::json SingboxLinkService::preview(const std::string& link) const {
    return public_proxy_fields(parse_proxy_link(link));
}

SingboxLinkService::ConfigWrite SingboxLinkService::write_checked_config(const nlohmann::json& config) {
    preserve_original_config(paths_.singbox_config);
    const bool had_config = backup_file(paths_.singbox_config);
    write_private(paths_.singbox_config, config.dump(2));
    try {
        std::string check_error;
        const int code = check_ ? check_(paths_.singbox_config, &check_error) : 0;
        if (code != 0) {
            const bool timed_out = check_error == "timed out";
            throw std::runtime_error(format_singbox_check_error(code, timed_out, check_error));
        }
    } catch (...) {
        restore_backup(paths_.singbox_config, had_config);
        throw;
    }
    return ConfigWrite{had_config, false};
}

void SingboxLinkService::write_store(const std::string& path, const SingboxStore& store) {
    write_private(path, store_json(store, true).dump(2));
}

SingboxApplyResult SingboxLinkService::persist(const SingboxStore& previous, SingboxStore next,
                                               bool rewrite_singbox, bool sync_keenetic, bool reload_must_succeed) {
    validate_unique(next.nodes);
    ConfigWrite written;
    bool wrote_config = false;
    const bool xray = proxy_core_ == "xray";
    std::string active_config = xray ? xray_config_ : paths_.singbox_config;
    std::vector<SingboxNode> live_nodes;
    for (const auto& node : next.nodes) {
        if (!node.unsupported) live_nodes.push_back(node);
    }
    if (rewrite_singbox) {
        const auto existing = read_config_object();
        bool remove_file = false;
        const auto rendered = xray ? render_xray_config(live_nodes)
                                   : merge_singbox_config(existing, live_nodes, &remove_file);
        if (!xray && remove_file) {
            preserve_original_config(paths_.singbox_config);
            written.had_config = backup_file(paths_.singbox_config);
            if (::unlink(paths_.singbox_config.c_str()) != 0 && errno != ENOENT) {
                throw std::runtime_error("cannot remove sing-box config");
            }
            written.removed = true;
            wrote_config = true;
        } else if (xray) {
            const auto body = rendered.dump(2);
            if (read_file(xray_config_) != body) {
                const auto candidate = candidate_of(xray_config_);
                write_private(candidate, body);
                std::string error;
                const int code = xray_test_ ? xray_test_(resolve_xray_binary(xray_bin_), candidate, &error) : 0;
                ::unlink(candidate.c_str());
                if (code != 0) {
                    throw std::runtime_error(error.empty() ? "xray run -test failed" : error);
                }
                written.had_config = backup_file(xray_config_);
                write_private(xray_config_, body);
                wrote_config = true;
            }
        } else if (read_file(paths_.singbox_config) != rendered.dump(2)) {
            written = write_checked_config(rendered);
            wrote_config = true;
        }
    }
    const bool store_differs = store_json(previous, true) != store_json(next, true);
    bool wrote_store = false;
    try {
        if (store_differs) {
            backup_file(paths_.store);
            write_store(paths_.store, next);
            wrote_store = true;
        }
        bool keenetic_changed = false;
        KeeneticSyncRequest request;
        request.nodes = next.nodes;
        std::set<std::string> previous_tags;
        std::set<std::string> next_tags;
        for (const auto& node : previous.nodes) previous_tags.insert(node.tag);
        for (const auto& node : next.nodes) next_tags.insert(node.tag);
        for (const auto& tag : previous_tags) {
            request.owned_tags.push_back(tag);
            if (!next_tags.count(tag)) request.removed_tags.push_back(tag);
        }
        if (previous_tags != next_tags) keenetic_changed = true;
        if (!keenetic_changed) {
            for (const auto& node : next.nodes) {
                const auto previous_node = std::find_if(previous.nodes.begin(), previous.nodes.end(),
                                                        [&](const SingboxNode& item) { return item.tag == node.tag; });
                if (previous_node == previous.nodes.end() || previous_node->interface_name != node.interface_name) {
                    keenetic_changed = true;
                }
            }
        }
        if (sync_keenetic && keenetic_changed && keenetic_) keenetic_(request);
    } catch (const std::exception&) {
        if (wrote_store) {
            const bool had_store = ::access(backup_of(paths_.store).c_str(), F_OK) == 0;
            restore_backup(paths_.store, had_store);
        }
        if (wrote_config) restore_backup(active_config, written.had_config);
        throw;
    }
    SingboxApplyResult result;
    result.keenetic_applied = true;
    if (written.removed) {
        result.warning = "removed the generated sing-box config because no nodes remain";
    } else if (wrote_config) {
        result.singbox_checked = true;
        try {
            if (xray) {
                result.singbox_reloaded = core_process_ && core_process_("xray", "start", xray_bin_, xray_config_);
            } else {
                result.singbox_reloaded = reload_ && reload_();
            }
            if (reload_must_succeed && !result.singbox_reloaded) {
                throw std::runtime_error(xray ? "could not restart xray; restoring the previous configuration"
                                              : "could not restart sing-box; restoring the previous configuration");
            }
            if (!result.singbox_reloaded) {
                result.warning = xray ? "xray config passed xray run -test; start xray on the router to load it"
                                      : "sing-box config passed check; restart sing-box on the router to load it";
            }
        } catch (const std::exception& error) {
            if (reload_must_succeed) {
                if (wrote_store) {
                    const bool had_store = ::access(backup_of(paths_.store).c_str(), F_OK) == 0;
                    restore_backup(paths_.store, had_store);
                }
                restore_backup(active_config, written.had_config);
                throw;
            }
            result.warning = std::string(xray ? "xray config is valid but was not restarted: "
                                              : "sing-box config is valid but was not restarted: ") +
                             error.what();
        }
    } else {
        result.singbox_checked = true;
    }
    result.state = public_state(next);
    return result;
}

SingboxApplyResult SingboxLinkService::add_links(const std::vector<std::string>& links, const SingboxTunOptions& tun) {
    const auto lock = begin_mutation();
    const auto lines = split_links(links);
    if (lines.empty()) throw std::runtime_error("a proxy link is required");
    for (const auto& line : lines) {
        if (is_http_url(line)) {
            throw std::runtime_error("add subscription URLs in the subscription section");
        }
    }
    auto store = read();
    const auto previous = store;
    SubscriptionParseInfo info;
    std::string encryption_rejection;
    std::size_t added = 0;
    const auto existing = read_config_object();
    for (const auto& line : lines) {
        if (std::any_of(store.nodes.begin(), store.nodes.end(),
                        [&](const SingboxNode& node) { return node.link == line; })) {
            continue;
        }
        try {
            ParsedProxyLink parsed;
            if (proxy_core_ == "xray") {
                const auto view = classify_link_for_core(line, "xray");
                if (!view.supported) throw std::runtime_error(view.reason);
                parsed.protocol = view.protocol;
                parsed.name = view.name;
                parsed.server = view.server;
                parsed.port = view.port;
                parsed.outbound = view.outbound;
            } else {
                parsed = parse_proxy_link(line);
            }
            for (const auto& warning : parsed.warnings) {
                if (warning.find("encryption") != std::string::npos) ++info.encryption_ignored;
            }
            auto node = node_from_parsed(std::move(parsed), line);
            apply_tun(node, tun);
            node.id = allocate_id(line, "n", store.nodes);
            node.tag = allocate_tag(node.name, store.nodes, node.id);
            node.interface_name = next_free_interface(existing, store.nodes, node.id, tun_prefix());
            node.identity = trim(node.name).empty() ? endpoint_identity(node.protocol, node.server, node.port)
                                                     : name_identity(node.name);
            store.nodes.push_back(std::move(node));
            ++added;
        } catch (const UnsupportedVlessEncryption& error) {
            ++info.skipped;
            if (encryption_rejection.empty()) encryption_rejection = error.what();
        } catch (const UnsupportedProxyTransport& error) {
            ++info.skipped;
            ++info.unsupported_transports[error.transport()];
        } catch (const std::runtime_error&) {
            ++info.skipped;
        }
    }
    if (added == 0) {
        if (lines.size() == 1 && !encryption_rejection.empty()) throw std::runtime_error(encryption_rejection);
        auto message = subscription_warning(info);
        if (message.empty()) message = "proxy link could not be parsed";
        throw std::runtime_error(message);
    }
    auto result = persist(previous, std::move(store), true, true);
    attach_skips(result, info);
    return result;
}

SingboxApplyResult SingboxLinkService::update_node(const SingboxNodePatch& patch) {
    const auto lock = begin_mutation();
    auto store = read();
    const auto previous = store;
    auto it = std::find_if(store.nodes.begin(), store.nodes.end(),
                           [&](const SingboxNode& node) { return node.id == patch.id; });
    if (it == store.nodes.end()) throw std::runtime_error("sing-box node was not found");
    if (!patch.tag.empty()) {
        const auto tag = sanitize_keenetic_tag(patch.tag);
        if (tag_used(store.nodes, tag, it->id)) throw std::runtime_error("keen-pbr-sx tag is already used");
        it->tag = tag;
    }
    if (!patch.interface_name.empty()) {
        if (!safe_interface_name(patch.interface_name)) throw std::runtime_error("interface name is invalid");
        for (const auto& node : store.nodes) {
            if (node.id != it->id && node.interface_name == patch.interface_name) {
                throw std::runtime_error("TUN interface is already used");
            }
        }
        it->interface_name = patch.interface_name;
    }
    if (!patch.tun_stack.empty()) {
        require_stack(patch.tun_stack);
        it->tun_stack = patch.tun_stack;
    }
    if (patch.tun_mtu != 0) {
        require_mtu(patch.tun_mtu);
        it->tun_mtu = patch.tun_mtu;
    }
    if (patch.tun_address_set) {
        require_addresses(patch.tun_address);
        it->tun_address = patch.tun_address;
    }
    return persist(previous, std::move(store), true, true);
}

SingboxApplyResult SingboxLinkService::remove_node(const std::string& id) {
    const auto lock = begin_mutation();
    auto store = read();
    const auto previous = store;
    const auto it = std::find_if(store.nodes.begin(), store.nodes.end(),
                                 [&](const SingboxNode& node) { return node.id == id; });
    if (it == store.nodes.end()) throw std::runtime_error("sing-box node was not found");
    const auto subscription_id = it->subscription_id;
    const auto identity = it->identity;
    store.nodes.erase(it);
    if (!subscription_id.empty()) {
        for (auto& subscription : store.subscriptions) {
            if (subscription.id != subscription_id) continue;
            subscription.selected.erase(std::remove(subscription.selected.begin(), subscription.selected.end(), identity),
                                        subscription.selected.end());
        }
    }
    return persist(previous, std::move(store), true, true);
}

nlohmann::json SingboxLinkService::preview_subscription(const std::string& url_or_id) const {
    if (!download_) throw std::runtime_error("subscription download failed");
    std::string url = url_or_id;
    if (!is_http_url(url)) {
        const auto store = read();
        const auto it = std::find_if(store.subscriptions.begin(), store.subscriptions.end(),
                                     [&](const SingboxSubscription& subscription) { return subscription.id == url_or_id; });
        if (it == store.subscriptions.end()) throw std::runtime_error("subscription was not found");
        url = it->url;
    }
    std::string body;
    try {
        body = download_(url, {});
    } catch (const std::exception&) {
        throw std::runtime_error("subscription download failed");
    }
    const auto fetched = parse_fetched(body, proxy_core_);
    nlohmann::json nodes = nlohmann::json::array();
    for (const auto& entry : fetched.catalog) nodes.push_back(catalog_json(entry));
    nlohmann::json json{{"nodes", std::move(nodes)}};
    const auto warning = subscription_warning(fetched.info);
    if (!warning.empty()) json["warning"] = warning;
    json["skipped"] = fetched.info.skipped;
    return json;
}

SingboxApplyResult SingboxLinkService::save_subscription(const std::string& url, int interval_hours,
                                                         const std::vector<std::string>& selected,
                                                         const SingboxTunOptions& tun,
                                                         const std::string& subscription_id) {
    const auto lock = begin_mutation();
    if (!is_http_url(url)) throw std::runtime_error("subscription URL is required");
    if (interval_hours < 0) throw std::runtime_error("interval must be a number of hours");
    if (!download_) throw std::runtime_error("subscription download failed");
    std::string body;
    try {
        body = download_(url, {});
    } catch (const std::exception&) {
        throw std::runtime_error("subscription download failed");
    }
    const auto fetched = parse_fetched(body, proxy_core_);
    auto store = read();
    const auto previous = store;
    SingboxSubscription* subscription = nullptr;
    if (!subscription_id.empty()) {
        for (auto& item : store.subscriptions) {
            if (item.id == subscription_id) subscription = &item;
        }
        if (subscription == nullptr) throw std::runtime_error("subscription was not found");
    } else {
        for (auto& item : store.subscriptions) {
            if (item.url == url) subscription = &item;
        }
    }
    if (subscription == nullptr) {
        SingboxSubscription created;
        created.url = url;
        created.name = host_of(url);
        created.id = "s" + fnv_hex(url).substr(0, 8);
        for (int number = 0; number < 100; ++number) {
            const auto candidate = number == 0 ? created.id : created.id + std::to_string(number);
            const bool used = std::any_of(store.subscriptions.begin(), store.subscriptions.end(),
                                          [&](const SingboxSubscription& item) { return item.id == candidate; });
            if (!used) {
                created.id = candidate;
                break;
            }
        }
        store.subscriptions.push_back(std::move(created));
        subscription = &store.subscriptions.back();
    }
    subscription->url = url;
    subscription->name = host_of(url);
    subscription->interval_hours = interval_hours;
    subscription->catalog = fetched.catalog;
    subscription->last_refresh = clock_();
    subscription->last_error = subscription_warning(fetched.info);
    const auto existing = read_config_object();
    std::size_t created_nodes = 0;
    for (const auto& identity : selected) {
        const bool exists = std::any_of(store.nodes.begin(), store.nodes.end(), [&](const SingboxNode& node) {
            return node.subscription_id == subscription->id && node.identity == identity;
        });
        if (exists) continue;
        const auto fresh = std::find_if(fetched.nodes.begin(), fetched.nodes.end(),
                                        [&](const SingboxNode& node) { return node.identity == identity; });
        if (fresh == fetched.nodes.end()) continue;
        SingboxNode node = *fresh;
        apply_tun(node, tun);
        node.subscription_id = subscription->id;
        node.id = allocate_id(identity + url, "n", store.nodes);
        node.tag = allocate_tag(node.name, store.nodes, node.id);
        node.interface_name = next_free_interface(existing, store.nodes, node.id, tun_prefix());
        store.nodes.push_back(std::move(node));
        ++created_nodes;
    }
    if (!selected.empty() && created_nodes == 0 &&
        std::none_of(store.nodes.begin(), store.nodes.end(), [&](const SingboxNode& node) {
            return node.subscription_id == subscription->id;
        })) {
        throw std::runtime_error("selected nodes are not in the subscription");
    }
    subscription->selected.clear();
    int unmatched = 0;
    for (const auto& fresh : fetched.nodes) {
        const bool have = std::any_of(store.nodes.begin(), store.nodes.end(), [&](const SingboxNode& node) {
            return node.subscription_id == subscription->id && node.identity == fresh.identity;
        });
        if (have) subscription->selected.push_back(fresh.identity);
        else ++unmatched;
    }
    subscription->new_nodes = unmatched;
    auto result = persist(previous, std::move(store), created_nodes > 0, created_nodes > 0);
    attach_skips(result, fetched.info);
    return result;
}

SingboxApplyResult SingboxLinkService::select_subscription(const std::string& subscription_id,
                                                           const std::vector<std::string>& selected,
                                                           const SingboxTunOptions& tun) {
    std::string url;
    int interval = 0;
    {
        const auto lock = begin_mutation();
        const auto store = read();
        const auto found = std::find_if(store.subscriptions.begin(), store.subscriptions.end(),
                                        [&](const SingboxSubscription& item) { return item.id == subscription_id; });
        if (found == store.subscriptions.end()) throw std::runtime_error("subscription was not found");
        url = found->url;
        interval = found->interval_hours;
    }
    return save_subscription(url, interval, selected, tun, subscription_id);
}

SingboxApplyResult SingboxLinkService::remove_subscription(const std::string& subscription_id) {
    const auto lock = begin_mutation();
    auto store = read();
    const auto previous = store;
    const auto found = std::find_if(store.subscriptions.begin(), store.subscriptions.end(),
                                    [&](const SingboxSubscription& item) { return item.id == subscription_id; });
    if (found == store.subscriptions.end()) throw std::runtime_error("subscription was not found");
    store.subscriptions.erase(found);
    store.nodes.erase(std::remove_if(store.nodes.begin(), store.nodes.end(),
                                     [&](const SingboxNode& node) { return node.subscription_id == subscription_id; }),
                      store.nodes.end());
    update_refresh_status(subscription_id, {});
    return persist(previous, std::move(store), true, true);
}

bool SingboxLinkService::refresh_one(SingboxStore& store, std::size_t index, const SubscriptionStopFn& stopping) {
    auto& subscription = store.subscriptions[index];
    const auto status = refresh_status(subscription);
    const char* failure = "subscription download failed";
    try {
        if (!download_) throw std::runtime_error(failure);
        const auto body = download_(subscription.url, stopping);
        if (stopping && stopping()) return true;
        failure = "subscription did not contain usable proxy data; keeping the previous configuration";
        const auto fetched = parse_fetched(body, proxy_core_);
        if (stopping && stopping()) return true;
        auto next = store;
        auto& updated = next.subscriptions[index];
        std::set<std::size_t> used;
        bool proxy_changed = false;
        for (auto& node : next.nodes) {
            if (node.subscription_id != updated.id) continue;
            const auto* match = match_fresh(node, fetched.nodes, used);
            if (match == nullptr) {
                const SingboxCatalogEntry* rejected = nullptr;
                for (const auto& entry : fetched.catalog) {
                    if (!entry.skipped || entry.reason.find("VLESS Encryption (") != 0) continue;
                    const bool same_name = !trim(node.name).empty() && lower_copy(trim(entry.name)) == lower_copy(trim(node.name));
                    const bool same_endpoint = lower_copy(entry.protocol) == lower_copy(node.protocol) &&
                                               lower_copy(entry.server) == lower_copy(node.server) && entry.port == node.port;
                    if (same_name || same_endpoint) {
                        rejected = &entry;
                        break;
                    }
                }
                if (rejected != nullptr) {
                    node.missing = false;
                    node.unsupported = true;
                    node.unsupported_reason = rejected->reason;
                    continue;
                }
                node.missing = true;
                node.unsupported = false;
                node.unsupported_reason.clear();
                continue;
            }
            node.missing = false;
            node.unsupported = false;
            node.unsupported_reason.clear();
            if (!proxy_equal(node, *match)) {
                node.name = match->name;
                node.protocol = match->protocol;
                node.server = match->server;
                node.port = match->port;
                node.link = match->link;
                node.outbound = match->outbound;
                node.identity = match->identity;
                proxy_changed = true;
            }
        }
        updated.catalog = fetched.catalog;
        updated.new_nodes = static_cast<int>(fetched.nodes.size() - used.size());
        updated.selected.clear();
        for (const auto& node : next.nodes) {
            if (node.subscription_id == updated.id) updated.selected.push_back(node.identity);
        }
        const auto warning = subscription_warning(fetched.info);
        const bool store_same = store_json(store, true) == store_json(next, true);
        if (!proxy_changed && store_same) {
            update_refresh_status(updated.id, {clock_(), 0, warning});
            return true;
        }
        updated.last_refresh = clock_();
        updated.last_error = warning;
        failure = "could not apply subscription: sing-box config write or check failed";
        const auto id = updated.id;
        persist(store, next, proxy_changed, false, true);
        store = std::move(next);
        update_refresh_status(id, {clock_(), 0, warning});
        return true;
    } catch (const std::exception&) {
        if (stopping && stopping()) return true;
        update_refresh_status(subscription.id, {status.last_refresh, clock_() + kSubscriptionRetrySeconds, failure});
        return false;
    }
}

nlohmann::json SingboxLinkService::refresh_subscriptions(const std::string& subscription_id, bool due_only,
                                                        const SubscriptionStopFn& stopping) {
    const auto lock = begin_mutation();
    auto store = read();
    nlohmann::json results = nlohmann::json::array();
    bool matched = subscription_id.empty();
    for (std::size_t i = 0; i < store.subscriptions.size(); ++i) {
        if (stopping && stopping()) break;
        const auto& subscription = store.subscriptions[i];
        if (!subscription_id.empty() && subscription.id != subscription_id) continue;
        matched = true;
        if (subscription.url.empty()) continue;
        const auto status = refresh_status(subscription);
        if (due_only && (subscription.interval_hours <= 0 || next_refresh(subscription, status) > clock_())) continue;
        const bool ok = refresh_one(store, i, stopping);
        if (stopping && stopping()) break;
        const auto updated = refresh_status(store.subscriptions[i]);
        results.push_back({{"id", store.subscriptions[i].id},
                           {"subscription_id", store.subscriptions[i].id},
                           {"ok", ok && updated.retry_at == 0},
                           {"message", updated.error}});
    }
    if (!subscription_id.empty() && !matched && !(stopping && stopping())) {
        throw std::runtime_error("subscription was not found");
    }
    return results;
}

std::string SingboxLinkService::tun_prefix() const { return tun_prefix_for_core(proxy_core_); }

void SingboxLinkService::set_proxy(std::string core, std::string xray_bin) {
    if (core != "xray") core = "sing-box";
    proxy_core_ = std::move(core);
    xray_bin_ = std::move(xray_bin);
}

void SingboxLinkService::set_core_hooks(CoreProcessFn process, XrayTestFn test, XrayVersionFn version, RamFn ram) {
    core_process_ = std::move(process);
    xray_test_ = std::move(test);
    xray_version_ = std::move(version);
    ram_ = std::move(ram);
}

SingboxApplyResult SingboxLinkService::switch_core(const std::string& requested, const std::string& xray_bin,
                                                   bool icmptest_groups) {
    const auto lock = begin_mutation();
    if (requested != "sing-box" && requested != "xray") {
        throw std::runtime_error("proxy.core must be sing-box or xray");
    }
    std::string bin = resolve_xray_binary(xray_bin.empty() ? xray_bin_ : xray_bin);
    if (requested == "xray") {
        const auto version = xray_version_ ? xray_version_(bin) : std::string{};
        if (!xray_version_at_least(version, 26, 10, 17)) {
            std::string shown = version.empty() ? "version is unknown" : version;
            const std::string prefix = "Xray ";
            if (shown.rfind(prefix, 0) == 0) shown.erase(0, prefix.size());
            throw std::runtime_error("Xray " + shown +
                                     " is older than 26.10.17. The core was not switched.");
        }
    }
    auto previous = read();
    auto next = previous;
    std::vector<InterfaceRename> renames;
    const auto prefix = tun_prefix_for_core(requested);
    std::vector<std::string> previous_interfaces;
    previous_interfaces.reserve(next.nodes.size());
    for (auto& node : next.nodes) {
        previous_interfaces.push_back(node.interface_name);
        const auto view = classify_link_for_core(node.link, requested);
        if (node.link.empty() && node.protocol == "vless" && requested == "xray") {
            node.unsupported = false;
            node.unsupported_reason.clear();
        } else if (!view.supported) {
            node.unsupported = true;
            node.unsupported_reason = view.reason.empty()
                                          ? std::string("protocol ") + node.protocol + " is not supported by " +
                                                (requested == "xray" ? "Xray" : "sing-box")
                                          : view.reason;
        } else {
            node.unsupported = false;
            node.unsupported_reason.clear();
            if (requested == "xray") node.outbound = view.outbound;
        }
        if (!node.unsupported) node.interface_name.clear();
    }
    const auto existing = requested == "xray" ? nlohmann::json::object() : read_config_object();
    for (std::size_t i = 0; i < next.nodes.size(); ++i) {
        auto& node = next.nodes[i];
        if (node.unsupported) {
            node.interface_name = previous_interfaces[i];
            continue;
        }
        const auto old_name = previous_interfaces[i];
        node.interface_name = next_free_interface(existing, next.nodes, node.id, prefix);
        if (!old_name.empty() && old_name != node.interface_name) {
            renames.push_back(InterfaceRename{node.tag, old_name, node.interface_name});
        }
    }
    std::vector<SingboxNode> live;
    for (const auto& node : next.nodes) {
        if (!node.unsupported) live.push_back(node);
    }
    const auto rendered = requested == "xray" ? render_xray_config(live)
                                              : merge_singbox_config(read_config_object(), live, nullptr);
    const auto target = requested == "xray" ? xray_config_ : paths_.singbox_config;
    const auto candidate = candidate_of(target);
    write_private(candidate, rendered.dump(2));
    std::string error;
    int code = 0;
    if (requested == "xray") code = xray_test_ ? xray_test_(bin, candidate, &error) : 0;
    else code = check_ ? check_(candidate, &error) : 0;
    ::unlink(candidate.c_str());
    if (code != 0) {
        throw std::runtime_error(error.empty() ? (requested == "xray" ? "xray run -test failed" : "sing-box check failed")
                                               : error);
    }
    const bool had_target = backup_file(target);
    write_private(target, rendered.dump(2));
    auto rollback_files = [&] {
        restore_backup(target, had_target);
    };
    auto stop_new = [&] {
        if (core_process_) core_process_(requested, "stop", bin, target);
    };
    if (requested == "xray") {
        if (!core_process_ || !core_process_("xray", "start", bin, target)) {
            rollback_files();
            throw std::runtime_error("could not start xray");
        }
    } else if (!reload_ || !reload_()) {
        rollback_files();
        throw std::runtime_error("could not restart sing-box");
    }
    KeeneticSyncRequest request;
    request.nodes = next.nodes;
    for (const auto& node : previous.nodes) request.owned_tags.push_back(node.tag);
    request.renames = renames;
    request.proxy = {{"core", requested}, {"xray_bin", bin}};
    request.has_proxy = true;
    try {
        if (keenetic_) keenetic_(request);
    } catch (const std::exception&) {
        stop_new();
        rollback_files();
        if (requested == "xray" && reload_) reload_();
        if (requested == "sing-box" && core_process_) core_process_("xray", "start", bin, xray_config_);
        throw;
    }
    const std::string old_core = requested == "xray" ? "sing-box" : "xray";
    if (core_process_ && !core_process_(old_core, "stop", bin, xray_config_)) {
        KeeneticSyncRequest back;
        back.nodes = previous.nodes;
        for (const auto& node : previous.nodes) back.owned_tags.push_back(node.tag);
        back.proxy = {{"core", proxy_core_}, {"xray_bin", xray_bin_}};
        back.has_proxy = true;
        try {
            if (keenetic_) keenetic_(back);
        } catch (const std::exception&) {
            // The file and process rollback below still has to run.
        }
        stop_new();
        rollback_files();
        if (old_core == "sing-box" && reload_) reload_();
        if (old_core == "xray" && core_process_) core_process_("xray", "start", bin, xray_config_);
        throw std::runtime_error("could not stop the previous core; the switch was rolled back");
    }
    const bool had_store = backup_file(paths_.store);
    try {
        write_store(paths_.store, next);
    } catch (const std::exception&) {
        restore_backup(paths_.store, had_store);
        throw;
    }
    proxy_core_ = requested;
    xray_bin_ = bin;
    SingboxApplyResult result;
    result.singbox_checked = true;
    result.singbox_reloaded = true;
    result.keenetic_applied = true;
    if (requested == "xray" && icmptest_groups) {
        result.warning =
            "icmptest does not measure an Xray TUN: the stack answers ICMP echo locally. Use urltest.";
    }
    result.state = public_state(next);
    return result;
}

void apply_interface_renames(nlohmann::json& config, const std::vector<InterfaceRename>& renames) {
    if (!config.contains("outbounds") || !config["outbounds"].is_array()) return;
    auto rewrite = [](nlohmann::json& value, const std::string& from, const std::string& to) {
        if (value.is_string() && value.get<std::string>() == from) value = to;
    };
    for (const auto& rename : renames) {
        if (rename.from.empty() || rename.from == rename.to || rename.from == rename.tag) continue;
        for (auto& outbound : config["outbounds"]) {
            if (!outbound.is_object()) continue;
            const auto type = outbound.value("type", "");
            if (type != "urltest" && type != "icmptest") continue;
            if (!outbound.contains("outbound_groups") || !outbound["outbound_groups"].is_array()) continue;
            for (auto& group : outbound["outbound_groups"]) {
                if (!group.is_object()) continue;
                if (group.contains("members") && group["members"].is_array()) {
                    for (auto& member : group["members"]) {
                        rewrite(member, rename.from, rename.to);
                        if (!member.is_object()) continue;
                        if (member.value("outbound", "") == rename.from) member["outbound"] = rename.to;
                        if (member.value("interface", "") == rename.from) member["interface"] = rename.to;
                    }
                }
                if (group.contains("outbounds") && group["outbounds"].is_array()) {
                    for (auto& item : group["outbounds"]) rewrite(item, rename.from, rename.to);
                }
                if (group.contains("candidates") && group["candidates"].is_array()) {
                    for (auto& candidate : group["candidates"]) {
                        if (candidate.is_object() && candidate.value("outbound", "") == rename.from) {
                            candidate["outbound"] = rename.to;
                        }
                    }
                }
            }
        }
    }
}

}  // namespace keen_pbr3
