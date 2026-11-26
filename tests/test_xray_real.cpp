#include <doctest/doctest.h>

#include "../src/singbox/link_store.hpp"
#include "../src/singbox/xray_config.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

using namespace keen_pbr3;

// Runs the configs keen-pbr-sx generates through the real `xray run -test`.
// KEEN_PBR_XRAY_BIN points at an official Xray release binary (CI downloads
// one). Without it the test is skipped, unless KEEN_PBR_REQUIRE_XRAY=1, which
// turns a missing binary into a failure. All keys and uuids are fake or made
// by `xray x25519`, `xray mldsa65` and `xray vlessenc` for this run only.

namespace {

struct CommandResult {
    int code{-1};
    std::string output;
};

CommandResult run_command(const std::string& command) {
    CommandResult result;
    FILE* pipe = popen((command + " 2>&1").c_str(), "r");
    if (!pipe) return result;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) result.output += buffer;
    const int status = pclose(pipe);
    result.code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return result;
}

std::string line_value(const std::string& text, const std::string& label) {
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        const auto pos = line.find(label);
        if (pos == std::string::npos) continue;
        auto value = line.substr(pos + label.size());
        while (!value.empty() && (value.front() == ' ' || value.front() == '"' || value.front() == ':')) {
            value.erase(value.begin());
        }
        while (!value.empty() && (value.back() == '"' || value.back() == ',' || value.back() == '\r' ||
                                  value.back() == ' ')) {
            value.pop_back();
        }
        return value;
    }
    return {};
}

SingboxNode link_node(const std::string& id, const std::string& iface, const std::string& link) {
    SingboxNode node;
    node.id = id;
    node.name = id;
    node.tag = id;
    node.protocol = "vless";
    node.server = "203.0.113.10";
    node.port = 443;
    node.link = link;
    node.interface_name = iface;
    return node;
}

SingboxNode outbound_node(const std::string& id, const std::string& iface, const nlohmann::json& outbound) {
    SingboxNode node;
    node.id = id;
    node.name = id;
    node.tag = id;
    node.protocol = "vless";
    node.server = outbound.at("server");
    node.port = outbound.at("server_port");
    node.outbound = outbound;
    node.interface_name = iface;
    return node;
}

nlohmann::json singbox_vless(const std::string& public_key, const nlohmann::json& transport,
                             bool reality) {
    nlohmann::json tls{{"enabled", true},
                       {"server_name", "www.example.org"},
                       {"utls", {{"enabled", true}, {"fingerprint", "chrome"}}}};
    if (reality) tls["reality"] = {{"enabled", true}, {"public_key", public_key}, {"short_id", "0123abcd"}};
    nlohmann::json outbound{{"type", "vless"},
                            {"tag", "n"},
                            {"server", "203.0.113.20"},
                            {"server_port", 443},
                            {"uuid", "22222222-2222-2222-2222-222222222222"},
                            {"packet_encoding", "xudp"},
                            {"tls", tls}};
    if (!transport.is_null()) outbound["transport"] = transport;
    return outbound;
}

}  // namespace

TEST_CASE("generated xray configs pass the real xray run -test") {
    const char* env = std::getenv("KEEN_PBR_XRAY_BIN");
    const std::string xray = env ? env : "";
    if (xray.empty()) {
        const char* require = std::getenv("KEEN_PBR_REQUIRE_XRAY");
        if (require && std::string(require) == "1") FAIL("KEEN_PBR_XRAY_BIN is not set");
        MESSAGE("KEEN_PBR_XRAY_BIN is not set: the real xray -test is skipped");
        return;
    }
    const auto version = run_command("'" + xray + "' version");
    REQUIRE(version.code == 0);
    MESSAGE(version.output.substr(0, version.output.find('\n')));

    const auto x25519 = run_command("'" + xray + "' x25519");
    const auto public_key = line_value(x25519.output, "(PublicKey):");
    REQUIRE_FALSE(public_key.empty());
    const auto mldsa = run_command("'" + xray + "' mldsa65");
    const auto verify = line_value(mldsa.output, "Verify:");
    REQUIRE_FALSE(verify.empty());
    const auto vlessenc = run_command("'" + xray + "' vlessenc");
    const auto encryption = line_value(vlessenc.output, "\"encryption\":");
    REQUIRE_FALSE(encryption.empty());

    const std::string uuid = "11111111-1111-1111-1111-111111111111";
    const std::string head = "vless://" + uuid + "@203.0.113.10:443?";
    const std::string reality = "security=reality&pbk=" + public_key + "&sid=0123abcd&sni=www.example.org&fp=chrome";

    struct Case {
        std::string name;
        SingboxNode node;
    };
    std::vector<Case> cases;
    cases.push_back({"link reality tcp vision", link_node("a1", "xrtun", head + reality + "&flow=xtls-rprx-vision&type=tcp#a")});
    cases.push_back({"link reality tcp, spiderX", link_node("a2", "xrtun", head + reality + "&spx=%2F&type=tcp#a")});
    cases.push_back({"link tls ws", link_node("b1", "xrtun", head + "security=tls&sni=cdn.example.org&fp=chrome&alpn=h2&type=ws&path=%2Fvpn&host=cdn.example.org#b")});
    cases.push_back({"link reality grpc", link_node("c1", "xrtun", head + reality + "&type=grpc&serviceName=GunService#c")});
    cases.push_back({"link reality xhttp", link_node("d1", "xrtun", head + reality + "&type=xhttp&path=%2Fxh&host=www.example.org&mode=auto#d")});
    cases.push_back({"link reality xhttp, ML-DSA and vless encryption",
                     link_node("d2", "xrtun", head + reality + "&pqv=" + verify + "&encryption=" + encryption + "&type=xhttp&path=%2Fxh&mode=auto#d")});
    cases.push_back({"link tls xhttp", link_node("d3", "xrtun", head + "security=tls&sni=cdn.example.org&type=xhttp&path=%2Fxh#d")});
    cases.push_back({"stored sing-box reality tcp", outbound_node("e1", "xrtun", [&] {
                         auto o = singbox_vless(public_key, nullptr, true);
                         o["flow"] = "xtls-rprx-vision";
                         return o;
                     }())});
    cases.push_back({"stored sing-box tls ws", outbound_node("e2", "xrtun", singbox_vless(public_key, {{"type", "ws"}, {"path", "/ws"}, {"headers", {{"Host", "cdn.example.org"}}}}, false))});
    cases.push_back({"stored sing-box reality grpc", outbound_node("e3", "xrtun", singbox_vless(public_key, {{"type", "grpc"}, {"service_name", "GunService"}}, true))});
    cases.push_back({"stored sing-box tls httpupgrade", outbound_node("e4", "xrtun", singbox_vless(public_key, {{"type", "httpupgrade"}, {"path", "/hu"}, {"host", "cdn.example.org"}}, false))});
    cases.push_back({"stored sing-box tls http becomes xhttp", outbound_node("e5", "xrtun", singbox_vless(public_key, {{"type", "http"}, {"path", "/h"}, {"host", {"cdn.example.org"}}}, false))});

    const auto dir = std::filesystem::temp_directory_path() / "keen-pbr-sx-xray-real";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    int index = 0;
    const auto check = [&](const std::string& name, const std::vector<SingboxNode>& nodes) {
        const auto path = dir / ("xray." + std::to_string(++index) + ".json");
        {
            std::ofstream out(path);
            out << render_xray_config(nodes).dump(2);
        }
        const auto result = run_command("'" + xray + "' run -test -format json -c '" + path.string() + "'");
        INFO(name << ":\n" << result.output);
        CHECK(result.code == 0);
        CHECK(result.output.find("Configuration OK") != std::string::npos);
        // Transports ws, grpc and httpupgrade are deprecated by Xray itself and always warn.
        // A deprecated *field* of ours would name it, e.g. "host" in "headers".
        CHECK(result.output.find("\"headers\"") == std::string::npos);
    };

    std::vector<SingboxNode> all;
    int n = 0;
    for (auto& item : cases) {
        item.node.interface_name = n == 0 ? "xrtun" : "xrtun" + std::to_string(n + 1);
        ++n;
        check(item.name, {item.node});
        all.push_back(item.node);
    }
    check("all nodes in one config", all);
    std::filesystem::remove_all(dir);
}
