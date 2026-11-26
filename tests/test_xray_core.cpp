#include <doctest/doctest.h>

#include "../src/singbox/link_store.hpp"
#include "../src/singbox/xray_config.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>

using namespace keen_pbr3;

namespace {

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

const char* kVless =
    "vless://11111111-1111-1111-1111-111111111111@example.com:443"
    "?security=reality&pbk=PUBKEY&sid=abcd&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision"
    "&pqv=MLDSA&encryption=mlkem768x25519plus.native.600s&type=xhttp&path=%2Fxh&host=www.example.com&mode=auto#Node";

// sing-box 1.14 rejects VLESS encryption, so the switch starts from a link it can store.
const char* kVlessSingbox =
    "vless://11111111-1111-1111-1111-111111111111@example.com:443"
    "?security=reality&pbk=PUBKEY&sid=abcd&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision"
    "&pqv=MLDSA&type=tcp#Node";

}  // namespace

TEST_CASE("xray version gate and ram warning") {
    CHECK(xray_version_at_least("Xray 26.10.29 (Xray, Penetrates Everything.)", 26, 10, 17));
    CHECK(xray_version_at_least("26.10.17", 26, 10, 17));
    CHECK_FALSE(xray_version_at_least("Xray 26.10.16", 26, 10, 17));
    CHECK_FALSE(xray_version_at_least("Xray 26.1.23", 26, 10, 17));
    CHECK_FALSE(xray_version_at_least("not a version", 26, 10, 17));
    CHECK(ram_below_xray_comfort(254L * 1024L));
    CHECK_FALSE(ram_below_xray_comfort(512L * 1024L));
    CHECK_FALSE(ram_below_xray_comfort(0));
    CHECK(ram_total_kib("MemTotal:        260096 kB\nMemFree: 1 kB\n") == 260096);
    CHECK(std::string(tun_prefix_for_core("xray")) == "xrtun");
    CHECK(std::string(tun_prefix_for_core("sing-box")) == "sbtun");
}

TEST_CASE("xray config carries reality, xhttp and vless encryption") {
    const auto view = classify_link_for_core(kVless, "xray");
    REQUIRE(view.supported);
    CHECK(view.protocol == "vless");
    const auto& reality = view.outbound.at("streamSettings").at("realitySettings");
    CHECK(reality.at("publicKey") == "PUBKEY");
    CHECK(reality.at("shortId") == "abcd");
    CHECK(reality.at("serverName") == "www.example.com");
    CHECK(reality.at("fingerprint") == "chrome");
    CHECK(reality.at("mldsa65Verify") == "MLDSA");
    CHECK(view.outbound.at("streamSettings").at("network") == "xhttp");
    CHECK(view.outbound.at("streamSettings").at("xhttpSettings").at("path") == "/xh");
    CHECK(view.outbound.at("streamSettings").at("xhttpSettings").at("mode") == "auto");
    CHECK(view.outbound.at("settings").at("vnext")[0].at("users")[0].at("encryption") ==
          "mlkem768x25519plus.native.600s");
    CHECK(view.outbound.at("settings").at("vnext")[0].at("users")[0].at("flow") == "xtls-rprx-vision");

    const auto trojan = classify_link_for_core("trojan://pw@a.example:443#t", "xray");
    CHECK_FALSE(trojan.supported);
    CHECK(trojan.reason.find("Xray") != std::string::npos);

    const auto ws = classify_link_for_core(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&security=tls&path=%2Fvpn&host=example.com#W",
        "xray");
    REQUIRE(ws.supported);
    CHECK(ws.outbound.at("streamSettings").at("network") == "ws");
    CHECK(ws.outbound.at("streamSettings").at("wsSettings").at("path") == "/vpn");

    const auto grpc = classify_link_for_core(
        "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=grpc&serviceName=GunService#G", "xray");
    REQUIRE(grpc.supported);
    CHECK(grpc.outbound.at("streamSettings").at("grpcSettings").at("serviceName") == "GunService");
}

TEST_CASE("urltest members keep the tag and follow a renamed tun") {
    nlohmann::json config = {{"outbounds", nlohmann::json::array({{
        {"type", "urltest"},
        {"tag", "proxy"},
        {"outbound_groups", nlohmann::json::array({{
            {"members", nlohmann::json::array({
                "Node",
                "sbtun",
                {{"outbound", "Node"}},
                {{"outbound", "sbtun"}, {"interface", "sbtun"}},
            })},
            {"outbounds", nlohmann::json::array({"Node", "sbtun"})},
        }})},
    }})}};
    apply_interface_renames(config, {InterfaceRename{"Node", "sbtun", "xrtun"}});
    const auto& members = config["outbounds"][0]["outbound_groups"][0]["members"];
    CHECK(members[0] == "Node");
    CHECK(members[1] == "xrtun");
    CHECK(members[2]["outbound"] == "Node");
    CHECK(members[3]["outbound"] == "xrtun");
    CHECK(members[3]["interface"] == "xrtun");
    CHECK(config["outbounds"][0]["outbound_groups"][0]["outbounds"][0] == "Node");
    CHECK(config["outbounds"][0]["outbound_groups"][0]["outbounds"][1] == "xrtun");

    nlohmann::json same_name = {{"outbounds", nlohmann::json::array({{
        {"type", "icmptest"},
        {"tag", "probe"},
        {"outbound_groups", nlohmann::json::array({{
            {"members", nlohmann::json::array({{{"outbound", "sbtun"}}})},
        }})},
    }})}};
    apply_interface_renames(same_name, {InterfaceRename{"sbtun", "sbtun", "xrtun"}});
    CHECK(same_name["outbounds"][0]["outbound_groups"][0]["members"][0]["outbound"] == "sbtun");
}

TEST_CASE("switching to xray renames interfaces and rolls back a failed start") {
    const auto root = std::filesystem::temp_directory_path() / "keen-pbr-sx-xray-switch";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    SingboxPaths paths;
    paths.store = (root / "links.json").string();
    paths.singbox_config = (root / "sing-box.json").string();
    int keenetic_calls = 0;
    nlohmann::json saved;
    SingboxLinkService service(
        paths, [](const std::string&, std::string*) { return 0; },
        [&](const KeeneticSyncRequest& request) {
            ++keenetic_calls;
            saved = request.proxy;
            saved["nodes"] = nlohmann::json::array();
            for (const auto& node : request.nodes) {
                saved["nodes"].push_back({{"tag", node.tag}, {"interface", node.interface_name}});
            }
            saved["renames"] = nlohmann::json::array();
            for (const auto& rename : request.renames) {
                saved["renames"].push_back({{"from", rename.from}, {"to", rename.to}, {"tag", rename.tag}});
            }
        },
        [] { return true; });
    int starts = 0;
    std::string tested_config;
    auto hooks = [&](const std::string& version, bool xray_starts, int test_code) {
        service.set_core_hooks(
            [&, xray_starts](const std::string& core, const std::string& action, const std::string&, const std::string&) {
                if (action == "start") ++starts;
                if (core == "xray" && action == "start") return xray_starts;
                return true;
            },
            [test_code, &tested_config](const std::string&, const std::string& config, std::string* error) {
                tested_config = config;
                if (test_code != 0 && error) *error = "xray run -test failed";
                return test_code;
            },
            [version](const std::string&) { return version; }, [] { return 254L * 1024L; });
    };
    hooks("26.10.29", true, 0);
    const auto added = service.add_links({std::string(kVlessSingbox) + "\ntrojan://pw@b.example:443#Other"}, {});
    REQUIRE(added.state["nodes"].size() == 2);
    CHECK(added.state["nodes"][0]["interface"] == "sbtun");
    CHECK(added.state["nodes"][1]["interface"] == "sbtun2");
    CHECK(added.state["ram_warning"] == true);
    const int after_add = keenetic_calls;

    hooks("26.10.16", true, 0);
    starts = 0;
    CHECK_THROWS_WITH(service.switch_core("xray", "/opt/bin/xray", true),
                      "Xray 26.10.16 is older than 26.10.17. The core was not switched.");
    CHECK(keenetic_calls == after_add);
    CHECK(starts == 0);
    CHECK(service.state()["core"] == "sing-box");
    CHECK(service.state()["nodes"][0]["interface"] == "sbtun");

    hooks("26.10.29", true, 1);
    CHECK_THROWS_WITH(service.switch_core("xray", "/opt/bin/xray", false), "xray run -test failed");
    CHECK(std::filesystem::path(tested_config).filename() == "xray.candidate.json");
    CHECK(keenetic_calls == after_add);
    CHECK(starts == 0);
    CHECK(service.state()["core"] == "sing-box");

    hooks("26.10.29", false, 0);
    CHECK_THROWS_WITH(service.switch_core("xray", "/opt/bin/xray", false), "could not start xray");
    CHECK(keenetic_calls == after_add);
    CHECK(service.state()["core"] == "sing-box");
    CHECK(service.state()["nodes"][0]["interface"] == "sbtun");

    hooks("Xray 26.10.29 (Xray, Penetrates Everything.)", true, 0);
    const auto switched = service.switch_core("xray", "/opt/bin/xray", true);
    CHECK(switched.state["core"] == "xray");
    CHECK(switched.state["nodes"][0]["interface"] == "xrtun");
    CHECK(switched.state["nodes"][1]["unsupported"] == true);
    CHECK(switched.state["nodes"][1]["interface"] == "sbtun2");
    CHECK(switched.state["nodes"][1]["unsupported_reason"].get<std::string>().find("Xray") != std::string::npos);
    CHECK(switched.warning.find("icmptest") != std::string::npos);
    CHECK(saved["nodes"][0]["interface"] == "xrtun");
    CHECK(saved["core"] == "xray");
    REQUIRE(saved["renames"].size() == 1);
    CHECK(saved["renames"][0]["from"] == "sbtun");
    CHECK(saved["renames"][0]["to"] == "xrtun");
    const auto xray = nlohmann::json::parse(read_file(root / "xray.json"));
    CHECK(xray["inbounds"][0]["protocol"] == "tun");
    CHECK(xray["inbounds"][0]["settings"]["name"] == "xrtun");
    CHECK(xray["inbounds"][0]["settings"]["autoSystemRoutingTable"] == false);
    CHECK(xray["inbounds"][0]["settings"]["autoSystemDnsToGateway"] == false);
    CHECK(xray["inbounds"].size() == 1);
    CHECK(xray["outbounds"][0]["streamSettings"]["network"] == "tcp");
    CHECK(xray["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] == "PUBKEY");

    const auto encrypted = service.add_links({kVless}, {});
    CHECK(encrypted.state["nodes"].size() == 3);
    CHECK(encrypted.state["nodes"][2]["unsupported"] == false);
    const auto with_encryption = nlohmann::json::parse(read_file(root / "xray.json"));
    CHECK(with_encryption["inbounds"].size() == 2);
    CHECK(with_encryption["outbounds"][1]["settings"]["vnext"][0]["users"][0]["encryption"] ==
          "mlkem768x25519plus.native.600s");
    std::filesystem::remove_all(root);
}

namespace {

// Fake values only. Shaped like a subscription node saved by sing-box mode.
nlohmann::json fake_singbox_reality_outbound() {
    return {{"type", "vless"},
            {"tag", "node"},
            {"server", "203.0.113.10"},
            {"server_port", 443},
            {"uuid", "22222222-2222-2222-2222-222222222222"},
            {"flow", "xtls-rprx-vision"},
            {"packet_encoding", "xudp"},
            {"tls",
             {{"enabled", true},
              {"server_name", "www.example.org"},
              {"utls", {{"enabled", true}, {"fingerprint", "firefox"}}},
              {"reality", {{"enabled", true}, {"public_key", "FAKEPUBLICKEY"}, {"short_id", "0123abcd"}}}}}};
}

nlohmann::json fake_hysteria2_outbound() {
    return {{"type", "hysteria2"},
            {"tag", "node"},
            {"server", "203.0.113.20"},
            {"server_port", 443},
            {"password", "fake-password"},
            {"tls", {{"enabled", true}, {"server_name", "203.0.113.20"}}}};
}

nlohmann::json store_node(const std::string& id, const std::string& tag, const std::string& iface,
                          const nlohmann::json& outbound) {
    return {{"id", id},
            {"name", tag},
            {"tag", tag},
            {"protocol", outbound.at("type")},
            {"server", outbound.at("server")},
            {"port", outbound.at("server_port")},
            {"interface", iface},
            {"subscription_id", "sfake"},
            {"outbound", outbound}};
}

void write_text(const std::filesystem::path& path, const std::string& body) {
    std::ofstream output(path);
    output << body;
}

}  // namespace

TEST_CASE("sing-box vless reality outbound becomes an xray outbound") {
    const auto xray = singbox_outbound_to_xray(fake_singbox_reality_outbound());
    CHECK(xray.at("protocol") == "vless");
    CHECK_FALSE(xray.contains("tag"));
    const auto& server = xray.at("settings").at("vnext")[0];
    CHECK(server.at("address") == "203.0.113.10");
    CHECK(server.at("port") == 443);
    CHECK(server.at("users")[0].at("id") == "22222222-2222-2222-2222-222222222222");
    CHECK(server.at("users")[0].at("encryption") == "none");
    CHECK(server.at("users")[0].at("flow") == "xtls-rprx-vision");
    const auto& stream = xray.at("streamSettings");
    CHECK(stream.at("network") == "tcp");
    CHECK(stream.at("security") == "reality");
    CHECK(stream.at("realitySettings").at("serverName") == "www.example.org");
    CHECK(stream.at("realitySettings").at("publicKey") == "FAKEPUBLICKEY");
    CHECK(stream.at("realitySettings").at("shortId") == "0123abcd");
    CHECK(stream.at("realitySettings").at("fingerprint") == "firefox");

    auto ws = fake_singbox_reality_outbound();
    ws["tls"] = {{"enabled", true}, {"server_name", "cdn.example.org"}, {"alpn", {"http/1.1"}}};
    ws["transport"] = {{"type", "ws"}, {"path", "/ws"}, {"headers", {{"Host", "cdn.example.org"}}}};
    const auto ws_xray = singbox_outbound_to_xray(ws);
    CHECK(ws_xray["streamSettings"]["network"] == "ws");
    CHECK(ws_xray["streamSettings"]["security"] == "tls");
    CHECK(ws_xray["streamSettings"]["wsSettings"]["path"] == "/ws");
    CHECK(ws_xray["streamSettings"]["wsSettings"]["headers"]["Host"] == "cdn.example.org");
    CHECK(ws_xray["streamSettings"]["tlsSettings"]["alpn"][0] == "http/1.1");

    auto grpc = fake_singbox_reality_outbound();
    grpc["transport"] = {{"type", "grpc"}, {"service_name", "Gun"}};
    CHECK(singbox_outbound_to_xray(grpc)["streamSettings"]["grpcSettings"]["serviceName"] == "Gun");

    auto http = fake_singbox_reality_outbound();
    http["transport"] = {{"type", "http"}, {"path", "/h"}, {"host", {"a.example.org"}}};
    const auto http_xray = singbox_outbound_to_xray(http);
    CHECK(http_xray["streamSettings"]["network"] == "xhttp");
    CHECK(http_xray["streamSettings"]["xhttpSettings"]["mode"] == "stream-one");
    CHECK(http_xray["streamSettings"]["xhttpSettings"]["host"] == "a.example.org");

    auto quic = fake_singbox_reality_outbound();
    quic["transport"] = {{"type", "quic"}};
    CHECK_THROWS_WITH(singbox_outbound_to_xray(quic), "transport quic is not supported by Xray");
    CHECK_THROWS_WITH(singbox_outbound_to_xray(fake_hysteria2_outbound()),
                      "protocol hysteria2 is not supported by Xray");
}

TEST_CASE("a subscription node without a link is classified from its outbound") {
    SingboxNode vless;
    vless.id = "nfake1";
    vless.tag = "hu_fake";
    vless.protocol = "vless";
    vless.interface_name = "xrtun";
    vless.outbound = fake_singbox_reality_outbound();
    const auto view = classify_node_for_core(vless, "xray");
    REQUIRE(view.supported);
    CHECK(view.outbound["streamSettings"]["realitySettings"]["publicKey"] == "FAKEPUBLICKEY");
    CHECK(classify_node_for_core(vless, "sing-box").supported);

    SingboxNode hy2 = vless;
    hy2.protocol = "hysteria2";
    hy2.outbound = fake_hysteria2_outbound();
    const auto hy2_view = classify_node_for_core(hy2, "xray");
    CHECK_FALSE(hy2_view.supported);
    CHECK(hy2_view.reason == "protocol hysteria2 is not supported by Xray");

    const auto config = render_xray_config({vless});
    REQUIRE(config["inbounds"].size() == 1);
    CHECK(config["inbounds"][0]["settings"]["name"] == "xrtun");
    CHECK(config["outbounds"][0]["protocol"] == "vless");
    CHECK(config["routing"]["rules"].size() == 1);
    CHECK(config["log"]["error"] == "/tmp/keen-pbr-sx-xray.log");
    CHECK(xray_tun_interfaces(config) == std::vector<std::string>{"xrtun"});
}

TEST_CASE("render_xray_config refuses an empty or lossy config") {
    CHECK_THROWS_WITH(render_xray_config({}), "Xray config has no TUN inbounds: no node can be carried by Xray");
    CHECK(render_xray_config({}, true)["inbounds"].empty());
    SingboxNode hy2;
    hy2.id = "nfake2";
    hy2.tag = "es_fake";
    hy2.protocol = "hysteria2";
    hy2.interface_name = "xrtun";
    hy2.outbound = fake_hysteria2_outbound();
    CHECK_THROWS_WITH(render_xray_config({hy2}),
                      "Xray config has no outbound for es_fake (xrtun): protocol hysteria2 is not supported by Xray");
}

TEST_CASE("switch to xray from stored outbounds is make-before-break") {
    const auto root = std::filesystem::temp_directory_path() / "keen-pbr-sx-xray-stored";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    SingboxPaths paths;
    paths.store = (root / "links.json").string();
    paths.singbox_config = (root / "sing-box.json").string();
    // The user's own sing-box TUN (sbtun) is not in the store.
    write_text(paths.singbox_config,
               nlohmann::json{{"inbounds", nlohmann::json::array({{{"type", "tun"},
                                                                     {"tag", "user-tun"},
                                                                     {"interface_name", "sbtun"}}})}}
                   .dump());
    const nlohmann::json store{{"nodes", nlohmann::json::array({
                                             store_node("nfake1", "hu_fake", "sbtun2", fake_singbox_reality_outbound()),
                                             store_node("nfake2", "es_fake", "sbtun3", fake_hysteria2_outbound()),
                                         })},
                               {"subscriptions", nlohmann::json::array()}};
    write_text(paths.store, store.dump());

    std::vector<std::string> events;
    int keenetic_calls = 0;
    SingboxLinkService service(
        paths, [](const std::string&, std::string*) { return 0; },
        [&](const KeeneticSyncRequest&) {
            ++keenetic_calls;
            events.push_back("keenetic");
        },
        [] { return true; });
    bool interfaces_come_up = false;
    std::vector<std::string> waited;
    service.set_core_hooks(
        [&](const std::string& core, const std::string& action, const std::string&, const std::string&) {
            events.push_back(core + ":" + action);
            return true;
        },
        [](const std::string&, const std::string&, std::string*) { return 0; },
        [](const std::string&) { return std::string("Xray 26.10.29"); }, [] { return 512L * 1024L; });
    service.set_interface_wait(
        [&](const std::vector<std::string>& names, int) {
            waited = names;
            events.push_back("wait");
            return interfaces_come_up;
        },
        1000);

    // DNS detours through the user's sbtun, which stops with sing-box.
    const nlohmann::json keen{
        {"outbounds", nlohmann::json::array({
                          {{"type", "interface"}, {"tag", "tun_hu"}, {"interface", "sbtun"}},
                          {{"type", "interface"}, {"tag", "hu_fake"}, {"interface", "sbtun2"}},
                          {{"type", "interface"}, {"tag", "es_fake"}, {"interface", "sbtun3"}},
                          {{"type", "urltest"},
                           {"tag", "vpn"},
                           {"outbound_groups",
                            nlohmann::json::array({{{"members", nlohmann::json::array({{{"outbound", "es_fake"}}})}}})}},
                      })},
        {"route", {{"rules", nlohmann::json::array({{{"outbound", "hu_fake"}}})}}},
        {"dns",
         {{"servers", nlohmann::json::array({{{"tag", "tun_dns"}, {"address", "8.8.8.8"}, {"detour", "tun_hu"}}})}}}};
    CHECK_THROWS_WITH_AS(service.switch_core("xray", "/opt/bin/xray", false, keen),
                         doctest::Contains("DNS server tun_dns (detour tun_hu)"), std::runtime_error);
    CHECK(events.empty());
    CHECK(service.state()["core"] == "sing-box");

    // A rule on a group whose only member is hysteria2 is refused too.
    auto group_rule = keen;
    group_rule["dns"]["servers"][0]["detour"] = "hu_fake";
    group_rule["route"]["rules"].push_back({{"outbound", "vpn"}});
    CHECK_THROWS_WITH_AS(service.switch_core("xray", "/opt/bin/xray", false, group_rule),
                         doctest::Contains("route rule 2 -> vpn"), std::runtime_error);
    CHECK(events.empty());

    // DNS through a node Xray carries is fine. xrtun never comes up: roll back,
    // sing-box is never stopped and keen-pbr-sx is not retargeted.
    auto usable = keen;
    usable["dns"]["servers"][0]["detour"] = "hu_fake";
    CHECK_THROWS_WITH_AS(service.switch_core("xray", "/opt/bin/xray", false, usable),
                         doctest::Contains("sing-box was left running"), std::runtime_error);
    CHECK(waited == std::vector<std::string>{"xrtun"});
    CHECK(events == std::vector<std::string>{"xray:start", "wait", "xray:stop"});
    CHECK(keenetic_calls == 0);
    CHECK(service.state()["core"] == "sing-box");
    CHECK(service.state()["nodes"][0]["interface"] == "sbtun2");

    events.clear();
    interfaces_come_up = true;
    const auto switched = service.switch_core("xray", "/opt/bin/xray", false, usable);
    CHECK(events == std::vector<std::string>{"xray:start", "wait", "keenetic", "sing-box:stop"});
    CHECK(switched.state["core"] == "xray");
    CHECK(switched.state["nodes"][0]["interface"] == "xrtun");
    CHECK(switched.state["nodes"][0]["unsupported"] == false);
    CHECK(switched.state["nodes"][1]["unsupported"] == true);
    CHECK(switched.state["nodes"][1]["unsupported_reason"] == "protocol hysteria2 is not supported by Xray");
    const auto xray = nlohmann::json::parse(read_file(root / "xray.json"));
    REQUIRE(xray["inbounds"].size() == 1);
    CHECK(xray["inbounds"][0]["settings"]["name"] == "xrtun");
    CHECK(xray["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] == "FAKEPUBLICKEY");
    // The sing-box outbound is kept so the node can go back to sing-box.
    const auto saved = nlohmann::json::parse(read_file(root / "links.json"));
    CHECK(saved["nodes"][0]["outbound"]["type"] == "vless");
    std::filesystem::remove_all(root);
}

TEST_CASE("switch to xray with nothing Xray can carry keeps sing-box") {
    const auto root = std::filesystem::temp_directory_path() / "keen-pbr-sx-xray-empty";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    SingboxPaths paths;
    paths.store = (root / "links.json").string();
    paths.singbox_config = (root / "sing-box.json").string();
    write_text(paths.store, nlohmann::json{{"nodes", nlohmann::json::array({store_node(
                                                         "nfake2", "es_fake", "sbtun", fake_hysteria2_outbound())})},
                                           {"subscriptions", nlohmann::json::array()}}
                                .dump());
    std::vector<std::string> events;
    SingboxLinkService service(
        paths, [](const std::string&, std::string*) { return 0; }, [&](const KeeneticSyncRequest&) {
            events.push_back("keenetic");
        },
        [] { return true; });
    service.set_core_hooks(
        [&](const std::string& core, const std::string& action, const std::string&, const std::string&) {
            events.push_back(core + ":" + action);
            return true;
        },
        [&](const std::string&, const std::string&, std::string*) {
            events.push_back("test");
            return 0;
        },
        [](const std::string&) { return std::string("Xray 26.10.29"); }, [] { return 512L * 1024L; });
    CHECK_THROWS_WITH(service.switch_core("xray", "/opt/bin/xray", false),
                      "Xray config has no TUN inbounds: no node can be carried by Xray");
    CHECK(events.empty());
    CHECK_FALSE(std::filesystem::exists(root / "xray.json"));
    CHECK(service.state()["core"] == "sing-box");
    std::filesystem::remove_all(root);
}

TEST_CASE("core_switch_blockers ignores groups with a surviving member") {
    const nlohmann::json config{
        {"outbounds", nlohmann::json::array({
                          {{"type", "interface"}, {"tag", "a"}, {"interface", "sbtun"}},
                          {{"type", "interface"}, {"tag", "b"}, {"interface", "xrtun"}},
                          {{"type", "urltest"},
                           {"tag", "g"},
                           {"outbound_groups", nlohmann::json::array({{{"members", nlohmann::json::array({
                                                                                       {{"outbound", "a"}},
                                                                                       {{"outbound", "b"}},
                                                                                   })}}})}},
                      })},
        {"route", {{"rules", nlohmann::json::array({{{"outbound", "g"}}, {{"outbound", "a"}, {"enabled", false}}})}}},
        {"dns", {{"servers", nlohmann::json::array({{{"tag", "d"}, {"detour", nullptr}}})}}}};
    CHECK(core_switch_blockers(config, {"sbtun"}).empty());
    CHECK(core_switch_blockers(config, {"sbtun", "xrtun"}).find("route rule 1 -> g") != std::string::npos);
}

namespace {

struct StartupFixture {
    std::filesystem::path root;
    SingboxPaths paths;
    std::vector<std::string> events;
    bool xray_alive{false};
    bool singbox_alive{false};
    bool interfaces_up{true};
    bool xray_test_ok{true};
    std::unique_ptr<SingboxLinkService> service;

    explicit StartupFixture(const std::string& name) {
        root = std::filesystem::temp_directory_path() / name;
        std::filesystem::remove_all(root);
        std::filesystem::create_directories(root);
        paths.store = (root / "links.json").string();
        paths.singbox_config = (root / "sing-box.json").string();
        write_text(paths.singbox_config, "{}");
        auto node = store_node("nfake1", "hu_fake", "xrtun", fake_singbox_reality_outbound());
        write_text(paths.store, nlohmann::json{{"nodes", nlohmann::json::array({node})},
                                               {"subscriptions", nlohmann::json::array()}}
                                    .dump());
        service = std::make_unique<SingboxLinkService>(
            paths, [](const std::string&, std::string*) { return 0; }, [](const KeeneticSyncRequest&) {},
            [] { return true; });
        service->set_core_hooks(
            [this](const std::string& core, const std::string& action, const std::string&, const std::string&) {
                if (action == "alive") return core == "xray" ? xray_alive : singbox_alive;
                events.push_back(core + ":" + action);
                if (core == "xray") xray_alive = action == "start";
                if (core == "sing-box") singbox_alive = action == "start";
                return true;
            },
            [this](const std::string&, const std::string&, std::string* error) {
                events.push_back("xray:test");
                if (!xray_test_ok && error) *error = "bad config";
                return xray_test_ok ? 0 : 1;
            },
            [](const std::string&) { return std::string("Xray 26.10.29"); }, [] { return 512L * 1024L; });
        service->set_interface_wait(
            [this](const std::vector<std::string>&, int) {
                events.push_back("wait");
                return interfaces_up;
            },
            1000);
    }
    ~StartupFixture() { std::filesystem::remove_all(root); }
};

}  // namespace

TEST_CASE("startup with proxy.core=xray writes xray.json, starts Xray and stops a stray sing-box") {
    StartupFixture fixture("keen-pbr-sx-xray-startup");
    fixture.singbox_alive = true;  // S99sing-box got there first
    fixture.service->set_proxy("xray", "/opt/bin/xray");

    const auto result = fixture.service->ensure_core_running();
    CHECK(result.ok);
    CHECK(result.changed);
    CHECK(fixture.events ==
          std::vector<std::string>{"xray:test", "xray:start", "wait", "sing-box:stop"});
    const auto xray = nlohmann::json::parse(read_file(fixture.root / "xray.json"));
    CHECK(xray["inbounds"][0]["settings"]["name"] == "xrtun");
    CHECK_FALSE(fixture.singbox_alive);
    CHECK(fixture.service->core_error().empty());

    // A second call (reload, restart of the service) finds Xray alive with the
    // same config and its interfaces up: nothing is restarted.
    fixture.events.clear();
    const auto again = fixture.service->ensure_core_running();
    CHECK(again.ok);
    CHECK_FALSE(again.changed);
    CHECK(fixture.events == std::vector<std::string>{"wait"});

    // The status shows the live core.
    const auto status = fixture.service->core_status();
    CHECK(status["core"] == "xray");
    CHECK(status["xray_running"] == true);
    CHECK(status["singbox_running"] == false);
    CHECK(status["interfaces"][0]["name"] == "xrtun");
    CHECK(status["interfaces"][0]["up"] == true);
}

TEST_CASE("startup restarts a dead Xray with the existing config") {
    StartupFixture fixture("keen-pbr-sx-xray-startup-dead");
    fixture.service->set_proxy("xray", "");
    REQUIRE(fixture.service->ensure_core_running().ok);
    fixture.xray_alive = false;  // the box rebooted
    fixture.events.clear();
    const auto result = fixture.service->ensure_core_running();
    CHECK(result.ok);
    CHECK(result.changed);
    CHECK(fixture.events == std::vector<std::string>{"xray:start", "wait"});
}

TEST_CASE("startup with a failing Xray keeps sing-box off and reports the error") {
    StartupFixture fixture("keen-pbr-sx-xray-startup-fail");
    fixture.singbox_alive = true;
    fixture.interfaces_up = false;
    fixture.service->set_proxy("xray", "");

    const auto result = fixture.service->ensure_core_running();
    CHECK_FALSE(result.ok);
    CHECK(result.message.find("did not bring up xrtun") != std::string::npos);
    CHECK(result.message.find("/tmp/keen-pbr-sx-xray.log") != std::string::npos);
    CHECK_FALSE(fixture.xray_alive);
    // No silent swap: sing-box is stopped, not left or started in Xray's place.
    CHECK_FALSE(fixture.singbox_alive);
    CHECK(fixture.service->core_error() == result.message);
    CHECK(fixture.service->core_status()["error"] == result.message);

    // A config that fails `xray run -test` is reported and nothing is started.
    StartupFixture rejected("keen-pbr-sx-xray-startup-reject");
    rejected.xray_test_ok = false;
    rejected.service->set_proxy("xray", "");
    const auto bad = rejected.service->ensure_core_running();
    CHECK_FALSE(bad.ok);
    CHECK(bad.message == "bad config");
    CHECK(std::count(rejected.events.begin(), rejected.events.end(), "xray:start") == 0);
    CHECK_FALSE(std::filesystem::exists(rejected.root / "xray.json"));
}

TEST_CASE("startup with proxy.core=sing-box touches nothing") {
    StartupFixture fixture("keen-pbr-sx-xray-startup-singbox");
    fixture.singbox_alive = true;
    fixture.service->set_proxy("sing-box", "");
    const auto result = fixture.service->ensure_core_running();
    CHECK(result.ok);
    CHECK_FALSE(result.changed);
    CHECK(fixture.events.empty());
    CHECK(fixture.singbox_alive);
    // The guard only acts when the core is xray.
    CHECK_FALSE(fixture.service->stop_stray_singbox());
    CHECK(fixture.singbox_alive);
}

TEST_CASE("the stray sing-box guard stops sing-box only while the core is xray") {
    StartupFixture fixture("keen-pbr-sx-xray-guard");
    fixture.service->set_proxy("xray", "");
    CHECK_FALSE(fixture.service->stop_stray_singbox());
    fixture.singbox_alive = true;
    CHECK(fixture.service->stop_stray_singbox());
    CHECK_FALSE(fixture.singbox_alive);
    CHECK(fixture.events == std::vector<std::string>{"sing-box:stop"});
}
