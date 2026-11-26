#include <doctest/doctest.h>

#include "../src/singbox/link_store.hpp"
#include "../src/singbox/xray_config.hpp"

#include <filesystem>
#include <fstream>
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
