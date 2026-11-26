#include <doctest/doctest.h>

#include "../src/cmd/core_cmd.hpp"

using namespace keen_pbr3;

TEST_CASE("core command: no arguments and status show the status") {
    auto command = parse_core_command({});
    CHECK(command.action == CoreCommand::Action::Status);
    CHECK_FALSE(command.json);
    command = parse_core_command({"status"});
    CHECK(command.action == CoreCommand::Action::Status);
    command = parse_core_command({"status", "--json"});
    CHECK(command.action == CoreCommand::Action::Status);
    CHECK(command.json);
}

TEST_CASE("core command: switching names the core and an optional Xray binary") {
    auto command = parse_core_command({"xray"});
    CHECK(command.action == CoreCommand::Action::Switch);
    CHECK(command.core == "xray");
    CHECK(command.xray_bin.empty());

    command = parse_core_command({"xray", "--xray-bin", "/opt/sbin/xray"});
    CHECK(command.core == "xray");
    CHECK(command.xray_bin == "/opt/sbin/xray");

    command = parse_core_command({"xray", "--xray-bin=/tmp/xray"});
    CHECK(command.xray_bin == "/tmp/xray");

    command = parse_core_command({"sing-box"});
    CHECK(command.action == CoreCommand::Action::Switch);
    CHECK(command.core == "sing-box");
}

TEST_CASE("core command: bad arguments are usage errors") {
    CHECK_THROWS_AS(parse_core_command({"bogus"}), CoreUsageError);
    CHECK_THROWS_AS(parse_core_command({"xray", "--xray-bin"}), CoreUsageError);
    CHECK_THROWS_AS(parse_core_command({"xray", "--nope"}), CoreUsageError);
    CHECK_THROWS_AS(parse_core_command({"xray", "extra"}), CoreUsageError);
    CHECK_THROWS_AS(parse_core_command({"status", "xray"}), CoreUsageError);
    CHECK_THROWS_AS(parse_core_command({"status", "--xray-bin", "x"}), CoreUsageError);
    CHECK(std::string(core_usage()).find("keen-pbr-sx core xray") != std::string::npos);
}

TEST_CASE("core command: output formats") {
    const nlohmann::json status{{"core", "xray"},
                                {"xray_bin", "/opt/sbin/xray"},
                                {"xray_running", true},
                                {"singbox_running", false},
                                {"error", ""},
                                {"interfaces",
                                 nlohmann::json::array({{{"name", "xrtun"}, {"tag", "hu"}, {"unsupported", false}, {"up", true}},
                                                        {{"name", "sbtun2"}, {"tag", "es"}, {"unsupported", true}, {"up", false}}})}};
    const auto text = format_core_status(status);
    CHECK(text.find("Core: xray") != std::string::npos);
    CHECK(text.find("xrtun") != std::string::npos);
    CHECK(text.find("State: ok") != std::string::npos);

    auto failed = status;
    failed["error"] = "Xray did not bring up xrtun";
    CHECK(format_core_status(failed).find("State: ERROR: Xray did not bring up xrtun") != std::string::npos);
}
