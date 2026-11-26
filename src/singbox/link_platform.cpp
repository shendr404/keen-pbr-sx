#include "link_store.hpp"
#include "xray_config.hpp"

#include "../http/http_client.hpp"
#include "../util/safe_exec.hpp"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

namespace keen_pbr3 {
namespace {

std::string start_stop_daemon() {
    for (const char* path : {"/opt/sbin/start-stop-daemon", "/opt/bin/start-stop-daemon",
                             "/usr/sbin/start-stop-daemon", "/sbin/start-stop-daemon"}) {
        std::ifstream probe(path);
        if (probe) return path;
    }
    return "start-stop-daemon";
}

bool singbox_script(const char* action) {
    for (const char* script : {"/opt/etc/init.d/S99sing-box", "/opt/etc/init.d/S98sing-box"}) {
        std::ifstream probe(script);
        if (!probe) continue;
        const auto result = safe_exec_capture_with_timeouts(
            {script, action}, safe_exec_timeouts(), true, 0, true, false);
        return result.exit_code == 0;
    }
    return std::string(action) == "stop";
}

void stop_packaged_xray() {
    // The Entware init must not also hold a TUN. Stopping it does not write flash.
    for (const char* script : {"/opt/etc/init.d/S24xray", "/opt/etc/init.d/S22xray", "/opt/etc/init.d/S99xray"}) {
        std::ifstream probe(script);
        if (!probe) continue;
        safe_exec_capture_with_timeouts({script, "stop"}, safe_exec_timeouts(), true, 0, true, false);
    }
}

bool xray_process(const std::string& action, const std::string& bin, const std::string& config) {
    const auto ssd = start_stop_daemon();
    const std::string pid = "/tmp/keen-pbr-sx-xray.pid";
    if (action != "stop") stop_packaged_xray();
    if (action == "stop") {
        const auto result = safe_exec_capture_with_timeouts(
            {ssd, "-K", "-p", pid}, safe_exec_timeouts(), true, 0, true, false);
        return result.exit_code == 0 || result.exit_code == 1;
    }
    safe_exec_capture_with_timeouts({ssd, "-K", "-p", pid}, safe_exec_timeouts(), true, 0, true, false);
    // xray.json sends warnings and errors to this file. Start each run with an
    // empty one so it stays small on tmpfs.
    { std::ofstream truncate(kXrayLogPath, std::ios::trunc); }
    const auto result = safe_exec_capture_with_timeouts(
        {ssd, "-S", "-b", "-m", "-p", pid, "-x", bin, "--", "run", "-format", "json", "-c", config},
        safe_exec_timeouts(), true, 0, true, false);
    return result.exit_code == 0;
}

bool interface_up(const std::string& name) {
    if (name.empty() || name.find('/') != std::string::npos) return false;
    std::ifstream input("/sys/class/net/" + name + "/flags");
    if (!input) return false;
    std::string text;
    input >> text;
    if (text.empty()) return false;
    try {
        return (std::stoul(text, nullptr, 0) & 0x1U) != 0;  // IFF_UP
    } catch (const std::exception&) {
        return false;
    }
}

bool wait_interfaces_up(const std::vector<std::string>& names, int timeout_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        bool all = true;
        for (const auto& name : names) {
            if (!interface_up(name)) {
                all = false;
                break;
            }
        }
        if (all) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

std::string read_meminfo() {
    std::ifstream input("/proc/meminfo");
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

}  // namespace

SingboxLinkService make_singbox_link_service() {
    SingboxPaths paths;
    if (const char* value = std::getenv("KEEN_PBR_SINGBOX_STORE")) paths.store = value;
    if (const char* value = std::getenv("KEEN_PBR_SINGBOX_CONFIG")) paths.singbox_config = value;
    if (const char* value = std::getenv("KEEN_PBR_SINGBOX_BIN")) paths.singbox_bin = value;

    return SingboxLinkService(
        paths,
        [bin = paths.singbox_bin](const std::string& config, std::string* error) {
            // Keep a bounded merged stderr so the UI can show the FATAL/ERROR line.
            // format_singbox_check_error redacts uuids, passwords and keys.
            const auto result = safe_exec_capture_with_timeouts(
                {bin, "check", "-c", config}, safe_exec_timeouts(), false, std::size_t{2} * 1024U, true, true);
            if (error) *error = result.timed_out ? "timed out" : result.stdout_output;
            return result.exit_code;
        },
        {},
        [] {
            if (!singbox_script("restart")) throw std::runtime_error("sing-box restart failed");
            return true;
        },
        [](const std::string& url, const SubscriptionStopFn& stopping) {
            HttpClient client;
            client.set_timeout(std::chrono::seconds{20});
            client.set_max_response_size(std::size_t{2} * 1024U * 1024U);
            // Do not wait behind unrelated transfers outside curl's timeout.
            return client.download(url, {0, true, stopping});
        },
        {},
        [](const std::string& core, const std::string& action, const std::string& bin, const std::string& config) {
            if (core == "sing-box") return singbox_script(action == "stop" ? "stop" : "restart");
            return xray_process(action, bin, config);
        },
        [](const std::string& bin, const std::string& config, std::string* error) {
            const auto result = safe_exec_capture_with_timeouts(
                {bin, "run", "-test", "-format", "json", "-c", config}, safe_exec_timeouts(), false, std::size_t{2} * 1024U, true, true);
            if (error) *error = result.timed_out ? "xray run -test timed out" : result.stdout_output;
            return result.exit_code;
        },
        [](const std::string& bin) {
            const auto result = safe_exec_capture_with_timeouts(
                {bin, "version"}, safe_exec_timeouts(), false, std::size_t{2} * 1024U, true, true);
            return result.stdout_output;
        },
        [] { return ram_total_kib(read_meminfo()); }, wait_interfaces_up);
}

}  // namespace keen_pbr3
