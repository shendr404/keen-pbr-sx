#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

struct SingboxPaths {
    std::string store{"/opt/etc/keen-pbr-sx/sing-box-links.json"};
    std::string singbox_config{"/opt/etc/sing-box/config.json"};
    std::string singbox_bin{"sing-box"};
};

// One proxy node is one TUN interface and one keen-pbr-sx interface outbound.
// Grouping belongs to the Outbounds page, not to this store.
struct SingboxNode {
    std::string id;
    std::string name;
    std::string tag;
    std::string protocol;
    std::string server;
    int port{0};
    std::string link;
    nlohmann::json outbound = nullptr;
    std::string interface_name;
    std::string tun_stack{"gvisor"};
    int tun_mtu{1400};
    std::string tun_address;
    std::string subscription_id;
    std::string identity;
    bool missing{false};
    // Set on refresh when the subscription still lists the node, but sing-box
    // cannot carry it (VLESS Encryption). The interface is kept.
    bool unsupported{false};
    std::string unsupported_reason;
};

struct SingboxCatalogEntry {
    std::string identity;
    std::string name;
    std::string protocol;
    std::string server;
    int port{0};
    bool skipped{false};
    std::string reason;
};

struct SingboxSubscription {
    std::string id;
    std::string url;
    std::string name;
    int interval_hours{0};
    std::int64_t last_refresh{0};
    std::string last_error;
    std::vector<std::string> selected;
    std::vector<SingboxCatalogEntry> catalog;
    int new_nodes{0};
};

struct SingboxStore {
    std::vector<SingboxNode> nodes;
    std::vector<SingboxSubscription> subscriptions;
};

struct SingboxTunOptions {
    std::string tun_stack{"gvisor"};
    int tun_mtu{1400};
    std::string tun_address;
};

struct SingboxNodePatch {
    std::string id;
    std::string tag;
    std::string interface_name;
    std::string tun_stack;
    int tun_mtu{0};
    std::string tun_address;
    bool tun_address_set{false};
};

struct SingboxApplyResult {
    bool singbox_checked{false};
    bool singbox_reloaded{false};
    bool keenetic_applied{false};
    std::string warning;
    std::size_t skipped{0};
    std::vector<std::string> skipped_transports;
    bool encryption_ignored{false};
    nlohmann::json state;
};

// nodes is the full set that should exist. removed_tags are keen-pbr-sx tags that
// this change drops. owned_tags are the tags this store already managed.
struct InterfaceRename {
    std::string tag;
    std::string from;
    std::string to;
};

struct KeeneticSyncRequest {
    std::vector<SingboxNode> nodes;
    std::vector<std::string> removed_tags;
    std::vector<std::string> owned_tags;
    // Old TUN name -> new TUN name. Group members that used the old name are rewritten.
    std::vector<InterfaceRename> renames;
    // When set, written into config.proxy in the same save as the outbounds.
    nlohmann::json proxy;
    bool has_proxy{false};
};

// Group members name outbound tags. Tags stay put across a core switch, so a
// member equal to the tag is left alone. A member that instead stored the old
// TUN name is rewritten to the new one (xrtun, xrtun2, ...).
void apply_interface_renames(nlohmann::json& config, const std::vector<InterfaceRename>& renames);

using SingboxCheck = std::function<int(const std::string& config_path, std::string* error)>;
using KeeneticSyncFn = std::function<void(const KeeneticSyncRequest& request)>;
using SingboxReloadFn = std::function<bool()>;
using SubscriptionStopFn = std::function<bool()>;
using SubscriptionDownloadFn = std::function<std::string(const std::string&, const SubscriptionStopFn&)>;
using SubscriptionClock = std::function<std::int64_t()>;
// core is "sing-box" or "xray". action is "start" or "stop".
// bin and config are the xray executable and xray.json; they are empty for sing-box.
using CoreProcessFn = std::function<bool(const std::string& core, const std::string& action,
                                          const std::string& bin, const std::string& config)>;
using XrayTestFn = std::function<int(const std::string& bin, const std::string& config_path, std::string* error)>;
using XrayVersionFn = std::function<std::string(const std::string& bin)>;
using RamFn = std::function<long()>;
// True once every named interface exists and is up. Gives up after timeout_ms.
using InterfaceWaitFn = std::function<bool(const std::vector<std::string>& names, int timeout_ms)>;

class SingboxBusy : public std::runtime_error {
public:
    SingboxBusy() : std::runtime_error("another sing-box operation is in progress") {}
};

class SingboxLinkService {
public:
    SingboxLinkService(SingboxPaths paths, SingboxCheck check, KeeneticSyncFn keenetic,
                       SingboxReloadFn reload, SubscriptionDownloadFn download = {},
                       SubscriptionClock clock = {}, CoreProcessFn process = {}, XrayTestFn test = {},
                       XrayVersionFn version = {}, RamFn ram = {}, InterfaceWaitFn wait = {});

    void set_keenetic_callback(KeeneticSyncFn keenetic) { keenetic_ = std::move(keenetic); }
    void set_proxy(std::string core, std::string xray_bin);
    void set_core_hooks(CoreProcessFn process, XrayTestFn test, XrayVersionFn version, RamFn ram);
    void set_interface_wait(InterfaceWaitFn wait, int timeout_ms = 20000) {
        interface_wait_ = std::move(wait);
        interface_wait_ms_ = timeout_ms;
    }
    // One core for the router. Recreates TUN names (sbtun* or xrtun*) and
    // asks keenetic sync to retarget interface outbounds and group members.
    // keen_config is the current keen-pbr-sx config. Switching to Xray is
    // refused when a route rule or DNS detour would be left on a TUN that stops
    // with sing-box. Xray starts first; sing-box stops only after the xrtun
    // interfaces are up.
    SingboxApplyResult switch_core(const std::string& core, const std::string& xray_bin, bool icmptest_groups,
                                   const nlohmann::json& keen_config = nlohmann::json());
    nlohmann::json preview(const std::string& link) const;
    // Downloads a subscription and returns nodes plus skipped lines. Does not save.
    nlohmann::json preview_subscription(const std::string& url_or_id) const;
    nlohmann::json state() const;
    std::map<std::string, std::string> subscription_errors() const;

    SingboxApplyResult add_links(const std::vector<std::string>& links, const SingboxTunOptions& tun);
    SingboxApplyResult update_node(const SingboxNodePatch& patch);
    SingboxApplyResult remove_node(const std::string& id);
    // Creates or updates a subscription and adds only the ticked identities.
    SingboxApplyResult save_subscription(const std::string& url, int interval_hours,
                                         const std::vector<std::string>& selected,
                                         const SingboxTunOptions& tun,
                                         const std::string& subscription_id = {});
    SingboxApplyResult select_subscription(const std::string& subscription_id,
                                           const std::vector<std::string>& selected,
                                           const SingboxTunOptions& tun);
    // Removes the subscription and its interfaces. Refuses when a keen-pbr-sx
    // outbound is still referenced; nothing is deleted in that case.
    SingboxApplyResult remove_subscription(const std::string& subscription_id);
    // Empty id refreshes every subscription that is due (or all, when due_only is false).
    nlohmann::json refresh_subscriptions(const std::string& subscription_id, bool due_only,
                                         const SubscriptionStopFn& stopping = {});

    static nlohmann::json render_singbox_config(const std::vector<SingboxNode>& nodes);
    static SingboxStore load_store(const std::string& path);

private:
    struct RefreshStatus {
        std::int64_t last_refresh{0};
        std::int64_t retry_at{0};
        std::string error;
    };
    struct ConfigWrite {
        bool had_config{false};
        bool removed{false};
    };

    std::unique_lock<std::mutex> begin_mutation();
    void update_refresh_status(const std::string& id, RefreshStatus status);
    RefreshStatus refresh_status(const SingboxSubscription& subscription) const;
    static std::int64_t next_refresh(const SingboxSubscription& subscription, const RefreshStatus& status);
    bool refresh_one(SingboxStore& store, std::size_t index, const SubscriptionStopFn& stopping);
    ConfigWrite write_checked_config(const nlohmann::json& config);
    nlohmann::json read_config_object() const;
    SingboxApplyResult persist(const SingboxStore& previous, SingboxStore next, bool rewrite_singbox,
                               bool sync_keenetic, bool reload_must_succeed = false);
    SingboxStore read() const;
    static void write_store(const std::string& path, const SingboxStore& store);
    nlohmann::json public_state(const SingboxStore& store) const;

    std::string tun_prefix() const;
    SingboxPaths paths_;
    SingboxCheck check_;
    KeeneticSyncFn keenetic_;
    SingboxReloadFn reload_;
    SubscriptionDownloadFn download_;
    SubscriptionClock clock_;
    std::string proxy_core_{"sing-box"};
    std::string xray_bin_;
    std::string xray_config_{"/opt/etc/keen-pbr-sx/xray.json"};
    CoreProcessFn core_process_;
    XrayTestFn xray_test_;
    mutable XrayVersionFn xray_version_;
    mutable RamFn ram_;
    InterfaceWaitFn interface_wait_;
    int interface_wait_ms_{20000};
    std::mutex mutation_mutex_;
    mutable std::mutex status_mutex_;
    std::map<std::string, RefreshStatus> refresh_status_;
};

SingboxLinkService make_singbox_link_service();
std::string sanitize_keenetic_tag(const std::string& name);
bool safe_interface_name(const std::string& name);
std::string format_singbox_check_error(int exit_code, bool timed_out, const std::string& output);
// Empty when tag is unused. Otherwise names the route rules and urltest/icmptest groups.
std::string outbound_reference_message(const nlohmann::json& config, const std::string& tag);
// Empty when nothing in use depends on the vanishing TUN interfaces. Otherwise
// names the route rules and DNS servers that would lose their path. A
// urltest/icmptest group counts as lost only when every member is lost.
std::string core_switch_blockers(const nlohmann::json& config, const std::set<std::string>& vanishing);

}  // namespace keen_pbr3
