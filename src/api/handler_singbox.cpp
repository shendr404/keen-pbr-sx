#ifdef WITH_API

#include "handler_singbox.hpp"
#include "handlers.hpp"
#include "status_stream.hpp"

#include "../config/config.hpp"
#include "../singbox/link_store.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <set>

namespace keen_pbr3 {
namespace {

nlohmann::json require_object(const std::string& body) {
    const auto json = nlohmann::json::parse(body);
    if (!json.is_object()) throw ApiError("JSON object required", 400);
    return json;
}

std::string field(const nlohmann::json& json, const char* key) {
    if (!json.contains(key) || json.at(key).is_null()) return {};
    if (!json.at(key).is_string()) throw ApiError(std::string(key) + " must be a string", 400);
    return json.at(key).get<std::string>();
}

int number_field(const nlohmann::json& json, const char* key, int fallback) {
    if (!json.contains(key) || json.at(key).is_null()) return fallback;
    if (json.at(key).is_number_integer()) return json.at(key).get<int>();
    if (json.at(key).is_number()) return static_cast<int>(json.at(key).get<double>());
    if (json.at(key).is_string()) {
        const auto text = json.at(key).get<std::string>();
        if (text.empty()) return fallback;
        int value = 0;
        for (unsigned char c : text) {
            if (c < '0' || c > '9') throw ApiError(std::string(key) + " must be a number", 400);
            value = value * 10 + static_cast<int>(c - '0');
        }
        return value;
    }
    throw ApiError(std::string(key) + " must be a number", 400);
}

std::vector<std::string> link_lines(const nlohmann::json& json) {
    std::vector<std::string> lines;
    if (json.contains("links") && json.at("links").is_array()) {
        for (const auto& item : json.at("links")) {
            if (!item.is_string()) throw ApiError("links must be strings", 400);
            lines.push_back(item.get<std::string>());
        }
    } else if (json.contains("links") && json.at("links").is_string()) {
        lines.push_back(json.at("links").get<std::string>());
    }
    if (json.contains("link") && json.at("link").is_string()) lines.push_back(json.at("link").get<std::string>());
    return lines;
}

SingboxTunOptions tun_options(const nlohmann::json& json) {
    SingboxTunOptions tun;
    tun.tun_stack = field(json, "tun_stack");
    tun.tun_mtu = number_field(json, "tun_mtu", 0);
    tun.tun_address = field(json, "tun_address");
    return tun;
}

std::vector<std::string> string_list(const nlohmann::json& json, const char* key) {
    std::vector<std::string> values;
    if (!json.contains(key) || json.at(key).is_null()) return values;
    if (json.at(key).is_string()) {
        values.push_back(json.at(key).get<std::string>());
        return values;
    }
    if (!json.at(key).is_array()) throw ApiError(std::string(key) + " must be a list of strings", 400);
    for (const auto& item : json.at(key)) {
        if (!item.is_string()) throw ApiError(std::string(key) + " must be a list of strings", 400);
        values.push_back(item.get<std::string>());
    }
    return values;
}

SingboxNodePatch node_patch(const nlohmann::json& json) {
    SingboxNodePatch patch;
    patch.id = field(json, "id");
    patch.tag = field(json, "tag");
    patch.interface_name = field(json, "interface");
    patch.tun_stack = field(json, "tun_stack");
    patch.tun_mtu = number_field(json, "tun_mtu", 0);
    if (json.contains("tun_address")) {
        patch.tun_address = field(json, "tun_address");
        patch.tun_address_set = true;
    }
    return patch;
}

std::string result_json(const SingboxApplyResult& result) {
    nlohmann::json json = result.state;
    json["singbox_checked"] = result.singbox_checked;
    json["singbox_reloaded"] = result.singbox_reloaded;
    json["keenetic_applied"] = result.keenetic_applied;
    if (!result.warning.empty()) json["warning"] = result.warning;
    if (result.skipped > 0) json["skipped"] = result.skipped;
    if (!result.skipped_transports.empty()) json["skipped_transports"] = result.skipped_transports;
    if (result.encryption_ignored) json["encryption_ignored"] = true;
    return json.dump();
}

void sync_keenetic_outbounds(ApiContext& ctx, const KeeneticSyncRequest& request) {
    if (!ctx.get_visible_config_fn || !ctx.validate_candidate_config_fn ||
        !ctx.enqueue_apply_validated_config_fn) {
        throw ApiError("config apply is unavailable", 503);
    }
    if (ctx.begin_save_operation_fn) ctx.begin_save_operation_fn();
    struct FinishSave {
        ApiContext* context;
        bool active;
        ~FinishSave() {
            if (active && context->finish_config_operation_fn) context->finish_config_operation_fn();
        }
    } finish{&ctx, static_cast<bool>(ctx.begin_save_operation_fn)};
    nlohmann::json doc;
    api::to_json(doc, ctx.get_visible_config_fn());
    std::string references;
    for (const auto& tag : request.removed_tags) {
        const auto message = outbound_reference_message(doc, tag);
        if (message.empty()) continue;
        if (!references.empty()) references += "; ";
        references += message;
    }
    if (!references.empty()) throw std::runtime_error(references);
    if (!doc.contains("outbounds") || !doc["outbounds"].is_array()) {
        doc["outbounds"] = nlohmann::json::array();
    }
    std::set<std::string> owned(request.owned_tags.begin(), request.owned_tags.end());
    std::set<std::string> next_tags;
    for (const auto& node : request.nodes) next_tags.insert(node.tag);
    for (const auto& outbound : doc["outbounds"]) {
        const auto tag = outbound.value("tag", "");
        if (next_tags.count(tag) && !owned.count(tag)) {
            throw std::runtime_error("keen-pbr-sx tag is already used");
        }
    }
    nlohmann::json kept = nlohmann::json::array();
    for (const auto& outbound : doc["outbounds"]) {
        const auto tag = outbound.value("tag", "");
        if (next_tags.count(tag) ||
            std::find(request.removed_tags.begin(), request.removed_tags.end(), tag) != request.removed_tags.end()) {
            continue;
        }
        kept.push_back(outbound);
    }
    for (const auto& node : request.nodes) {
        // TUN and point-to-point interfaces are device routes. Writing
        // gateway "auto" makes keen-pbr-sx report that the gateway is ignored.
        kept.push_back({
            {"type", "interface"},
            {"tag", node.tag},
            {"interface", node.interface_name},
        });
    }
    doc["outbounds"] = std::move(kept);
    apply_interface_renames(doc, request.renames);
    if (request.has_proxy) doc["proxy"] = request.proxy;
    const auto dumped = doc.dump(2);
    Config updated = parse_config(dumped);
    ctx.validate_candidate_config_fn(updated);
    const auto applied = ctx.enqueue_apply_validated_config_fn(std::move(updated), dumped);
    if (!applied.error.empty() || !applied.saved) {
        throw std::runtime_error(applied.error.empty() ? "keen-pbr-sx config was not saved" : applied.error);
    }
}

}  // namespace

void register_singbox_handler(ApiServer& server, ApiContext& ctx, SingboxLinkService& service) {
    auto apply_proxy = [&ctx, &service] {
        if (!ctx.get_visible_config_fn) return;
        const auto config = ctx.get_visible_config_fn();
        std::string core = "sing-box";
        std::string bin;
        if (config.proxy) {
            if (config.proxy->core && !config.proxy->core->empty()) core = *config.proxy->core;
            if (config.proxy->xray_bin) bin = *config.proxy->xray_bin;
        }
        service.set_proxy(core, bin);
    };
    service.set_keenetic_callback([&ctx](const KeeneticSyncRequest& request) {
        sync_keenetic_outbounds(ctx, request);
    });
    server.post("/api/sing-box/core", [&service, &ctx, apply_proxy](const std::string& body) {
        try {
            apply_proxy();
            const auto json = require_object(body);
            bool icmptest = false;
            nlohmann::json keen_config = nlohmann::json::object();
            if (ctx.get_visible_config_fn) {
                const auto config = ctx.get_visible_config_fn();
                if (config.outbounds) {
                    for (const auto& outbound : *config.outbounds) {
                        if (outbound.type == OutboundType::ICMPTEST) icmptest = true;
                    }
                }
                api::to_json(keen_config, config);
            }
            return result_json(
                service.switch_core(field(json, "core"), field(json, "xray_bin"), icmptest, keen_config));
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid JSON", 400);
        } catch (const SingboxBusy& error) {
            throw ApiError(error.what(), 409);
        } catch (const std::runtime_error& error) {
            throw ApiError(error.what(), 400);
        }
    });

    server.post("/api/sing-box/preview", [&service](const std::string& body) {
        try {
            const auto json = require_object(body);
            if (!field(json, "url").empty() || !field(json, "subscription_id").empty()) {
                const auto key = field(json, "url").empty() ? field(json, "subscription_id") : field(json, "url");
                return service.preview_subscription(key).dump();
            }
            return service.preview(field(json, "link")).dump();
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid JSON", 400);
        } catch (const std::runtime_error& error) {
            throw ApiError(error.what(), 400);
        }
    });
    server.get("/api/sing-box/profiles", [&service, apply_proxy]() {
        apply_proxy();
        return service.state().dump();
    });
    server.post("/api/sing-box/nodes", [&service, apply_proxy](const std::string& body) {
        try {
            apply_proxy();
            const auto json = require_object(body);
            return result_json(service.add_links(link_lines(json), tun_options(json)));
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid JSON", 400);
        } catch (const SingboxBusy& error) {
            throw ApiError(error.what(), 409);
        } catch (const std::runtime_error& error) {
            throw ApiError(error.what(), 400);
        }
    });
    server.post("/api/sing-box/nodes/update", [&service](const std::string& body) {
        try {
            return result_json(service.update_node(node_patch(require_object(body))));
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid JSON", 400);
        } catch (const SingboxBusy& error) {
            throw ApiError(error.what(), 409);
        } catch (const std::runtime_error& error) {
            throw ApiError(error.what(), 400);
        }
    });
    server.post("/api/sing-box/nodes/delete", [&service](const std::string& body) {
        try {
            const auto json = require_object(body);
            return result_json(service.remove_node(field(json, "id")));
        } catch (const SingboxBusy& error) {
            throw ApiError(error.what(), 409);
        } catch (const std::runtime_error& error) {
            throw ApiError(error.what(), 400);
        }
    });
    server.post("/api/sing-box/subscriptions", [&service, apply_proxy](const std::string& body) {
        try {
            apply_proxy();
            const auto json = require_object(body);
            return result_json(service.save_subscription(field(json, "url"), number_field(json, "interval_hours", 0),
                                                         string_list(json, "selected"), tun_options(json),
                                                         field(json, "subscription_id")));
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid JSON", 400);
        } catch (const SingboxBusy& error) {
            throw ApiError(error.what(), 409);
        } catch (const std::runtime_error& error) {
            throw ApiError(error.what(), 400);
        }
    });
    server.post("/api/sing-box/subscriptions/select", [&service](const std::string& body) {
        try {
            const auto json = require_object(body);
            return result_json(service.select_subscription(field(json, "subscription_id"), string_list(json, "selected"),
                                                           tun_options(json)));
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid JSON", 400);
        } catch (const SingboxBusy& error) {
            throw ApiError(error.what(), 409);
        } catch (const std::runtime_error& error) {
            throw ApiError(error.what(), 400);
        }
    });
    server.post("/api/sing-box/subscriptions/delete", [&service](const std::string& body) {
        try {
            const auto json = require_object(body);
            const auto id = field(json, "subscription_id");
            return result_json(service.remove_subscription(id.empty() ? field(json, "id") : id));
        } catch (const SingboxBusy& error) {
            throw ApiError(error.what(), 409);
        } catch (const std::runtime_error& error) {
            throw ApiError(error.what(), 400);
        }
    });
    server.post("/api/sing-box/subscriptions/refresh", [&service, &ctx, apply_proxy](const std::string& body) {
        try {
            apply_proxy();
            const auto json = require_object(body);
            auto id = field(json, "subscription_id");
            if (id.empty()) id = field(json, "profile_id");
            if (id.empty()) throw ApiError("subscription id is required", 400);
            const auto outcomes = service.refresh_subscriptions(id, false);
            if (outcomes.empty()) throw ApiError("subscription was not found", 404);
            std::string errors;
            for (const auto& outcome : outcomes) {
                if (outcome.at("ok").get<bool>()) continue;
                if (!errors.empty()) errors += "; ";
                errors += outcome.at("message").get<std::string>();
            }
            if (ctx.status_stream) ctx.status_stream->reconcile(StatusUpdate::Issues);
            if (!errors.empty()) throw ApiError(errors, 502);
            return service.state().dump();
        } catch (const ApiError&) {
            throw;
        } catch (const nlohmann::json::exception&) {
            throw ApiError("invalid JSON", 400);
        } catch (const SingboxBusy& error) {
            throw ApiError(error.what(), 409);
        } catch (const std::runtime_error& error) {
            throw ApiError(error.what(), 400);
        }
    });
}

}  // namespace keen_pbr3

#endif
