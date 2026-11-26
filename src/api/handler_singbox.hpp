#pragma once

#ifdef WITH_API

#include "server.hpp"

#include <nlohmann/json.hpp>
#include <string>

namespace keen_pbr3 {

struct ApiContext;

class SingboxLinkService;
void register_singbox_handler(ApiServer& server, ApiContext& ctx, SingboxLinkService& service);

// The switch behind POST /api/sing-box/core and `keen-pbr-sx core <name>`: the
// same pre-checks, make-before-break start, rollback and config save. Returns
// the result JSON of the API. Throws SingboxBusy or std::runtime_error.
nlohmann::json switch_proxy_core(ApiContext& ctx, SingboxLinkService& service, const std::string& core,
                                 const std::string& xray_bin);

}  // namespace keen_pbr3

#endif
