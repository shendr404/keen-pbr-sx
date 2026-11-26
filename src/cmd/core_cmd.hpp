#pragma once

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <vector>

namespace keen_pbr3 {

// `keen-pbr-sx core [status [--json]] | sing-box | xray [--xray-bin PATH]`.
// Status needs no argument. A switch goes to the running daemon over the
// root-only control socket and runs the same switch_core as the REST API.
struct CoreCommand {
  enum class Action { Status, Switch };
  Action action{Action::Status};
  std::string core;      // "sing-box" or "xray" for a switch
  std::string xray_bin;  // empty: the configured path or the usual Entware ones
  bool json{false};      // status only
};

class CoreUsageError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

// args are the words after "core". Throws CoreUsageError.
CoreCommand parse_core_command(const std::vector<std::string> &args);

const char *core_usage();

// Human readable status from the control response "result".
std::string format_core_status(const nlohmann::json &status);
// One line per outcome of a switch, from the control response "result".
std::string format_core_switch(const nlohmann::json &result);

}  // namespace keen_pbr3
