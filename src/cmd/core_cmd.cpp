#include "core_cmd.hpp"

#include <sstream>

namespace keen_pbr3 {

const char *core_usage() {
  return "Usage: keen-pbr-sx core [status [--json]]\n"
         "       keen-pbr-sx core sing-box [--xray-bin PATH]\n"
         "       keen-pbr-sx core xray [--xray-bin PATH]\n";
}

CoreCommand parse_core_command(const std::vector<std::string> &args) {
  CoreCommand command;
  if (args.empty()) return command;
  const auto &word = args.front();
  if (word == "status") {
    for (std::size_t i = 1; i < args.size(); ++i) {
      if (args[i] == "--json") command.json = true;
      else throw CoreUsageError("unknown option for core status: " + args[i]);
    }
    return command;
  }
  if (word != "sing-box" && word != "xray") {
    throw CoreUsageError("unknown core command: " + word);
  }
  command.action = CoreCommand::Action::Switch;
  command.core = word;
  for (std::size_t i = 1; i < args.size(); ++i) {
    const auto &arg = args[i];
    if (arg == "--xray-bin") {
      if (i + 1 >= args.size() || args[i + 1].empty() || args[i + 1].rfind("--", 0) == 0) {
        throw CoreUsageError("--xray-bin requires a path");
      }
      command.xray_bin = args[++i];
    } else if (arg.rfind("--xray-bin=", 0) == 0) {
      command.xray_bin = arg.substr(std::string("--xray-bin=").size());
      if (command.xray_bin.empty()) throw CoreUsageError("--xray-bin requires a path");
    } else {
      throw CoreUsageError("unknown option for core " + word + ": " + arg);
    }
  }
  return command;
}

namespace {

std::string text_of(const nlohmann::json &object, const char *key) {
  if (!object.is_object() || !object.contains(key) || !object.at(key).is_string()) return {};
  return object.at(key).get<std::string>();
}

bool bool_of(const nlohmann::json &object, const char *key) {
  return object.is_object() && object.contains(key) && object.at(key).is_boolean() &&
         object.at(key).get<bool>();
}

}  // namespace

std::string format_core_status(const nlohmann::json &status) {
  std::ostringstream out;
  const auto core = text_of(status, "core");
  out << "Core: " << (core.empty() ? "sing-box" : core) << '\n';
  if (core == "xray") {
    const auto bin = text_of(status, "xray_bin");
    out << "Xray: " << (bool_of(status, "xray_running") ? "running" : "NOT running")
        << (bin.empty() ? "" : " (" + bin + ")") << '\n';
    out << "sing-box: " << (bool_of(status, "singbox_running") ? "running (unexpected)" : "stopped") << '\n';
  } else {
    out << "sing-box: " << (bool_of(status, "singbox_running") ? "running" : "NOT running") << '\n';
    out << "Xray: " << (bool_of(status, "xray_running") ? "running (unexpected)" : "stopped") << '\n';
  }
  if (status.contains("interfaces") && status.at("interfaces").is_array()) {
    for (const auto &item : status.at("interfaces")) {
      out << "  " << text_of(item, "name") << " [" << text_of(item, "tag") << "] ";
      if (bool_of(item, "unsupported")) out << "unsupported by this core";
      else out << (bool_of(item, "up") ? "up" : "DOWN");
      out << '\n';
    }
  }
  const auto error = text_of(status, "error");
  out << "State: " << (error.empty() ? "ok" : "ERROR: " + error) << '\n';
  return out.str();
}

std::string format_core_switch(const nlohmann::json &result) {
  std::ostringstream out;
  out << "Core: " << text_of(result, "core") << '\n';
  if (result.contains("nodes") && result.at("nodes").is_array()) {
    for (const auto &node : result.at("nodes")) {
      out << "  " << text_of(node, "interface") << " [" << text_of(node, "tag") << "] ";
      if (bool_of(node, "unsupported")) {
        const auto reason = text_of(node, "unsupported_reason");
        out << "unsupported" << (reason.empty() ? "" : ": " + reason);
      } else {
        out << "ok";
      }
      out << '\n';
    }
  }
  const auto warning = text_of(result, "warning");
  if (!warning.empty()) out << "Warning: " << warning << '\n';
  return out.str();
}

}  // namespace keen_pbr3
