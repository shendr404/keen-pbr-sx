---
title: keen-pbr-sx CLI usage
weight: 4
aliases:
  - /docs/advanced/cli/
  - /docs/advanced/signals/
---

`keen-pbr-sx` can run the service, inspect live routing state, download list data, and test routing decisions.

The `status`, `download` and `test-routing` commands talk to the running service. If the service is not running, they fail with exit code 1. Start the service first (on a router it starts with the system).

## Usage

```text
Usage: keen-pbr-sx [options] <command>

Options:
  --config <path>    Path to JSON config file (default: <KEEN_PBR_DEFAULT_CONFIG_PATH>)
  --log-level <lvl>  Log level: error, warn, info, verbose, debug (default: info)
  --log-target <target>  Log destination: stderr, syslog, or both (default: both)
  --pid-file <path>  Override daemon.pid_file when running the service command
  --crash-report <path>  Last-crash report path (default: /tmp/keen-pbr-sx-crash.log)
  --no-api           Disable REST API at runtime
  --use-raw-prerouting  Use raw PREROUTING for IPv4 forwarded traffic (iptables only)
  --use-raw6-prerouting Use raw PREROUTING for IPv6 forwarded traffic (iptables only)
  --version          Show version and exit
  --help             Show this help and exit

Commands:
  service                            Start the routing service (foreground)
  status                             Show routing/firewall status and exit
  download                           Download all configured lists to cache and exit
  test-routing <ip-or-domain> [packet options]
                                     Test expected vs actual routing for an IP or domain
      --proto <tcp|udp|other>        Packet protocol
      --src-addr <ip>                Packet source address
      --src-port <port>              Packet source port
      --dest-port <port>             Packet destination port
      --dscp <0-63>                  Packet DSCP (default: 0)
  resolver dnsmasq print-config      Print the dnsmasq config generated from dns.rules/dns.fallback (cached lists only; used as dnsmasq conf-script, always exits 0)
  resolver dnsmasq detect [--json]   List dnsmasq instances, their DNS endpoints and which one keen-pbr-sx uses
  core [status [--json]]             Show the proxy core (sing-box or Xray), its process and TUN interfaces
  core <sing-box|xray> [--xray-bin PATH]
                                     Switch the proxy core through the running daemon (root only);
                                     same checks and rollback as POST /api/sing-box/core
  hash-password [--update]           Generate an authentication password hash; --update writes config.json
```

The config file is usually `/etc/keen-pbr-sx/config.json` on OpenWrt and Debian, and `/opt/etc/keen-pbr-sx/config.json` on Keenetic / NetCraze.

## Options

| Flag | Description |
|---|---|
| `--config <path>` | Path to the JSON config file. Works only with the `service` command. |
| `--log-level <lvl>` | Log verbosity: `error`, `warn`, `info`, `verbose`, or `debug`. |
| `--log-target <target>` | External log destination: `stderr`, `syslog`, or `both`. Defaults to `both` for every command. The packaged service files (systemd, OpenWrt procd, Keenetic init script) pass `--log-target syslog` so logs are not duplicated when stdout/stderr are also captured by the init system. |
| `--pid-file <path>` | Path to the PID file (the file holding the service's process number). Replaces `daemon.pid_file` from the config; `service` only. |
| `--crash-report <path>` | Where to write the report about the last crash. Defaults to `/tmp/keen-pbr-sx-crash.log`. |
| `--no-api` | Disable the REST API even if enabled in config. |
| `--use-raw-prerouting` | {{< only iptables >}} Opt in to raw-table IPv4 forwarded-traffic classification. |
| `--use-raw6-prerouting` | {{< only iptables >}} Opt in to raw-table IPv6 forwarded-traffic classification. |
| `--version` | Print version and exit. |
| `--help` | Print help and exit. |

### `--use-raw-prerouting`

This flag is mainly for Keenetic / NetCraze. The firmware periodically rebuilds the `mangle` firewall table, and keen-pbr-sx's rules briefly disappear. With this flag keen-pbr-sx puts the rules for IPv4 traffic passing through the router into the `raw` table, which the firmware does not rebuild. IPv6 has a separate flag, `--use-raw6-prerouting`.

On Keenetic / NetCraze the start script sets these flags. The mode is set with `KEEN_PBR_RAW_PREROUTING` in `/opt/etc/keen-pbr-sx/defaults`:

| Value | What it does |
|---|---|
| `auto` (default) | Checks separately for IPv4 and IPv6 whether `raw` works, and uses it if so; otherwise `mangle` |
| `disable` | Always use `mangle` |
| `enable` | Require `raw` for IPv4 and IPv6. If `raw` is unavailable, the service does not start |
| `ipv4-only`, `ipv6-only` | Require `raw` for one address family only |

Restart the service after changing it. The practical difference between the modes is described in [Keenetic / NetCraze installation]({{< relref "/docs/getting-started/installation/keenetic" >}}).

To check whether `raw` is available:

```sh
ls -l "/lib/modules/$(uname -r)/iptable_raw.ko"
ls -l "/lib/modules/$(uname -r)/ip6table_raw.ko"
grep -x raw /proc/net/ip_tables_names
grep -x raw /proc/net/ip6_tables_names
iptables -t raw -S
ip6tables -t raw -S
```

## Commands

| Command | Description |
|---|---|
| `service` | Start the routing service in the foreground. |
| `status` | Show service, outbound, routing, firewall and kernel health, then the issue list the web UI overview shows, and exit. Exits with 1 when any check failed or any issue is an error. |
| `download [--reload]` | Download all URL-backed lists into the cache and exit. With `--reload` the service applies the lists that changed right away. |
| `resolver dnsmasq print-config` | Print the dnsmasq configuration for per-list DNS servers. |
| `core [status [--json]]` | Show the proxy core, whether its process is running and the state of the TUN interfaces. Exits with 1 when the active core is not running or its startup failed. |
| `core <sing-box\|xray> [--xray-bin PATH]` | Switch the proxy core through the running service. See [`core`](#core). |
| `hash-password [--update]` | Create a password hash for logging in to the web UI and API. |
| `resolver dnsmasq detect [--json]` | List dnsmasq instances, their DNS endpoints and the instance keen-pbr-sx uses. |
| `test-routing <ip-or-domain> [packet options]` | Compare expected and actual routing for the given IP or domain. The daemon runs the check, the same way as the routing test in the web UI. |

### `resolver dnsmasq print-config`

When `dns.resolver_integration: "dnsmasq"` is enabled, this command prints the dnsmasq configuration built by keen-pbr-sx. Lists are taken from the cache only; nothing is downloaded. It contains domain-to-server mappings, {{< term "DNS rebinding" >}} protection exceptions, and `fallback` servers.

**Usage:**

```bash
keen-pbr-sx resolver dnsmasq print-config
```

**Output:** Dnsmasq configuration directives.

```text
# keen-pbr-sx generated, do not edit

address=/use-application-dns.net/

no-resolv
# direct -> [DNS] 192.168.1.1
server=192.168.1.1
# dns proxy :52100 -> [DoH] https://dns.google/dns-query
server=127.0.0.89#52100

# List: ai_services

# direct -> [DNS] 1.1.1.1
server=/openai.com/www.openai.com/.../1.1.1.1
rebind-domain-ok=/openai.com/www.openai.com/...

# List: blocked

# dns proxy :52101 -> [DoH] https://dns.google/dns-query via vpn, [DoH] https://cloudflare-dns.com/dns-query
server=/example.com/.../127.0.0.89#52101
```

**Behavior:**
- Always exits with status 0, even on errors; errors are printed as `# keen-pbr-sx: ...` comment lines.
- When `resolver_integration: "none"` (default), or the config cannot be read, the output is only the `server=` lines from `dnsmasq-fallback.conf`; the dynamic sets are filled by interception.
- With `"dnsmasq"` and no `fallback` servers, those `server=` lines are added to the output.
- dnsmasq reads the config via this command (see `conf-script=keen-pbr-sx generate-resolver-config dnsmasq` in the {{< term "drop-in" >}}).

### `hash-password`

Creates a password hash for logging in to the web UI and API. The command asks for the password twice.

```bash
keen-pbr-sx hash-password
keen-pbr-sx hash-password --update
```

Without `--update` the command prints `Password hash: <hash>`, which you paste into `api.authentication.password_hash` yourself. With `--update` it writes `api.enabled: true`, `api.authentication.enabled: true` and the hash into `config.json`. Then restart the service: `Restart the keen-pbr-sx service for authentication changes to take effect.`

### `core` {#core}

Shows and switches the proxy core: sing-box (default) or Xray. Run it as root on the router, with the service running.

```bash
keen-pbr-sx core                      # same as: core status
keen-pbr-sx core status --json
keen-pbr-sx core xray                 # switch to Xray
keen-pbr-sx core xray --xray-bin /opt/sbin/xray
keen-pbr-sx core sing-box             # switch back
```

`status` prints the active core, whether the sing-box and Xray processes are running, each node's TUN interface (`up`, `DOWN`, or `unsupported` for a node the active core cannot carry) and the startup error, if there is one. The exit code is 0 when the active core is running and there is no error, otherwise 1. `--json` prints the same data as JSON.

`xray` and `sing-box` run the same switch as `POST /api/sing-box/core` in the web UI: the Xray version check, the config test, the check of route rules and DNS detours that would be left on an interface that goes away, starting the new core before stopping the old one, and rollback if anything fails. The command prints the new core and the interfaces and exits with 0, or prints the error and exits with 1. `--xray-bin` sets `proxy.xray_bin` for that switch.

The command talks to the service over the root-only control socket (mode 0600, only uid 0 may connect). The REST API and its authentication are not used and are not weakened. The switch itself saves the config through the API subsystem, so `api.enabled` must be on and the service must not run with `--no-api`; otherwise the command fails with `api_unavailable`. See [Xray core]({{< relref "/docs/developer/xray-core" >}}) for what the service does at start.

### `resolver dnsmasq detect` {#resolver-dnsmasq-detect}

Inspect the dnsmasq integration without the daemon. The command does not need the control socket.

```bash
keen-pbr-sx resolver dnsmasq detect [--json]
```

The command lists every dnsmasq instance the platform hook reports: whether it runs, its DNS endpoint and how it was confirmed, listening sockets, whether keen-pbr-sx's {{< term "drop-in" >}} is installed and which configuration it loaded, and any problem. The last line tells which instance keen-pbr-sx selected and how (`explicit`, `adopted` or `automatic`), or why it could not choose.

```text
dnsmasq hook: /usr/lib/keen-pbr-sx/dnsmasq-hook.sh (platform openwrt, binary /usr/sbin/dnsmasq)

  uci:cfg01411c  [selected: adopted]
    running:     yes (pid 1842)
    enabled:     yes
    endpoint:    127.0.0.1:53 (stamp_verified)
    listeners:   udp+tcp 0.0.0.0:53, udp+tcp [::]:53
    keen-pbr-sx:    installed, loaded hash 3f2a9c0e1b7d4a55c6e8f0a1b2c3d4e5
    conf-dir:    /tmp/dnsmasq.cfg01411c.d (included)
    problem:     none

Selection: uci:cfg01411c (adopted)
```

- `--json` prints the same data as one JSON object (`selected`, `selection`, `error_code`, `message`, `warnings`, `instances[]`).
- Exit code `0` when an instance is selected and has no problem, `1` otherwise.
- If the choice is ambiguous, the output ends with a hint to set `dns.dnsmasq_instance`.

## Signals

You can control the running `keen-pbr-sx` service with signals:

| Signal | Action |
|---|---|
| `SIGUSR1` | Rebuild routes and firewall rules |
| `SIGHUP` | Re-read `config.json` and apply it again. Does not work in the `keen-pbr-sx-headless` build |
| `SIGTERM` / `SIGINT` | Graceful shutdown |

Example: re-read the config with SIGHUP:

```bash {filename="bash"}
kill -HUP $(cat /var/run/keen-pbr-sx.pid)
```

## Examples

Check live routing and firewall state:

```bash {filename="bash"}
keen-pbr-sx status
```

Example output:

```text
keen-pbr-sx status - config: /etc/keen-pbr-sx/config.json
Service: running (runtime running: startup complete) - keen-pbr-sx 3.4.0 (build 20261012064940)
Firewall backend: nftables

Outbounds:
  corp_vpn [interface] iface=corp_vpn fwmark=0x00010000 table=402
    state ........................................................... HEALTHY
    route   table=402 default dev corp_vpn ............................... OK
    rule    0x00010000/0x00ff0000 -> table=402 pri=402 ........... OK [v4+v6]
  auto_vpn [urltest] fwmark=0x00060000 table=402
    state ........................................................... HEALTHY
    member  corp_vpn (corp_vpn) 41 ms ................................ ACTIVE
    member  backup_vpn (wg1) ....................................... DEGRADED
      probe failed: timeout
    route   table=402 default dev corp_vpn ............................... OK
    rule    0x00060000/0x00ff0000 -> table=402 pri=407 ........... OK [v4+v6]

Firewall:
  chain   KeenPbrTable / prerouting hook ............................... OK
  rule    kpbr4_generic -> MARK 0x00010000 ........................ MISSING
    rule not found in nftables prerouting chain
  rule    kpbr4_auto -> MARK 0x00060000 selected=corp_vpn .............. OK

Kernel 6.12.94:
  capability nfqueue ................................................... OK
  probe      set_write ................................................. OK
  probe      conntrack ................................................. OK

Interception: running, DNS hold active, L7 active
dnsmasq: ok, alive, 127.0.0.1:53 (uci:cfg01411c), 3 rules, 16 domains

Issues:
  ERROR  Firewall rules do not match: 1
         kpbr4_generic: rule not found in nftables prerouting chain
  WARN   auto_vpn: failing members: 1
         backup_vpn · degraded · probe failed: timeout

Overall: DEGRADED (1 check(s) failed, 1 error(s), 1 warning(s))
Status values: OK / MISSING / MISMATCH / ERROR
```

Download all URL-backed lists:

```bash {filename="bash"}
keen-pbr-sx download
```

The command prints the service's answer as one JSON line. `refreshed_lists` holds the lists that were updated, `changed_lists` those whose content changed:

```text
{"ok":true,"protocol_version":2,"request_id":"cli-download","result":{"changed_lists":["google"],"failed_lists":[],"refreshed_lists":["google"],"reloaded":false}}
```

If a list fails to download, the command prints an error and exits with code 1.

Compare expected and actual routing:

```bash {filename="bash"}
keen-pbr-sx test-routing google.com
```

Example output:

```text
Target: google.com
Resolved IPs: 2001:4860:4860::8888, 142.250.74.14

IP                        | List Match               | Expected Outbound  | Actual Outbound    | Status
---------------------------------------------------------------------------------------------------
2001:4860:4860::8888      | google (via google.com)  | corp_vpn           | corp_vpn           | OK
142.250.74.14             | google (via google.com)  | corp_vpn           | corp_vpn           | OK
```

By default only list membership is checked. To also match rules that use ports, protocol, source address or DSCP, describe the packet:

| Flag | Description |
|---|---|
| `--proto <tcp\|udp\|other>` | Packet protocol. |
| `--src-addr <ip>` | Source address of the client sending the packet. |
| `--src-port <port>` | Source port. |
| `--dest-port <port>` | Destination port. |
| `--dscp <0-63>` | DSCP value. A packet without `--dscp` is treated as DSCP 0. |

```bash {filename="bash"}
keen-pbr-sx test-routing google.com --proto tcp --dest-port 443 --src-addr 192.168.1.10
```

If a rule depends on a field you did not give (for example `src_addr`), that IP shows `(unknown)`.
