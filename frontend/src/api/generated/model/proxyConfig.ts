/**
 * Generated from docs/openapi.yaml (ProxyConfig).
 * Which proxy core owns the per-node TUN interfaces.
 */
export interface ProxyConfig {
  /**
   * sing-box (default) or xray. Xray older than 26.10.17 cannot be selected.
   */
  core?: string;
  /**
   * Path to the xray binary. Empty searches /opt/bin/xray, /opt/usr/bin/xray, then PATH.
   */
  xray_bin?: string;
}
