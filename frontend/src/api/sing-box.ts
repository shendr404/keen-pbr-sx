import { apiFetch } from "@/api/client"

export type SingboxCatalogNode = {
  identity: string
  name: string
  protocol: string
  server: string
  port: number
  skipped: boolean
  reason: string
}

export type SingboxNode = {
  id: string
  name: string
  tag: string
  protocol: string
  server: string
  port: number
  interface: string
  tun_stack: string
  tun_mtu: number
  tun_address: string
  subscription_id: string
  subscription_name?: string
  source: string
  identity: string
  missing: boolean
  unsupported?: boolean
  unsupported_reason?: string
}

export type SingboxSubscription = {
  id: string
  name: string
  interval_hours: number
  last_refresh: number
  next_refresh?: number | null
  last_error: string
  new_nodes: number
  catalog: SingboxCatalogNode[]
}

export type SingboxState = {
  nodes: SingboxNode[]
  subscriptions: SingboxSubscription[]
  suggested_interface?: string
  warning?: string
  skipped?: number
  skipped_transports?: string[]
  encryption_ignored?: boolean
  singbox_checked?: boolean
  singbox_reloaded?: boolean
  keenetic_applied?: boolean
  core?: string
  xray_bin?: string
  xray_version?: string
  ram_kib?: number
  ram_warning?: boolean
}

type Envelope = { data: SingboxState }

export const fetchSingboxState = async () => {
  const response = await apiFetch<Envelope>("/api/sing-box/profiles", { method: "GET" })
  return response.data
}

export const postSingbox = async (path: string, body: unknown) => {
  const response = await apiFetch<Envelope>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
  return response.data
}

export const previewSingboxSubscription = async (url: string) => {
  const response = await apiFetch<{
    data: { nodes: SingboxCatalogNode[]; warning?: string; skipped?: number }
  }>("/api/sing-box/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  })
  return response.data
}
