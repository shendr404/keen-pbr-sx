import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"

import type { ApiError } from "@/api/client"
import {
  fetchSingboxState,
  postSingbox,
  previewSingboxSubscription,
  type SingboxCatalogNode,
  type SingboxNode,
  type SingboxState,
  type SingboxSubscription,
} from "@/api/sing-box"
import { PageHeader } from "@/components/shared/page-header"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { getApiErrorMessage } from "@/lib/api-errors"
import { getTagNameValidationError } from "@/lib/tag-name-validation"

const queryKey = ["sing-box-profiles"]

const nativeSelectClass =
  "h-8 w-full rounded-lg border border-input bg-background px-2.5 text-sm text-foreground scheme-light dark:bg-popover dark:text-popover-foreground dark:scheme-dark"

function formatRefreshTime(timestamp: number | null | undefined, locale: string) {
  return timestamp ? new Date(timestamp * 1000).toLocaleString(locale) : "—"
}

function localizeServerMessage(
  message: string,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  const skipped = /^(\d+) nodes skipped: transport (.+) is not supported by sing-box$/.exec(message)
  if (skipped) {
    return t("pages.singbox.skippedTransports", {
      count: Number(skipped[1]),
      transports: skipped[2],
    })
  }
  if (message.includes("vless encryption is ignored")) return t("pages.singbox.encryptionIgnored")
  const tooOld = /^Xray (.+) is older than 26\.10\.17/.exec(message)
  if (tooOld) return t("pages.singbox.versionTooOld", { version: tooOld[1] })
  if (message.includes("icmptest does not measure")) return t("pages.singbox.icmptestXray")
  if (message.includes("could not start xray")) return t("pages.singbox.startFailed")
  if (message.includes("xray run -test")) return t("pages.singbox.testFailed")
  const protocol = /^protocol (.+) is not supported by (Xray|sing-box)$/.exec(message)
  if (protocol) return t("pages.singbox.unsupportedProtocol", { protocol: protocol[1], core: protocol[2] })
  const transport = /^transport (.+) is not supported by Xray$/.exec(message)
  if (transport) return t("pages.singbox.unsupportedTransport", { transport: transport[1] })
  return message
}

function noticeText(
  state: SingboxState,
  t: (key: string, options?: Record<string, unknown>) => string,
  fallback: string
) {
  const parts = [fallback]
  if (state.warning) parts.push(localizeServerMessage(state.warning, t))
  if (state.skipped && state.skipped_transports?.length) {
    parts.push(
      t("pages.singbox.skippedTransports", {
        count: state.skipped,
        transports: state.skipped_transports.join(", "),
      })
    )
  }
  if (state.encryption_ignored) parts.push(t("pages.singbox.encryptionIgnored"))
  return parts.filter(Boolean).join(" ")
}

function TunFields({
  idPrefix,
  stack,
  mtu,
  address,
  onStack,
  onMtu,
  onAddress,
}: {
  idPrefix: string
  stack: string
  mtu: string
  address: string
  onStack: (value: string) => void
  onMtu: (value: string) => void
  onAddress: (value: string) => void
}) {
  const { t } = useTranslation()
  return (
    <details className="rounded-lg border border-border px-3 py-2">
      <summary className="cursor-pointer text-sm font-medium">{t("pages.singbox.advanced")}</summary>
      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <div className="grid gap-1.5">
          <Label htmlFor={`${idPrefix}-stack`}>{t("pages.singbox.tunStack")}</Label>
          <select
            className={nativeSelectClass}
            id={`${idPrefix}-stack`}
            onChange={(event) => onStack(event.target.value)}
            value={stack}
          >
            <option value="gvisor">gvisor</option>
            <option value="system">system</option>
          </select>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor={`${idPrefix}-mtu`}>{t("pages.singbox.tunMtu")}</Label>
          <Input id={`${idPrefix}-mtu`} onChange={(event) => onMtu(event.target.value)} value={mtu} />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor={`${idPrefix}-address`}>{t("pages.singbox.tunAddress")}</Label>
          <Input
            id={`${idPrefix}-address`}
            onChange={(event) => onAddress(event.target.value)}
            placeholder={t("pages.singbox.addressPlaceholder")}
            value={address}
          />
        </div>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">{t("pages.singbox.tunAddressHint")}</p>
    </details>
  )
}

export function SingboxPage() {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const stateQuery = useQuery({ queryKey, queryFn: fetchSingboxState, refetchInterval: 30_000 })
  const [links, setLinks] = useState("")
  const [stack, setStack] = useState("gvisor")
  const [mtu, setMtu] = useState("1400")
  const [address, setAddress] = useState("")
  const [subUrl, setSubUrl] = useState("")
  const [subHours, setSubHours] = useState("0")
  const [preview, setPreview] = useState<SingboxCatalogNode[] | null>(null)
  const [picked, setPicked] = useState<Record<string, boolean>>({})
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")
  const [coreDraft, setCoreDraft] = useState<string | null>(null)
  const [binDraft, setBinDraft] = useState<string | null>(null)

  const invalidate = () => queryClient.invalidateQueries({ queryKey })
  const fail = (caught: unknown) => {
    const message =
      caught && typeof caught === "object" && "message" in caught
        ? getApiErrorMessage(caught as ApiError)
        : t("pages.singbox.failed")
    setSuccess("")
    setError(localizeServerMessage(message, t))
  }
  const tun = {
    tun_stack: stack,
    tun_mtu: Number(mtu) || 1400,
    tun_address: address,
  }

  const createNodes = useMutation({
    mutationFn: () => postSingbox("/api/sing-box/nodes", { links, ...tun }),
    onMutate: () => {
      setError("")
      setSuccess("")
    },
    onSuccess: async (state) => {
      setSuccess(noticeText(state, t, t("pages.singbox.savedNodes")))
      setLinks("")
      await invalidate()
    },
    onError: fail,
  })
  const loadSubscription = useMutation({
    mutationFn: () => previewSingboxSubscription(subUrl.trim()),
    onMutate: () => {
      setError("")
      setSuccess("")
    },
    onSuccess: (result) => {
      setPreview(result.nodes)
      const next: Record<string, boolean> = {}
      for (const node of result.nodes) {
        if (!node.skipped && node.identity) next[node.identity] = false
      }
      setPicked(next)
      if (result.warning) setSuccess(localizeServerMessage(result.warning, t))
    },
    onError: fail,
  })
  const confirmSubscription = useMutation({
    mutationFn: () =>
      postSingbox("/api/sing-box/subscriptions", {
        url: subUrl.trim(),
        interval_hours: Number(subHours) || 0,
        selected: Object.entries(picked)
          .filter(([, on]) => on)
          .map(([identity]) => identity),
        ...tun,
      }),
    onSuccess: async (state) => {
      setSuccess(noticeText(state, t, t("pages.singbox.subscriptionSaved")))
      setPreview(null)
      setPicked({})
      setSubUrl("")
      await invalidate()
    },
    onError: fail,
  })

  const nodes = stateQuery.data?.nodes ?? []
  const subscriptions = stateQuery.data?.subscriptions ?? []
  const coreValue = coreDraft ?? stateQuery.data?.core ?? "sing-box"
  const binValue = binDraft ?? stateQuery.data?.xray_bin ?? ""
  const switchCore = useMutation({
    mutationFn: () => postSingbox("/api/sing-box/core", { core: coreValue, xray_bin: binValue }),
    onMutate: () => {
      setError("")
      setSuccess("")
    },
    onSuccess: async (state) => {
      setCoreDraft(null)
      setBinDraft(null)
      setSuccess(noticeText(state, t, t("pages.singbox.coreSaved")))
      await invalidate()
    },
    onError: fail,
  })
  const ramMb = Math.round((stateQuery.data?.ram_kib ?? 0) / 1024)

  return (
    <div className="grid gap-6">
      <PageHeader description={t("pages.singbox.description")} title={t("pages.singbox.title")} />
      <section className="grid gap-3 rounded-xl border border-border p-4">
        <h2 className="text-base font-medium">{t("pages.singbox.core")}</h2>
        <p className="text-xs text-muted-foreground">{t("pages.singbox.coreHint")}</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-1.5">
            <Label htmlFor="proxy-core">{t("pages.singbox.core")}</Label>
            <select
              className={nativeSelectClass}
              id="proxy-core"
              onChange={(event) => setCoreDraft(event.target.value)}
              value={coreValue}
            >
              <option value="sing-box">sing-box</option>
              <option value="xray">Xray</option>
            </select>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="xray-bin">{t("pages.singbox.xrayBin")}</Label>
            <Input id="xray-bin" onChange={(event) => setBinDraft(event.target.value)} value={binValue} />
            <p className="text-xs text-muted-foreground">{t("pages.singbox.xrayBinHint")}</p>
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          {stateQuery.data?.xray_version
            ? t("pages.singbox.xrayVersion", { version: stateQuery.data.xray_version })
            : t("pages.singbox.xrayVersionUnknown")}
        </p>
        {stateQuery.data?.ram_warning ? (
          <Alert>
            <AlertDescription>{t("pages.singbox.ramWarning", { mb: ramMb })}</AlertDescription>
          </Alert>
        ) : null}
        <Button disabled={switchCore.isPending} onClick={() => switchCore.mutate()}>
          {t("pages.singbox.switchCore")}
        </Button>
      </section>
      <section className="grid gap-3 rounded-xl border border-border p-4">
        <h2 className="text-base font-medium">{t("pages.singbox.create")}</h2>
        <Label htmlFor="singbox-links">{t("pages.singbox.links")}</Label>
        <Textarea
          id="singbox-links"
          onChange={(event) => setLinks(event.target.value)}
          placeholder={t("pages.singbox.linksPlaceholder")}
          rows={5}
          value={links}
        />
        <p className="text-xs text-muted-foreground">{t("pages.singbox.linksHint")}</p>
        <p className="text-xs text-muted-foreground">
          {t("pages.singbox.interfaceHint", {
            name: stateQuery.data?.suggested_interface || "sbtun",
          })}
        </p>
        <TunFields
          address={address}
          idPrefix="create"
          mtu={mtu}
          onAddress={setAddress}
          onMtu={setMtu}
          onStack={setStack}
          stack={stack}
        />
        <Button disabled={createNodes.isPending || links.trim().length === 0} onClick={() => createNodes.mutate()}>
          {t("pages.singbox.saveNodes")}
        </Button>
      </section>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {success ? (
        <Alert>
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      ) : null}

      <section className="grid gap-3">
        <h2 className="text-base font-medium">{t("pages.singbox.interfaces")}</h2>
        {nodes.length === 0 ? <p className="text-sm text-muted-foreground">{t("pages.singbox.noNodes")}</p> : null}
        {nodes.map((node) => (
          <NodeCard
            key={node.id}
            node={node}
            onError={fail}
            onSuccess={async (state, fallback) => {
              setError("")
              setSuccess(noticeText(state, t, fallback))
              await invalidate()
            }}
          />
        ))}
      </section>

      <section className="grid gap-3 rounded-xl border border-border p-4">
        <h2 className="text-base font-medium">{t("pages.singbox.subscriptions")}</h2>
        <div className="grid gap-3 sm:grid-cols-[1fr_12rem]">
          <div className="grid gap-1.5">
            <Label htmlFor="sub-url">{t("pages.singbox.subscriptionUrl")}</Label>
            <Input id="sub-url" onChange={(event) => setSubUrl(event.target.value)} value={subUrl} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="sub-hours">{t("pages.singbox.interval")}</Label>
            <Input id="sub-hours" onChange={(event) => setSubHours(event.target.value)} value={subHours} />
          </div>
        </div>
        <Button disabled={loadSubscription.isPending || subUrl.trim().length === 0} onClick={() => loadSubscription.mutate()}>
          {t("pages.singbox.loadSubscription")}
        </Button>
        {preview ? (
          <div className="grid gap-2">
            {preview.map((node) => (
              <label className="flex items-start gap-2 text-sm" key={node.identity || `${node.name}-${node.reason}`}>
                <input
                  checked={!node.skipped && !!picked[node.identity]}
                  className="mt-1 size-4 accent-primary"
                  disabled={node.skipped || !node.identity}
                  onChange={(event) =>
                    setPicked((current) => ({ ...current, [node.identity]: event.target.checked }))
                  }
                  type="checkbox"
                />
                <span>
                  <span className="font-medium">{node.name || node.server || t("pages.singbox.unnamed")}</span>
                  {" · "}
                  {node.protocol || "—"}
                  {node.server ? ` · ${node.server}${node.port ? `:${node.port}` : ""}` : ""}
                  {node.skipped ? (
                    <span className="text-muted-foreground"> — {node.reason}</span>
                  ) : null}
                </span>
              </label>
            ))}
            <Button disabled={confirmSubscription.isPending} onClick={() => confirmSubscription.mutate()}>
              {t("pages.singbox.confirmSelection")}
            </Button>
          </div>
        ) : null}
        {subscriptions.map((subscription) => (
          <SubscriptionCard
            createdIdentities={nodes
              .filter((node) => node.subscription_id === subscription.id)
              .map((node) => node.identity)}
            key={subscription.id}
            locale={i18n.language}
            onError={fail}
            onSuccess={async (state, fallback) => {
              setError("")
              setSuccess(noticeText(state, t, fallback))
              await invalidate()
            }}
            subscription={subscription}
            tun={tun}
          />
        ))}
      </section>
    </div>
  )
}

function NodeCard({
  node,
  onSuccess,
  onError,
}: {
  node: SingboxNode
  onSuccess: (state: SingboxState, fallback: string) => Promise<void>
  onError: (caught: unknown) => void
}) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const [tag, setTag] = useState(node.tag)
  const [iface, setIface] = useState(node.interface)
  const [stack, setStack] = useState(node.tun_stack || "gvisor")
  const [mtu, setMtu] = useState(String(node.tun_mtu || 1400))
  const [address, setAddress] = useState(node.tun_address || "")
  const tagError = getTagNameValidationError(tag, {
    requiredError: t("common.validation.required"),
    invalidError: t("common.validation.tagNamePattern"),
    duplicateError: null,
  })
  const save = useMutation({
    mutationFn: () =>
      postSingbox("/api/sing-box/nodes/update", {
        id: node.id,
        tag,
        interface: iface,
        tun_stack: stack,
        tun_mtu: Number(mtu) || 1400,
        tun_address: address,
      }),
    onSuccess: async (state) => {
      setEditing(false)
      await onSuccess(state, t("pages.singbox.saved"))
    },
    onError,
  })
  const remove = useMutation({
    mutationFn: () => postSingbox("/api/sing-box/nodes/delete", { id: node.id }),
    onSuccess: (state) => onSuccess(state, t("pages.singbox.saved")),
    onError,
  })
  const source =
    node.source === "subscription"
      ? node.subscription_name || t("pages.singbox.subscription")
      : t("pages.singbox.sourceLink")
  return (
    <article className="grid gap-2 rounded-xl border border-border p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-base font-medium">{node.tag}</h3>
        <span className="text-sm text-muted-foreground">
          {node.protocol} · {node.server}:{node.port} · {node.interface} · {source}
          {node.unsupported ? ` · ${t("pages.singbox.unsupportedCore")}` : ""}
          {node.missing ? ` · ${t("pages.singbox.missing")}` : ""}
        </span>
      </div>
      <p className="text-sm text-muted-foreground">{node.name}</p>
      {node.unsupported && node.unsupported_reason ? (
        <p className="text-sm text-destructive">{localizeServerMessage(node.unsupported_reason, t)}</p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => setEditing((value) => !value)} size="sm" variant="outline">
          {t("pages.singbox.edit")}
        </Button>
        <Button disabled={remove.isPending} onClick={() => remove.mutate()} size="sm" variant="outline">
          {t("pages.singbox.deleteNode")}
        </Button>
      </div>
      {editing ? (
        <div className="grid gap-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor={`${node.id}-tag`}>{t("pages.singbox.tag")}</Label>
              <Input
                aria-invalid={tagError ? true : undefined}
                id={`${node.id}-tag`}
                onChange={(event) => setTag(event.target.value)}
                value={tag}
              />
              <p className={tagError ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
                {t("common.validation.tagNamePattern")}
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor={`${node.id}-iface`}>{t("pages.singbox.interface")}</Label>
              <Input id={`${node.id}-iface`} onChange={(event) => setIface(event.target.value)} value={iface} />
            </div>
          </div>
          <TunFields
            address={address}
            idPrefix={node.id}
            mtu={mtu}
            onAddress={setAddress}
            onMtu={setMtu}
            onStack={setStack}
            stack={stack}
          />
          <Button disabled={save.isPending || Boolean(tagError)} onClick={() => save.mutate()}>
            {t("pages.singbox.save")}
          </Button>
        </div>
      ) : null}
    </article>
  )
}

function SubscriptionCard({
  subscription,
  locale,
  tun,
  createdIdentities,
  onSuccess,
  onError,
}: {
  subscription: SingboxSubscription
  locale: string
  tun: { tun_stack: string; tun_mtu: number; tun_address: string }
  createdIdentities: string[]
  onSuccess: (state: SingboxState, fallback: string) => Promise<void>
  onError: (caught: unknown) => void
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [picked, setPicked] = useState<Record<string, boolean>>({})
  const created = new Set(createdIdentities)
  const refresh = useMutation({
    mutationFn: () => postSingbox("/api/sing-box/subscriptions/refresh", { subscription_id: subscription.id }),
    onSuccess: (state) => onSuccess(state, t("pages.singbox.saved")),
    onError,
  })
  const remove = useMutation({
    mutationFn: () => postSingbox("/api/sing-box/subscriptions/delete", { subscription_id: subscription.id }),
    onSuccess: (state) => onSuccess(state, t("pages.singbox.saved")),
    onError,
  })
  const select = useMutation({
    mutationFn: () =>
      postSingbox("/api/sing-box/subscriptions/select", {
        subscription_id: subscription.id,
        selected: Object.entries(picked)
          .filter(([, on]) => on)
          .map(([identity]) => identity),
        ...tun,
      }),
    onSuccess: async (state) => {
      setOpen(false)
      await onSuccess(state, t("pages.singbox.subscriptionSaved"))
    },
    onError,
  })
  return (
    <article className="grid gap-2 rounded-lg border border-border p-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="font-medium">{subscription.name}</h3>
        <span className="text-sm text-muted-foreground">
          {t("pages.singbox.lastRefresh")}: {formatRefreshTime(subscription.last_refresh, locale)}
        </span>
      </div>
      <p className="text-sm text-muted-foreground">
        {t("pages.singbox.interval")}: {subscription.interval_hours === 0 ? t("pages.singbox.autoRefreshOff") : subscription.interval_hours}
        {subscription.next_refresh ? ` · ${t("pages.singbox.nextRefresh")}: ${formatRefreshTime(subscription.next_refresh, locale)}` : ""}
      </p>
      {subscription.last_error ? <p className="text-sm text-destructive">{subscription.last_error}</p> : null}
      {subscription.new_nodes > 0 ? (
        <p className="text-sm">{t("pages.singbox.newNodes", { count: subscription.new_nodes })}</p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button disabled={refresh.isPending} onClick={() => refresh.mutate()} size="sm" variant="outline">
          {t("pages.singbox.refresh")}
        </Button>
        <Button
          onClick={() => {
            const next: Record<string, boolean> = {}
            for (const node of subscription.catalog) {
              if (!node.skipped && node.identity) next[node.identity] = false
            }
            setPicked(next)
            setOpen(true)
          }}
          size="sm"
          variant="outline"
        >
          {t("pages.singbox.selectNodes")}
        </Button>
        <Button disabled={remove.isPending} onClick={() => remove.mutate()} size="sm" variant="outline">
          {t("pages.singbox.removeSubscription")}
        </Button>
      </div>
      {open ? (
        <div className="grid gap-2">
          {subscription.catalog.map((node) => {
            const already = created.has(node.identity)
            return (
              <label className="flex items-start gap-2 text-sm" key={`${node.identity}-${node.reason}`}>
                <input
                  checked={already || (!node.skipped && !!picked[node.identity])}
                  className="mt-1 size-4 accent-primary"
                  disabled={node.skipped || already}
                  onChange={(event) =>
                    setPicked((current) => ({ ...current, [node.identity]: event.target.checked }))
                  }
                  type="checkbox"
                />
                <span>
                  {node.name || node.server || t("pages.singbox.unnamed")}
                  {" · "}
                  {node.protocol || "—"}
                  {node.server ? ` · ${node.server}:${node.port}` : ""}
                  {node.skipped ? <span className="text-muted-foreground"> — {node.reason}</span> : null}
                  {already ? <span className="text-muted-foreground"> — {t("pages.singbox.alreadyAdded")}</span> : null}
                </span>
              </label>
            )
          })}
          <Button disabled={select.isPending} onClick={() => select.mutate()} size="sm">
            {t("pages.singbox.confirmSelection")}
          </Button>
        </div>
      ) : null}
    </article>
  )
}
