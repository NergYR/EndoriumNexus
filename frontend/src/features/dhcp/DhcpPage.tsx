import { useMemo, useState } from "react";

import { Panel } from "../../components/Panel";
import {
  useCreateDhcpPool,
  useDeleteDhcpPool,
  useDhcpPools,
  useRestartDhcpService,
  useUpdateDhcpPool
} from "../../lib/api";

type AdvancedOption = {
  id: number;
  key: string;
  value: string;
};

type PoolForm = {
  name: string;
  subnet: string;
  rangeStart: string;
  rangeEnd: string;
  router: string;
  dns: string;
  dnsSecondary: string;
  domainName: string;
  domainSearch: string;
  ntpServer: string;
  tftpServer: string;
  bootFile: string;
  nextServer: string;
  leaseTime: string;
  maxLeaseTime: string;
  mtu: string;
  broadcastAddress: string;
  advancedOptions: AdvancedOption[];
};

const KNOWN_OPTION_KEYS = new Set([
  "router",
  "dns",
  "dns-secondary",
  "domain-name",
  "domain-search",
  "ntp-server",
  "tftp-server-name",
  "bootfile-name",
  "next-server",
  "lease-time",
  "max-lease-time",
  "interface-mtu",
  "broadcast-address"
]);

const DHCP_OPTION_SUGGESTIONS = [
  { key: "static-route", label: "Static route", placeholder: "10.40.0.0/16,10.10.10.254" },
  { key: "vendor-class-identifier", label: "Vendor class", placeholder: "PXEClient" },
  { key: "wpad-url", label: "WPAD URL", placeholder: "http://wpad.endorium.local/wpad.dat" },
  { key: "time-offset", label: "Time offset", placeholder: "0" },
  { key: "sip-server", label: "SIP server", placeholder: "sip.endorium.local" }
] as const;

const LEASE_PRESETS = [
  { label: "6 hours", value: "21600" },
  { label: "12 hours", value: "43200" },
  { label: "1 day", value: "86400" },
  { label: "7 days", value: "604800" }
] as const;

function makeOptionId() {
  return Date.now() + Math.floor(Math.random() * 1000);
}

function optionsToForm(options: Record<string, string>) {
  const advancedOptions = Object.entries(options)
    .filter(([key]) => !KNOWN_OPTION_KEYS.has(key))
    .map(([key, value], index) => ({ id: makeOptionId() + index, key, value }));

  return {
    router: options.router ?? "",
    dns: options.dns ?? "",
    dnsSecondary: options["dns-secondary"] ?? "",
    domainName: options["domain-name"] ?? "",
    domainSearch: options["domain-search"] ?? "",
    ntpServer: options["ntp-server"] ?? "",
    tftpServer: options["tftp-server-name"] ?? "",
    bootFile: options["bootfile-name"] ?? "",
    nextServer: options["next-server"] ?? "",
    leaseTime: options["lease-time"] ?? "",
    maxLeaseTime: options["max-lease-time"] ?? "",
    mtu: options["interface-mtu"] ?? "",
    broadcastAddress: options["broadcast-address"] ?? "",
    advancedOptions
  };
}

function buildOptionsFromForm(form: PoolForm) {
  const options: Record<string, string> = {};

  const add = (key: string, value: string) => {
    const trimmed = value.trim();
    if (trimmed) {
      options[key] = trimmed;
    }
  };

  add("router", form.router);
  add("dns", form.dns);
  add("dns-secondary", form.dnsSecondary);
  add("domain-name", form.domainName);
  add("domain-search", form.domainSearch);
  add("ntp-server", form.ntpServer);
  add("tftp-server-name", form.tftpServer);
  add("bootfile-name", form.bootFile);
  add("next-server", form.nextServer);
  add("lease-time", form.leaseTime);
  add("max-lease-time", form.maxLeaseTime);
  add("interface-mtu", form.mtu);
  add("broadcast-address", form.broadcastAddress);

  for (const option of form.advancedOptions) {
    add(option.key, option.value);
  }

  return options;
}

function defaultPoolForm(): PoolForm {
  return {
    name: "pool-main",
    subnet: "10.10.10.0/24",
    rangeStart: "10.10.10.100",
    rangeEnd: "10.10.10.200",
    router: "10.10.10.1",
    dns: "10.10.10.10",
    dnsSecondary: "10.10.10.11",
    domainName: "endorium.local",
    domainSearch: "endorium.local,lab.endorium.local",
    ntpServer: "10.10.10.15",
    tftpServer: "",
    bootFile: "",
    nextServer: "",
    leaseTime: "86400",
    maxLeaseTime: "604800",
    mtu: "",
    broadcastAddress: "10.10.10.255",
    advancedOptions: []
  };
}

const POOL_TEMPLATES = [
  {
    label: "Office LAN",
    value: "office",
    form: {
      subnet: "10.10.10.0/24",
      rangeStart: "10.10.10.100",
      rangeEnd: "10.10.10.200",
      router: "10.10.10.1",
      dns: "10.10.10.10",
      dnsSecondary: "10.10.10.11",
      domainName: "endorium.local",
      domainSearch: "endorium.local,lab.endorium.local",
      ntpServer: "10.10.10.15",
      tftpServer: "",
      bootFile: "",
      nextServer: "",
      leaseTime: "86400",
      maxLeaseTime: "604800",
      mtu: "",
      broadcastAddress: "10.10.10.255"
    }
  },
  {
    label: "Lab VLAN",
    value: "lab",
    form: {
      subnet: "10.20.20.0/24",
      rangeStart: "10.20.20.50",
      rangeEnd: "10.20.20.150",
      router: "10.20.20.1",
      dns: "10.10.10.10",
      dnsSecondary: "10.10.10.11",
      domainName: "lab.endorium.local",
      domainSearch: "lab.endorium.local,endorium.local",
      ntpServer: "10.10.10.15",
      tftpServer: "10.20.20.5",
      bootFile: "pxelinux.0",
      nextServer: "10.20.20.5",
      leaseTime: "43200",
      maxLeaseTime: "604800",
      mtu: "",
      broadcastAddress: "10.20.20.255"
    }
  },
  {
    label: "Guest Wi-Fi",
    value: "guest",
    form: {
      subnet: "10.30.30.0/24",
      rangeStart: "10.30.30.100",
      rangeEnd: "10.30.30.220",
      router: "10.30.30.1",
      dns: "10.10.10.10",
      dnsSecondary: "1.1.1.1",
      domainName: "guest.endorium.local",
      domainSearch: "guest.endorium.local",
      ntpServer: "10.10.10.15",
      tftpServer: "",
      bootFile: "",
      nextServer: "",
      leaseTime: "21600",
      maxLeaseTime: "86400",
      mtu: "",
      broadcastAddress: "10.30.30.255"
    }
  }
] as const;

type PoolTemplateValue = (typeof POOL_TEMPLATES)[number]["value"];

function validatePoolForm(form: PoolForm) {
  if (!form.name.trim() || !form.subnet.trim() || !form.rangeStart.trim() || !form.rangeEnd.trim()) {
    return "Pool name, subnet and allocation range are required.";
  }

  const badAdvancedOption = form.advancedOptions.find((option) => option.key.trim() && !option.value.trim());
  if (badAdvancedOption) {
    return "Advanced DHCP options need both a key and a value.";
  }

  return null;
}

export function DhcpPage() {
  const pools = useDhcpPools();
  const createPool = useCreateDhcpPool();
  const updatePool = useUpdateDhcpPool();
  const deletePool = useDeleteDhcpPool();
  const restartService = useRestartDhcpService();
  const [editingPoolName, setEditingPoolName] = useState<string | null>(null);
  const [form, setForm] = useState<PoolForm>(() => defaultPoolForm());
  const [formError, setFormError] = useState<string | null>(null);

  const optionPreview = useMemo(() => buildOptionsFromForm(form), [form]);

  if (pools.isLoading || !pools.data) {
    return <div className="text-sm text-slate-500">Chargement des pools DHCP...</div>;
  }

  const beginEdit = (name: string) => {
    const pool = pools.data.find((entry) => entry.name === name);
    if (!pool) {
      return;
    }

    setEditingPoolName(pool.name);
    setFormError(null);
    const optionFields = optionsToForm(pool.options);
    setForm({
      ...defaultPoolForm(),
      name: pool.name,
      subnet: pool.subnet,
      rangeStart: pool.rangeStart,
      rangeEnd: pool.rangeEnd,
      ...optionFields
    });
  };

  const resetForm = () => {
    setEditingPoolName(null);
    setFormError(null);
    setForm(defaultPoolForm());
  };

  const applyTemplate = (templateValue: PoolTemplateValue) => {
    const template = POOL_TEMPLATES.find((entry) => entry.value === templateValue);
    if (!template) {
      return;
    }

    setFormError(null);
    setForm((current) => ({
      ...current,
      ...template.form
    }));
  };

  const updateAdvancedOption = (id: number, patch: Partial<AdvancedOption>) => {
    setFormError(null);
    setForm((current) => ({
      ...current,
      advancedOptions: current.advancedOptions.map((option) => (option.id === id ? { ...option, ...patch } : option))
    }));
  };

  const addAdvancedOption = (key = "", value = "") => {
    setForm((current) => ({
      ...current,
      advancedOptions: [...current.advancedOptions, { id: makeOptionId(), key, value }]
    }));
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col justify-between gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 md:flex-row md:items-center">
        <p className="text-sm text-slate-600">
          Modifications are saved immediately but require a service restart to take effect.
        </p>
        <button
          className="rounded-full border border-slate-200 px-4 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-50 disabled:opacity-60"
          onClick={() => restartService.mutate()}
          type="button"
          disabled={restartService.isPending}
        >
          {restartService.isPending ? "Restarting..." : "Restart Service"}
        </button>
        {restartService.error ? <p className="text-sm text-rose-200">{restartService.error.message}</p> : null}
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <Panel title="DHCP Pools and Leases" eyebrow="IPv4 Allocation">
          <div className="space-y-5">
            {pools.data.length ? (
              pools.data.map((pool) => (
                <section className="rounded-3xl border border-slate-200 bg-white p-5" key={pool.name}>
                  <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-slate-900">{pool.name}</h3>
                      <p className="text-sm text-slate-600">
                        {pool.subnet} - {pool.rangeStart} to {pool.rangeEnd}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        className="rounded-full border border-slate-200 px-3 py-1 text-xs uppercase tracking-[0.18em] text-slate-600 transition hover:bg-slate-50"
                        onClick={() => beginEdit(pool.name)}
                        type="button"
                      >
                        Edit
                      </button>
                      <button
                        className="rounded-full border border-rose-300/20 px-3 py-1 text-xs uppercase tracking-[0.18em] text-rose-100 transition hover:bg-rose-300/10"
                        onClick={() => deletePool.mutate({ poolName: pool.name })}
                        type="button"
                      >
                        Delete
                      </button>
                      <div className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs uppercase tracking-[0.18em] text-slate-600">
                        {pool.leases.length} leases
                      </div>
                    </div>
                  </div>

                  {Object.keys(pool.options).length ? (
                    <div className="mt-4 grid gap-2 md:grid-cols-2">
                      {Object.entries(pool.options).map(([key, value]) => (
                        <div className="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2" key={`${pool.name}-${key}`}>
                          <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{key}</p>
                          <p className="mt-1 break-all text-sm text-slate-700">{value}</p>
                        </div>
                      ))}
                    </div>
                  ) : null}

                  <div className="mt-4 grid gap-3 lg:grid-cols-2">
                    {pool.leases.map((lease) => (
                      <article className="rounded-2xl border border-slate-200 bg-white px-4 py-3" key={lease.ipAddress}>
                        <p className="font-medium text-slate-900">{lease.ipAddress}</p>
                        <p className="mt-1 text-sm text-slate-600">{lease.hostname}</p>
                        <p className="mt-2 text-xs uppercase tracking-[0.16em] text-slate-500">
                          {lease.clientId} - {lease.state}
                        </p>
                      </article>
                    ))}
                  </div>
                </section>
              ))
            ) : (
              <p className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
                No DHCP pool is configured yet. Create a pool to start allocating leases.
              </p>
            )}
          </div>
        </Panel>

        <Panel title={editingPoolName ? "Edit DHCP Pool" : "Create DHCP Pool"} eyebrow="Guided Configuration">
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              const error = validatePoolForm(form);
              if (error) {
                setFormError(error);
                return;
              }

              const payload = {
                name: form.name.trim(),
                subnet: form.subnet.trim(),
                rangeStart: form.rangeStart.trim(),
                rangeEnd: form.rangeEnd.trim(),
                options: buildOptionsFromForm(form)
              };

              if (editingPoolName) {
                updatePool.mutate(
                  { poolName: editingPoolName, pool: payload },
                  {
                    onSuccess: resetForm
                  }
                );
                return;
              }

              createPool.mutate(payload, {
                onSuccess: resetForm
              });
            }}
          >
            <label className="grid gap-2">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Preset</span>
              <select
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => applyTemplate(event.target.value as PoolTemplateValue)}
                defaultValue="office"
              >
                {POOL_TEMPLATES.map((template) => (
                  <option key={template.value} value={template.value}>
                    {template.label}
                  </option>
                ))}
              </select>
            </label>

            <div className="grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <p className="text-sm font-medium text-slate-900">Addressing</p>
              <label className="grid gap-2">
                <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Pool name</span>
                <input
                  className="field rounded-2xl px-4 py-3 outline-none"
                  onChange={(event) => {
                    setFormError(null);
                    setForm((current) => ({ ...current, name: event.target.value }));
                  }}
                  value={form.name}
                />
              </label>
              <label className="grid gap-2">
                <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Subnet</span>
                <input
                  className="field rounded-2xl px-4 py-3 outline-none"
                  onChange={(event) => {
                    setFormError(null);
                    setForm((current) => ({ ...current, subnet: event.target.value }));
                  }}
                  placeholder="10.10.10.0/24"
                  value={form.subnet}
                />
              </label>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Range start</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => {
                      setFormError(null);
                      setForm((current) => ({ ...current, rangeStart: event.target.value }));
                    }}
                    value={form.rangeStart}
                  />
                </label>
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Range end</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => {
                      setFormError(null);
                      setForm((current) => ({ ...current, rangeEnd: event.target.value }));
                    }}
                    value={form.rangeEnd}
                  />
                </label>
              </div>
            </div>

            <div className="grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <p className="text-sm font-medium text-slate-900">Client Network Options</p>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Router / gateway</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, router: event.target.value }))}
                    placeholder="10.10.10.1"
                    value={form.router}
                  />
                </label>
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Broadcast address</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, broadcastAddress: event.target.value }))}
                    placeholder="10.10.10.255"
                    value={form.broadcastAddress}
                  />
                </label>
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Primary DNS</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, dns: event.target.value }))}
                    placeholder="10.10.10.10"
                    value={form.dns}
                  />
                </label>
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Secondary DNS</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, dnsSecondary: event.target.value }))}
                    placeholder="10.10.10.11"
                    value={form.dnsSecondary}
                  />
                </label>
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Domain name</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, domainName: event.target.value }))}
                    placeholder="endorium.local"
                    value={form.domainName}
                  />
                </label>
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Domain search</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, domainSearch: event.target.value }))}
                    placeholder="endorium.local,lab.endorium.local"
                    value={form.domainSearch}
                  />
                </label>
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">NTP server</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, ntpServer: event.target.value }))}
                    placeholder="10.10.10.15"
                    value={form.ntpServer}
                  />
                </label>
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Interface MTU</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, mtu: event.target.value }))}
                    placeholder="1500"
                    value={form.mtu}
                  />
                </label>
              </div>
            </div>

            <div className="grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <p className="text-sm font-medium text-slate-900">Lease and Boot Options</p>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Lease time</span>
                  <select
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, leaseTime: event.target.value }))}
                    value={form.leaseTime}
                  >
                    {LEASE_PRESETS.map((preset) => (
                      <option key={preset.value} value={preset.value}>
                        {preset.label} ({preset.value}s)
                      </option>
                    ))}
                    {!LEASE_PRESETS.some((preset) => preset.value === form.leaseTime) ? (
                      <option value={form.leaseTime}>Custom ({form.leaseTime}s)</option>
                    ) : null}
                  </select>
                </label>
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Max lease time</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, maxLeaseTime: event.target.value }))}
                    placeholder="604800"
                    value={form.maxLeaseTime}
                  />
                </label>
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">TFTP server</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, tftpServer: event.target.value }))}
                    placeholder="10.20.20.5"
                    value={form.tftpServer}
                  />
                </label>
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Next server</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => setForm((current) => ({ ...current, nextServer: event.target.value }))}
                    placeholder="10.20.20.5"
                    value={form.nextServer}
                  />
                </label>
              </div>
              <label className="grid gap-2">
                <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Boot file</span>
                <input
                  className="field rounded-2xl px-4 py-3 outline-none"
                  onChange={(event) => setForm((current) => ({ ...current, bootFile: event.target.value }))}
                  placeholder="pxelinux.0"
                  value={form.bootFile}
                />
              </label>
            </div>

            <div className="grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <p className="text-sm font-medium text-slate-900">Advanced Options</p>
                <select
                  className="field rounded-2xl px-4 py-3 text-sm outline-none"
                  defaultValue=""
                  onChange={(event) => {
                    const suggestion = DHCP_OPTION_SUGGESTIONS.find((entry) => entry.key === event.target.value);
                    if (suggestion) {
                      addAdvancedOption(suggestion.key, suggestion.placeholder);
                    }
                    event.currentTarget.value = "";
                  }}
                >
                  <option value="">Add common option...</option>
                  {DHCP_OPTION_SUGGESTIONS.map((option) => (
                    <option key={option.key} value={option.key}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              {form.advancedOptions.map((option) => (
                <div className="grid gap-2 md:grid-cols-[0.9fr_1fr_auto]" key={option.id}>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => updateAdvancedOption(option.id, { key: event.target.value })}
                    placeholder="option-key"
                    value={option.key}
                  />
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => updateAdvancedOption(option.id, { value: event.target.value })}
                    placeholder="value"
                    value={option.value}
                  />
                  <button
                    className="rounded-2xl border border-rose-200 px-4 py-3 text-sm font-medium text-rose-700 transition hover:bg-rose-50"
                    onClick={() => {
                      setForm((current) => ({
                        ...current,
                        advancedOptions: current.advancedOptions.filter((entry) => entry.id !== option.id)
                      }));
                    }}
                    type="button"
                  >
                    Remove
                  </button>
                </div>
              ))}

              <button
                className="rounded-2xl border border-slate-200 px-4 py-3 text-sm font-medium text-slate-600 transition hover:bg-slate-50"
                onClick={() => addAdvancedOption()}
                type="button"
              >
                Add custom option
              </button>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Option payload</p>
              <pre className="mt-2 overflow-x-auto text-sm text-slate-700">{JSON.stringify(optionPreview, null, 2)}</pre>
            </div>

            <div className="flex flex-wrap gap-3">
              <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" type="submit">
                {editingPoolName ? "Save pool" : "Create pool"}
              </button>
              {editingPoolName ? (
                <button
                  className="rounded-2xl border border-slate-200 px-4 py-3 font-medium text-slate-600 transition hover:bg-slate-50"
                  onClick={resetForm}
                  type="button"
                >
                  Cancel edit
                </button>
              ) : null}
            </div>
            {createPool.error || updatePool.error || deletePool.error ? (
              <p className="text-sm text-rose-200">
                {createPool.error?.message ?? updatePool.error?.message ?? deletePool.error?.message}
              </p>
            ) : null}
            {formError ? <p className="text-sm text-amber-200">{formError}</p> : null}
          </form>
        </Panel>
      </div>
    </div>
  );
}
