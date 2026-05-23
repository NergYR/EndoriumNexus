import { useEffect, useMemo, useState } from "react";

import { Panel } from "../../components/Panel";
import {
  useCreateDnsRecord,
  useCreateDnsZone,
  useDeleteDnsRecord,
  useDeleteDnsZone,
  useDnsZones,
  useRestartDnsService,
  useUpdateDnsRecord,
  useUpdateDnsZone,
  useZoneRender
} from "../../lib/api";
import type { DnsRecordCreatePayload } from "../../lib/types";

const DNS_RECORD_TYPES = [
  { value: "A", label: "A", description: "IPv4 host address" },
  { value: "AAAA", label: "AAAA", description: "IPv6 host address" },
  { value: "CNAME", label: "CNAME", description: "Alias to another name" },
  { value: "MX", label: "MX", description: "Mail exchanger with priority" },
  { value: "SRV", label: "SRV", description: "Service target, weight and port" },
  { value: "TXT", label: "TXT", description: "Verification or policy text" },
  { value: "NS", label: "NS", description: "Delegated name server" },
  { value: "PTR", label: "PTR", description: "Reverse lookup pointer" },
  { value: "CAA", label: "CAA", description: "Certificate authority policy" }
] as const;

const DNS_CLASSES = ["IN", "CH", "HS"] as const;
const TTL_PRESETS = [
  { label: "5 min", value: 300 },
  { label: "15 min", value: 900 },
  { label: "1 hour", value: 3600 },
  { label: "1 day", value: 86400 }
] as const;

type DnsRecordType = (typeof DNS_RECORD_TYPES)[number]["value"];

type ZoneForm = {
  name: string;
};

type RecordForm = {
  name: string;
  type: DnsRecordType;
  class: string;
  value: string;
  ttl: number;
  priority: number;
  port: number;
  weight: number;
  flags: string;
};

type RecordTypeConfig = {
  hint: string;
  namePlaceholder: string;
  valueLabel: string;
  valuePlaceholder: string;
  valueHelp: string;
  defaultName: string;
  defaultValue: string;
  defaults: Partial<RecordForm>;
  showPriority?: boolean;
  showWeight?: boolean;
  showPort?: boolean;
  showFlags?: boolean;
  priorityLabel?: string;
  flagsLabel?: string;
  flagsPlaceholder?: string;
};

const RECORD_TYPE_CONFIG: Record<DnsRecordType, RecordTypeConfig> = {
  A: {
    hint: "Map a hostname to an IPv4 address.",
    namePlaceholder: "www or @",
    valueLabel: "IPv4 address",
    valuePlaceholder: "10.10.10.20",
    valueHelp: "Use dotted quad notation.",
    defaultName: "www",
    defaultValue: "10.10.10.20",
    defaults: { priority: 0, weight: 0, port: 0, flags: "" }
  },
  AAAA: {
    hint: "Map a hostname to an IPv6 address.",
    namePlaceholder: "www or @",
    valueLabel: "IPv6 address",
    valuePlaceholder: "2001:db8::20",
    valueHelp: "Compressed IPv6 notation is accepted.",
    defaultName: "www",
    defaultValue: "2001:db8::20",
    defaults: { priority: 0, weight: 0, port: 0, flags: "" }
  },
  CNAME: {
    hint: "Create an alias to a canonical DNS name.",
    namePlaceholder: "app",
    valueLabel: "Canonical hostname",
    valuePlaceholder: "web.endorium.local.",
    valueHelp: "Prefer a trailing dot for a fully qualified target.",
    defaultName: "app",
    defaultValue: "web.endorium.local.",
    defaults: { priority: 0, weight: 0, port: 0, flags: "" }
  },
  MX: {
    hint: "Route mail for this zone or host to a mail exchanger.",
    namePlaceholder: "@",
    valueLabel: "Mail server",
    valuePlaceholder: "mail.endorium.local.",
    valueHelp: "Lower priority values are preferred first.",
    defaultName: "@",
    defaultValue: "mail.endorium.local.",
    defaults: { priority: 10, weight: 0, port: 0, flags: "" },
    showPriority: true,
    priorityLabel: "Preference"
  },
  SRV: {
    hint: "Publish service discovery data for protocols such as LDAP, SIP or Kerberos.",
    namePlaceholder: "_ldap._tcp",
    valueLabel: "Target host",
    valuePlaceholder: "directory.endorium.local.",
    valueHelp: "SRV records require priority, weight and port.",
    defaultName: "_ldap._tcp",
    defaultValue: "directory.endorium.local.",
    defaults: { priority: 10, weight: 10, port: 389, flags: "" },
    showPriority: true,
    showWeight: true,
    showPort: true,
    priorityLabel: "Priority"
  },
  TXT: {
    hint: "Publish SPF, ownership verification, DKIM fragments or arbitrary text.",
    namePlaceholder: "@ or _dmarc",
    valueLabel: "Text payload",
    valuePlaceholder: "v=spf1 mx -all",
    valueHelp: "Quotes are added by downstream DNS tooling when needed.",
    defaultName: "@",
    defaultValue: "v=spf1 mx -all",
    defaults: { priority: 0, weight: 0, port: 0, flags: "" }
  },
  NS: {
    hint: "Delegate a zone or subdomain to an authoritative name server.",
    namePlaceholder: "@ or lab",
    valueLabel: "Name server",
    valuePlaceholder: "ns1.endorium.local.",
    valueHelp: "Use a hostname, usually fully qualified.",
    defaultName: "@",
    defaultValue: "ns1.endorium.local.",
    defaults: { priority: 0, weight: 0, port: 0, flags: "" }
  },
  PTR: {
    hint: "Point a reverse lookup name to its canonical hostname.",
    namePlaceholder: "20",
    valueLabel: "Canonical hostname",
    valuePlaceholder: "host20.endorium.local.",
    valueHelp: "Use this inside a reverse DNS zone.",
    defaultName: "20",
    defaultValue: "host20.endorium.local.",
    defaults: { priority: 0, weight: 0, port: 0, flags: "" }
  },
  CAA: {
    hint: "Restrict which certificate authorities can issue certificates.",
    namePlaceholder: "@",
    valueLabel: "CAA value",
    valuePlaceholder: "letsencrypt.org",
    valueHelp: "Common tags are issue, issuewild and iodef.",
    defaultName: "@",
    defaultValue: "letsencrypt.org",
    defaults: { priority: 0, weight: 0, port: 0, flags: "issue" },
    showPriority: true,
    showFlags: true,
    priorityLabel: "Flag",
    flagsLabel: "Tag",
    flagsPlaceholder: "issue"
  }
};

function isDnsRecordType(value: string): value is DnsRecordType {
  return DNS_RECORD_TYPES.some((entry) => entry.value === value);
}

function defaultRecordForm(type: DnsRecordType = "A"): RecordForm {
  const config = RECORD_TYPE_CONFIG[type];
  return {
    name: config.defaultName,
    type,
    class: "IN",
    value: config.defaultValue,
    ttl: 300,
    priority: 0,
    port: 0,
    weight: 0,
    flags: "",
    ...config.defaults
  };
}

function isValidIpv4(value: string) {
  return /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/.test(value);
}

function isValidIpv6(value: string) {
  return /^[0-9a-fA-F:]+$/.test(value) && value.includes(":");
}

function isValidHostname(value: string) {
  return /^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.?$/.test(value);
}

function validateDnsRecord(record: RecordForm): string | null {
  const name = record.name.trim();
  const value = record.value.trim();

  if (!name) {
    return "Record name is required.";
  }

  if (!value) {
    return "Record value is required.";
  }

  if (record.ttl <= 0) {
    return "TTL must be greater than zero.";
  }

  if (record.type === "A" && !isValidIpv4(value)) {
    return "A records must point to a valid IPv4 address.";
  }

  if (record.type === "AAAA" && !isValidIpv6(value)) {
    return "AAAA records must point to a valid IPv6 address.";
  }

  if ((record.type === "CNAME" || record.type === "MX" || record.type === "NS" || record.type === "PTR" || record.type === "SRV") && !isValidHostname(value)) {
    return `${record.type} records must point to a valid hostname.`;
  }

  if (record.type === "SRV") {
    if (record.port <= 0 || record.port > 65535) {
      return "SRV records require a port between 1 and 65535.";
    }

    if (record.priority < 0 || record.weight < 0) {
      return "SRV priority and weight must be non-negative.";
    }
  }

  if (record.type === "MX" && record.priority < 0) {
    return "MX preference must be non-negative.";
  }

  if (record.type === "CAA") {
    if (record.priority < 0 || record.priority > 255) {
      return "CAA flag must be between 0 and 255.";
    }

    if (!record.flags.trim()) {
      return "CAA records require a tag such as issue, issuewild or iodef.";
    }
  }

  return null;
}

function buildRecordPayload(record: RecordForm): DnsRecordCreatePayload {
  const payload: DnsRecordCreatePayload = {
    name: record.name.trim(),
    type: record.type,
    class: record.class.trim().toUpperCase(),
    value: record.value.trim(),
    ttl: record.ttl,
    priority: record.priority
  };

  if (record.type === "SRV") {
    payload.weight = record.weight;
    payload.port = record.port;
  }

  if (record.type === "CAA") {
    payload.flags = record.flags.trim();
  }

  return payload;
}

function renderRecordPreview(record: RecordForm) {
  const payload = buildRecordPayload(record);
  if (payload.type === "SRV") {
    return `${payload.name} ${payload.ttl} ${payload.class ?? "IN"} SRV ${payload.priority} ${payload.weight ?? 0} ${payload.port ?? 0} ${payload.value}`;
  }

  if (payload.type === "MX") {
    return `${payload.name} ${payload.ttl} ${payload.class ?? "IN"} MX ${payload.priority} ${payload.value}`;
  }

  if (payload.type === "CAA") {
    return `${payload.name} ${payload.ttl} ${payload.class ?? "IN"} CAA ${payload.priority} ${payload.flags ?? "issue"} "${payload.value}"`;
  }

  return `${payload.name} ${payload.ttl} ${payload.class ?? "IN"} ${payload.type} ${payload.value}`;
}

export function DnsPage() {
  const zones = useDnsZones();
  const [selectedZone, setSelectedZone] = useState<string>();
  const zoneRender = useZoneRender(selectedZone);
  const createZone = useCreateDnsZone();
  const updateZone = useUpdateDnsZone();
  const deleteZone = useDeleteDnsZone();
  const createRecord = useCreateDnsRecord();
  const updateRecord = useUpdateDnsRecord();
  const deleteRecord = useDeleteDnsRecord();
  const restartService = useRestartDnsService();
  const [zoneForm, setZoneForm] = useState<ZoneForm>({ name: "endorium.local" });
  const [recordForm, setRecordForm] = useState<RecordForm>(() => defaultRecordForm());
  const [editingRecordIndex, setEditingRecordIndex] = useState<number | null>(null);
  const [recordError, setRecordError] = useState<string | null>(null);
  const recordConfig = RECORD_TYPE_CONFIG[recordForm.type];

  const activeZone = useMemo(() => {
    if (!zones.data?.length) {
      return undefined;
    }
    return zones.data.find((zone) => zone.name === selectedZone) ?? zones.data[0];
  }, [selectedZone, zones.data]);

  useEffect(() => {
    if (activeZone) {
      setSelectedZone(activeZone.name);
    }
  }, [activeZone]);

  const activeRecords = activeZone?.records ?? [];
  const selectedZoneLabel = activeZone?.name ?? "No zone selected";

  const beginEditRecord = (index: number) => {
    const record = activeZone?.records[index];
    if (!record) {
      return;
    }

    const type = isDnsRecordType(record.type) ? record.type : "A";
    setEditingRecordIndex(index);
    setRecordError(null);
    setRecordForm({
      ...defaultRecordForm(type),
      name: record.name,
      type,
      class: record.class || "IN",
      value: record.value,
      ttl: record.ttl,
      priority: record.priority,
      port: record.port ?? 0,
      weight: record.weight ?? 0,
      flags: record.flags || ""
    });
  };

  const setRecordType = (nextType: string) => {
    const type = isDnsRecordType(nextType) ? nextType : "A";
    setRecordError(null);
    setRecordForm((current) => ({
      ...defaultRecordForm(type),
      class: current.class,
      ttl: current.ttl,
      type
    }));
  };

  if (zones.isLoading || !zones.data) {
    return <div className="text-sm text-slate-500">Chargement du DNS...</div>;
  }

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

      <div className="grid gap-6 xl:grid-cols-[1fr_0.95fr]">
        <Panel title="Zone Catalog" eyebrow="Authoritative DNS">
          <div className="flex flex-wrap gap-3">
            {zones.data.map((zone) => (
              <button
                className={[
                  "rounded-2xl border px-4 py-3 text-left transition",
                  activeZone?.name === zone.name
                    ? "border-blue-200 bg-blue-50"
                    : "border-slate-200 bg-white hover:border-slate-300"
                ].join(" ")}
                key={zone.name}
                onClick={() => {
                  setEditingRecordIndex(null);
                  setSelectedZone(zone.name);
                }}
                type="button"
              >
                <p className="font-medium text-slate-900">{zone.name}</p>
                <p className="mt-1 text-sm text-slate-600">{zone.records.length} enregistrements</p>
              </button>
            ))}
          </div>

          {!zones.data.length ? (
            <p className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
              No DNS zone configured yet. Create one to start publishing records.
            </p>
          ) : null}

          {activeZone ? (
            <div className="mt-5 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3">
                <div>
                  <p className="text-sm uppercase tracking-[0.18em] text-slate-500">Selected zone</p>
                  <p className="font-medium text-slate-900">{selectedZoneLabel}</p>
                </div>
                <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Serial {activeZone.serial}</span>
              </div>

              {activeRecords.map((record, index) => (
                <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3" key={`${record.name}-${record.type}-${index}`}>
                  <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                    <div>
                      <p className="font-medium text-slate-900">
                        {record.name} <span className="text-slate-500">{record.type}</span>
                      </p>
                      <p className="mt-1 break-all text-sm text-slate-600">{record.value}</p>
                      <p className="mt-2 text-xs uppercase tracking-[0.18em] text-slate-500">
                        TTL {record.ttl} {record.priority ? `- Priority ${record.priority}` : ""}
                        {record.port ? ` - Port ${record.port}` : ""}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        className="rounded-full border border-slate-200 px-3 py-1 text-xs uppercase tracking-[0.16em] text-slate-600 transition hover:bg-slate-50"
                        onClick={() => beginEditRecord(index)}
                        type="button"
                      >
                        Edit
                      </button>
                      <button
                        className="rounded-full border border-rose-300/20 px-3 py-1 text-xs uppercase tracking-[0.16em] text-rose-100 transition hover:bg-rose-300/10"
                        onClick={() => deleteRecord.mutate({ zoneName: activeZone.name, index })}
                        type="button"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : null}
        </Panel>

        <div className="space-y-6">
          <Panel title="Create or Rename Zone" eyebrow="Bootstrap">
            <form
              className="grid gap-3"
              onSubmit={(event) => {
                event.preventDefault();
                const zoneName = zoneForm.name.trim();
                if (!zoneName) {
                  return;
                }

                if (activeZone && zoneName !== activeZone.name) {
                  updateZone.mutate(
                    { zoneName: activeZone.name, zone: { name: zoneName } },
                    {
                      onSuccess: () => {
                        setSelectedZone(zoneName);
                      }
                    }
                  );
                  return;
                }

                createZone.mutate(
                  { name: zoneName },
                  {
                    onSuccess: (payload) => {
                      setSelectedZone(payload.zone);
                    }
                  }
                );
              }}
            >
              <input
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => setZoneForm({ name: event.target.value })}
                placeholder="Zone name (ex: endorium.local)"
                value={zoneForm.name}
              />
              <div className="flex flex-wrap gap-3">
                <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" type="submit">
                  {activeZone ? "Update zone" : "Create zone"}
                </button>
                {activeZone ? (
                  <button
                    className="rounded-2xl border border-rose-300/20 px-4 py-3 font-medium text-rose-100 transition hover:bg-rose-300/10"
                    onClick={() => {
                      deleteZone.mutate(
                        { zoneName: activeZone.name },
                        {
                          onSuccess: () => {
                            setSelectedZone(undefined);
                          }
                        }
                      );
                    }}
                    type="button"
                  >
                    Delete active zone
                  </button>
                ) : null}
              </div>
              {createZone.error || updateZone.error || deleteZone.error ? (
                <p className="text-sm text-rose-200">
                  {createZone.error?.message ?? updateZone.error?.message ?? deleteZone.error?.message}
                </p>
              ) : null}
            </form>
          </Panel>

          <Panel title="Zone Renderer" eyebrow="BIND-Compatible">
            <pre className="overflow-x-auto rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
              {zoneRender.data?.text ?? "Select a zone to render"}
            </pre>
          </Panel>

          <Panel title={editingRecordIndex === null ? "Add Record" : "Edit Record"} eyebrow="Typed Record Builder">
            <form
              className="grid gap-4"
              onSubmit={(event) => {
                event.preventDefault();
                if (!activeZone) {
                  return;
                }

                const error = validateDnsRecord(recordForm);
                if (error) {
                  setRecordError(error);
                  return;
                }

                const payload = buildRecordPayload(recordForm);
                if (editingRecordIndex === null) {
                  createRecord.mutate({ zoneName: activeZone.name, record: payload });
                  return;
                }

                updateRecord.mutate(
                  { zoneName: activeZone.name, index: editingRecordIndex, record: payload },
                  {
                    onSuccess: () => {
                      setEditingRecordIndex(null);
                    }
                  }
                );
              }}
            >
              <label className="grid gap-2">
                <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Record type</span>
                <select
                  className="field rounded-2xl px-4 py-3 outline-none"
                  onChange={(event) => setRecordType(event.target.value)}
                  value={recordForm.type}
                >
                  {DNS_RECORD_TYPES.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label} - {option.description}
                    </option>
                  ))}
                </select>
                <span className="text-xs text-slate-500">{recordConfig.hint}</span>
              </label>

              <div className="grid gap-3 md:grid-cols-[1fr_0.65fr]">
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Name</span>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => {
                      setRecordError(null);
                      setRecordForm((current) => ({ ...current, name: event.target.value }));
                    }}
                    placeholder={recordConfig.namePlaceholder}
                    value={recordForm.name}
                  />
                </label>
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Class</span>
                  <select
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => {
                      setRecordError(null);
                      setRecordForm((current) => ({ ...current, class: event.target.value }));
                    }}
                    value={recordForm.class}
                  >
                    {DNS_CLASSES.map((dnsClass) => (
                      <option key={dnsClass}>{dnsClass}</option>
                    ))}
                  </select>
                </label>
              </div>

              <div className="grid gap-3 md:grid-cols-[1fr_0.65fr]">
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">{recordConfig.valueLabel}</span>
                  <input
                    className="field rounded-2xl px-4 py-3 font-mono text-sm outline-none"
                    onChange={(event) => {
                      setRecordError(null);
                      setRecordForm((current) => ({ ...current, value: event.target.value }));
                    }}
                    placeholder={recordConfig.valuePlaceholder}
                    value={recordForm.value}
                  />
                  <span className="text-xs text-slate-500">{recordConfig.valueHelp}</span>
                </label>
                <label className="grid gap-2">
                  <span className="text-xs uppercase tracking-[0.18em] text-slate-500">TTL</span>
                  <select
                    className="field rounded-2xl px-4 py-3 outline-none"
                    onChange={(event) => {
                      setRecordError(null);
                      setRecordForm((current) => ({ ...current, ttl: Number(event.target.value) }));
                    }}
                    value={recordForm.ttl}
                  >
                    {TTL_PRESETS.map((ttl) => (
                      <option key={ttl.value} value={ttl.value}>
                        {ttl.label} ({ttl.value}s)
                      </option>
                    ))}
                    {!TTL_PRESETS.some((ttl) => ttl.value === recordForm.ttl) ? (
                      <option value={recordForm.ttl}>Custom ({recordForm.ttl}s)</option>
                    ) : null}
                  </select>
                  <input
                    className="field rounded-2xl px-4 py-3 outline-none"
                    min={1}
                    onChange={(event) => {
                      setRecordError(null);
                      setRecordForm((current) => ({ ...current, ttl: Number(event.target.value) }));
                    }}
                    type="number"
                    value={recordForm.ttl}
                  />
                </label>
              </div>

              {recordConfig.showPriority || recordConfig.showWeight || recordConfig.showPort || recordConfig.showFlags ? (
                <div className="grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4 md:grid-cols-2">
                  {recordConfig.showPriority ? (
                    <label className="grid gap-2">
                      <span className="text-xs uppercase tracking-[0.18em] text-slate-500">{recordConfig.priorityLabel ?? "Priority"}</span>
                      <input
                        className="field rounded-2xl px-4 py-3 outline-none"
                        min={0}
                        onChange={(event) => {
                          setRecordError(null);
                          setRecordForm((current) => ({ ...current, priority: Number(event.target.value) }));
                        }}
                        type="number"
                        value={recordForm.priority}
                      />
                    </label>
                  ) : null}
                  {recordConfig.showWeight ? (
                    <label className="grid gap-2">
                      <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Weight</span>
                      <input
                        className="field rounded-2xl px-4 py-3 outline-none"
                        min={0}
                        onChange={(event) => {
                          setRecordError(null);
                          setRecordForm((current) => ({ ...current, weight: Number(event.target.value) }));
                        }}
                        type="number"
                        value={recordForm.weight}
                      />
                    </label>
                  ) : null}
                  {recordConfig.showPort ? (
                    <label className="grid gap-2">
                      <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Port</span>
                      <input
                        className="field rounded-2xl px-4 py-3 outline-none"
                        max={65535}
                        min={1}
                        onChange={(event) => {
                          setRecordError(null);
                          setRecordForm((current) => ({ ...current, port: Number(event.target.value) }));
                        }}
                        type="number"
                        value={recordForm.port}
                      />
                    </label>
                  ) : null}
                  {recordConfig.showFlags ? (
                    <label className="grid gap-2">
                      <span className="text-xs uppercase tracking-[0.18em] text-slate-500">{recordConfig.flagsLabel ?? "Flags"}</span>
                      <input
                        className="field rounded-2xl px-4 py-3 outline-none"
                        onChange={(event) => {
                          setRecordError(null);
                          setRecordForm((current) => ({ ...current, flags: event.target.value }));
                        }}
                        placeholder={recordConfig.flagsPlaceholder}
                        value={recordForm.flags}
                      />
                    </label>
                  ) : null}
                </div>
              ) : null}

              <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Preview</p>
                <p className="mt-2 break-all font-mono text-sm text-slate-700">{renderRecordPreview(recordForm)}</p>
              </div>

              <div className="flex flex-wrap gap-3 pt-1">
                <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" type="submit">
                  {editingRecordIndex === null ? "Publish record" : "Save record"}
                </button>
                {editingRecordIndex !== null ? (
                  <button
                    className="rounded-2xl border border-slate-200 px-4 py-3 font-medium text-slate-600 transition hover:bg-slate-50"
                    onClick={() => {
                      setEditingRecordIndex(null);
                      setRecordForm(defaultRecordForm());
                    }}
                    type="button"
                  >
                    Cancel edit
                  </button>
                ) : null}
              </div>
              {createRecord.error || updateRecord.error || deleteRecord.error ? (
                <p className="text-sm text-rose-200">
                  {createRecord.error?.message ?? updateRecord.error?.message ?? deleteRecord.error?.message}
                </p>
              ) : null}
              {recordError ? <p className="text-sm text-amber-200">{recordError}</p> : null}
            </form>
          </Panel>
        </div>
      </div>
    </div>
  );
}
