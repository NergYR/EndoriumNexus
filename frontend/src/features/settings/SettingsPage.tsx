import { useEffect, useMemo, useState } from "react";

import { Panel } from "../../components/Panel";
import { ServiceBadge } from "../../components/ServiceBadge";
import { StatCard } from "../../components/StatCard";
import { useDashboard, useFeatureFlags, useSettings, useUpdateFeatureFlags, useUpdateSettings } from "../../lib/api";

type SettingsForm = {
  environment: string;
  domain: string;
  blobRoot: string;
  stateRoot: string;
  databaseUrl: string;
  adminEmail: string;
  adminPasswordHash: string;
  adminTotpSecret: string;
  httpPort: number;
  ldapPort: number;
  ldapsPort: number;
  kerberosPort: number;
  dnsTcpPort: number;
  dnsUdpPort: number;
  dhcpPort: number;
  directory: {
    baseDn: string;
    organization: string;
    realm: string;
  };
  dns: {
    primaryNs: string;
    adminMailbox: string;
    defaultTtl: number;
  };
  dhcp: {
    subnet: string;
    rangeStart: string;
    rangeEnd: string;
    router: string;
  };
  pki: {
    organization: string;
    commonName: string;
    leafDaysValid: number;
  };
  repo: {
    origin: string;
    distribution: string;
    component: string;
  };
};

type PortField =
  | "httpPort"
  | "ldapPort"
  | "ldapsPort"
  | "kerberosPort"
  | "dnsTcpPort"
  | "dnsUdpPort"
  | "dhcpPort";

export function SettingsPage() {
  const dashboard = useDashboard();
  const settings = useSettings();
  const featureFlags = useFeatureFlags();
  const updateFeatureFlags = useUpdateFeatureFlags();
  const updateSettings = useUpdateSettings();
  const [form, setForm] = useState<SettingsForm>({
    environment: "development",
    domain: "endorium.local",
    blobRoot: "var/blob",
    stateRoot: "var/state",
    databaseUrl: "",
    adminEmail: "admin@endorium.local",
    adminPasswordHash: "",
    adminTotpSecret: "",
    httpPort: 8080,
    ldapPort: 8389,
    ldapsPort: 8636,
    kerberosPort: 8088,
    dnsTcpPort: 8053,
    dnsUdpPort: 8053,
    dhcpPort: 8067,
    directory: {
      baseDn: "dc=endorium,dc=local",
      organization: "Endorium",
      realm: "ENDORIUM.LOCAL"
    },
    dns: {
      primaryNs: "ns1.endorium.local",
      adminMailbox: "hostmaster.endorium.local",
      defaultTtl: 3600
    },
    dhcp: {
      subnet: "10.10.10.0/24",
      rangeStart: "10.10.10.100",
      rangeEnd: "10.10.10.200",
      router: "10.10.10.1"
    },
    pki: {
      organization: "Endorium",
      commonName: "Endorium Root CA",
      leafDaysValid: 365
    },
    repo: {
      origin: "Endorium",
      distribution: "bookworm",
      component: "main"
    }
  });

  useEffect(() => {
    if (!settings.data) {
      return;
    }

    setForm({
      environment: settings.data.environment,
      domain: settings.data.domain,
      blobRoot: settings.data.blobRoot,
      stateRoot: settings.data.stateRoot,
      databaseUrl: settings.data.databaseUrl,
      adminEmail: settings.data.adminEmail,
      adminPasswordHash: settings.data.adminPasswordHash,
      adminTotpSecret: settings.data.adminTotpSecret,
      httpPort: settings.data.ports.http,
      ldapPort: settings.data.ports.ldap,
      ldapsPort: settings.data.ports.ldaps,
      kerberosPort: settings.data.ports.kerberos,
      dnsTcpPort: settings.data.ports.dnsTcp,
      dnsUdpPort: settings.data.ports.dnsUdp,
      dhcpPort: settings.data.ports.dhcp,
      directory: settings.data.directory,
      dns: settings.data.dns,
      dhcp: settings.data.dhcp,
      pki: settings.data.pki,
      repo: settings.data.repo
    });
  }, [settings.data]);

  const serviceStates = useMemo(() => dashboard.data?.services.map((service) => service.state) ?? [], [dashboard.data]);
  const featureFlagMap = useMemo(
    () => new Map((featureFlags.data ?? []).map((entry) => [entry.featureFlag, entry.enabled])),
    [featureFlags.data]
  );
  const [featureDraft, setFeatureDraft] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!featureFlags.data) {
      return;
    }

    setFeatureDraft(
      featureFlags.data.reduce<Record<string, boolean>>((accumulator, entry) => {
        accumulator[entry.featureFlag] = entry.enabled;
        return accumulator;
      }, {})
    );
  }, [featureFlags.data]);

  if (settings.isLoading || !settings.data || dashboard.isLoading || !dashboard.data || featureFlags.isLoading || !featureFlags.data) {
    return <div className="text-sm text-slate-500">Chargement des réglages...</div>;
  }

  const healthyServices = serviceStates.filter((state) => state === "healthy").length;
  const disabledServices = serviceStates.filter((state) => state === "disabled").length;

  const portCards: Array<[PortField, string]> = [
    ["httpPort", "HTTP port"],
    ["ldapPort", "LDAP port"],
    ["ldapsPort", "LDAPS port"],
    ["kerberosPort", "Kerberos port"],
    ["dnsTcpPort", "DNS TCP port"],
    ["dnsUdpPort", "DNS UDP port"],
    ["dhcpPort", "DHCP port"]
  ];

  const canEnableService = (serviceId: string) => {
    if (serviceId === "api") {
      return true;
    }

    if (serviceId === "directory") {
      return Boolean(form.directory.baseDn && form.directory.organization && form.directory.realm);
    }

    if (serviceId === "network") {
      return Boolean(form.dns.primaryNs && form.dns.adminMailbox && form.dhcp.subnet && form.dhcp.rangeStart && form.dhcp.rangeEnd && form.dhcp.router);
    }

    if (serviceId === "pki-repo") {
      return Boolean(
        form.pki.organization &&
          form.pki.commonName &&
          form.repo.origin &&
          form.repo.distribution &&
          form.repo.component
      );
    }

    return false;
  };

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Healthy Services" value={healthyServices} />
        <StatCard label="Disabled Services" value={disabledServices} />
        <StatCard label="DB Connected" value={settings.data.databaseConfigured ? "Yes" : "No"} />
        <StatCard label="Environment" value={settings.data.environment} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <Panel title="Runtime Snapshot" eyebrow="Monitoring">
          <div className="grid gap-3 md:grid-cols-2">
            {dashboard.data.services.map((service) => (
              <article className="rounded-2xl border border-slate-200 bg-white px-4 py-4" key={service.id}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-medium text-slate-900">{service.label}</p>
                    <p className="mt-1 text-sm text-slate-600">{service.summary}</p>
                    {service.blockingReason && <p className="mt-2 text-xs text-amber-700">{service.blockingReason}</p>}
                  </div>
                  <ServiceBadge state={service.state} />
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {service.endpoints.map((endpoint) => (
                    <span
                      className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs uppercase tracking-[0.16em] text-slate-600"
                      key={endpoint}
                    >
                      {endpoint}
                    </span>
                  ))}
                </div>
              </article>
            ))}
          </div>
        </Panel>

        <Panel title="Aperçu rapide" eyebrow="Live Diagnostics">
          <div className="space-y-3 text-sm text-slate-600">
            <p>
              Domaine: <span className="text-slate-900">{settings.data.domain}</span>
            </p>
            <p>
              Email admin: <span className="text-slate-900">{settings.data.adminEmail}</span>
            </p>
            <p>
              Base de données: <span className="text-slate-900">{settings.data.databaseConfigured ? "connectée" : "désactivée"}</span>
            </p>
            <p>
              Blob root: <span className="text-slate-900">{settings.data.blobRoot}</span>
            </p>
            <p>
              State root: <span className="text-slate-900">{settings.data.stateRoot}</span>
            </p>
          </div>
          <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Cette vue remplace l'ancien console de debug pour garder seulement les informations utiles.
          </div>
        </Panel>
      </div>

      <Panel title="Platform Configurator" eyebrow="Editable Runtime Settings">
        <form
          className="grid gap-5"
          onSubmit={(event) => {
            event.preventDefault();
            updateSettings.mutate(form);
          }}
        >
          <div className="grid gap-4 md:grid-cols-2">
            <label className="grid gap-2">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Environment</span>
              <input
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, environment: event.target.value }))}
                value={form.environment}
              />
            </label>
            <label className="grid gap-2">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Domain</span>
              <input
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, domain: event.target.value }))}
                value={form.domain}
              />
            </label>
            <label className="grid gap-2">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Admin email</span>
              <input
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, adminEmail: event.target.value }))}
                value={form.adminEmail}
              />
            </label>
            <label className="grid gap-2">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Database URL</span>
              <input
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, databaseUrl: event.target.value }))}
                value={form.databaseUrl}
              />
            </label>
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            <label className="grid gap-2">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Blob root</span>
              <input
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, blobRoot: event.target.value }))}
                value={form.blobRoot}
              />
            </label>
            <label className="grid gap-2">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">State root</span>
              <input
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, stateRoot: event.target.value }))}
                value={form.stateRoot}
              />
            </label>
            <label className="grid gap-2">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">TOTP secret</span>
              <input
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, adminTotpSecret: event.target.value }))}
                value={form.adminTotpSecret}
              />
            </label>
          </div>

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {portCards.map(([field, label]) => (
              <label className="grid gap-2" key={field}>
                <span className="text-xs uppercase tracking-[0.18em] text-slate-500">{label}</span>
                <input
                  className="field rounded-2xl px-4 py-3 outline-none"
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      [field]: Number(event.target.value)
                    }))
                  }
                  type="number"
                  value={form[field]}
                />
              </label>
            ))}
            <label className="grid gap-2">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Admin password hash</span>
              <input
                className="field rounded-2xl px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, adminPasswordHash: event.target.value }))}
                type="password"
                value={form.adminPasswordHash}
              />
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              className="accent-gradient rounded-2xl px-5 py-3 font-medium text-white disabled:cursor-not-allowed disabled:opacity-60"
              disabled={updateSettings.isPending}
              type="submit"
            >
              {updateSettings.isPending ? "Applying..." : "Apply configuration"}
            </button>
            {updateSettings.error ? <p className="text-sm text-rose-700">{updateSettings.error.message}</p> : null}
            {updateSettings.isSuccess ? <p className="text-sm text-emerald-700">Configuration saved.</p> : null}
          </div>
        </form>
      </Panel>

      <Panel title="Module Flags" eyebrow="Module Control">
        <div className="space-y-3">
          <p className="text-sm text-slate-600">
            Activez uniquement les modules réellement prêts à être utilisés.
          </p>
          <div className="grid gap-3">
            {featureFlags.data.map((entry) => {
              const ready = canEnableService(entry.serviceId);
              const enabled = featureDraft[entry.featureFlag] ?? featureFlagMap.get(entry.featureFlag) ?? entry.enabled;

              const statusText =
                entry.serviceId === "api"
                  ? "Toujours actif"
                  : ready
                    ? `Priorité ${entry.priority}`
                    : dashboard.data.services.find((service) => service.id === entry.serviceId)?.blockingReason ||
                      "Configuration incomplète";

              return (
                <label className="rounded-2xl border border-slate-200 bg-white px-4 py-3" key={entry.serviceId}>
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-medium text-slate-900">{entry.label}</p>
                      <p className="mt-1 text-xs text-slate-500">{statusText}</p>
                    </div>
                    <input
                      disabled={entry.serviceId === "api" || !ready}
                      type="checkbox"
                      checked={enabled}
                      onChange={(event) =>
                        setFeatureDraft((current) => ({
                          ...current,
                          [entry.featureFlag]: event.target.checked
                        }))
                      }
                    />
                  </div>
                </label>
              );
            })}
          </div>
          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              className="accent-gradient rounded-2xl px-5 py-3 font-medium text-white disabled:cursor-not-allowed disabled:opacity-60"
              disabled={updateFeatureFlags.isPending}
              type="button"
              onClick={() => updateFeatureFlags.mutate({ features: featureDraft })}
            >
              {updateFeatureFlags.isPending ? "Saving module flags..." : "Save module flags"}
            </button>
            {updateFeatureFlags.error ? <p className="text-sm text-rose-700">{updateFeatureFlags.error.message}</p> : null}
            {updateFeatureFlags.isSuccess ? <p className="text-sm text-emerald-700">Module flags saved.</p> : null}
          </div>
        </div>
      </Panel>


      <Panel title="Current Settings" eyebrow="Snapshot">
        <dl className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {[
            ["Environment", settings.data.environment],
            ["Domain", settings.data.domain],
            ["Database", settings.data.databaseConfigured ? "connected" : "disabled"],
            ["Admin email", settings.data.adminEmail],
            ["HTTP", settings.data.ports.http],
            ["LDAP", settings.data.ports.ldap],
            ["LDAPS", settings.data.ports.ldaps],
            ["Kerberos", settings.data.ports.kerberos]
          ].map(([label, value]) => (
            <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3" key={label}>
              <dt className="text-xs uppercase tracking-[0.18em] text-slate-500">{label}</dt>
              <dd className="mt-2 text-sm text-slate-900">{value}</dd>
            </div>
          ))}
        </dl>
      </Panel>
    </div>
  );
}

