import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { Panel } from "../../components/Panel";
import { AdvancedSection, Wizard, WizardSummary } from "../../components/Wizard";
import {
  useActiveDirectoryDomain,
  useCreateDhcpPool,
  useCreateActiveDirectoryDomain,
  useCreateDirectoryObject,
  useCreateDnsRecord,
  useCreateDnsZone,
  useCreatePkiAuthority,
  useCreatePkiCertificate,
  useCreateRepository,
  useCreateRepositoryPackage,
  useDashboard,
  useDhcpPools,
  useDirectoryObjects,
  useDnsZones,
  usePkiAuthorities,
  usePkiCertificates,
  useRepositories,
  useSettings
} from "../../lib/api";

const steps = [
  { id: "platform", title: "Platform", description: "Confirm the base domain and defaults." },
  { id: "directory", title: "Windows Domain", description: "Create the domain model and first administrator." },
  { id: "network", title: "Network", description: "Create DNS and DHCP basics." },
  { id: "trust", title: "Trust", description: "Create a CA and first certificate." },
  { id: "repo", title: "Repository", description: "Create an APT catalog and package." },
  { id: "review", title: "Review", description: "Apply the missing configuration." }
];

type SetupDraft = {
  domain: string;
  directoryBaseDn: string;
  netbiosName: string;
  domainControllerHost: string;
  domainControllerAddress: string;
  directoryOu: string;
  adminUid: string;
  adminName: string;
  adminMail: string;
  adminPassword: string;
  dnsZone: string;
  dnsHost: string;
  dnsAddress: string;
  dhcpPool: string;
  dhcpSubnet: string;
  dhcpStart: string;
  dhcpEnd: string;
  dhcpRouter: string;
  caName: string;
  caCommonName: string;
  certCommonName: string;
  repoDistribution: string;
  repoComponent: string;
  packageName: string;
  packageVersion: string;
};

function defaultDraft(): SetupDraft {
  return {
    domain: "endorium.local",
    directoryBaseDn: "dc=endorium,dc=local",
    netbiosName: "ENDORIUM",
    domainControllerHost: "dc1",
    domainControllerAddress: "10.10.10.10",
    directoryOu: "People",
    adminUid: "alice",
    adminName: "Alice Admin",
    adminMail: "alice@endorium.local",
    adminPassword: "ChangeMe-endorium-1",
    dnsZone: "endorium.local",
    dnsHost: "portal",
    dnsAddress: "10.10.10.20",
    dhcpPool: "office",
    dhcpSubnet: "10.10.10.0/24",
    dhcpStart: "10.10.10.100",
    dhcpEnd: "10.10.10.200",
    dhcpRouter: "10.10.10.1",
    caName: "root-ca",
    caCommonName: "Endorium Root CA",
    certCommonName: "portal.endorium.local",
    repoDistribution: "bookworm",
    repoComponent: "main",
    packageName: "endorium-agent",
    packageVersion: "0.1.0"
  };
}

export function SetupWizardPage() {
  const dashboard = useDashboard();
  const settings = useSettings();
  const adDomain = useActiveDirectoryDomain();
  const directory = useDirectoryObjects();
  const dnsZones = useDnsZones();
  const dhcpPools = useDhcpPools();
  const authorities = usePkiAuthorities();
  const certificates = usePkiCertificates();
  const repositories = useRepositories();
  const createDirectoryObject = useCreateDirectoryObject();
  const createDomain = useCreateActiveDirectoryDomain();
  const createDnsZone = useCreateDnsZone();
  const createDnsRecord = useCreateDnsRecord();
  const createDhcpPool = useCreateDhcpPool();
  const createAuthority = useCreatePkiAuthority();
  const createCertificate = useCreatePkiCertificate();
  const createRepository = useCreateRepository();
  const createPackage = useCreateRepositoryPackage();
  const [draft, setDraft] = useState<SetupDraft>(() => defaultDraft());
  const [step, setStep] = useState(0);
  const [result, setResult] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const readiness = useMemo(() => {
    const services = dashboard.data?.services ?? [];
    return [
      { label: "Platform services", done: services.length > 0 && services.every((service) => !service.blockingReason) },
      { label: "Windows domain", done: Boolean(adDomain.data) },
      { label: "DNS zone", done: Boolean(dnsZones.data?.length) },
      { label: "DHCP pool", done: Boolean(dhcpPools.data?.length) },
      { label: "PKI authority", done: Boolean(authorities.data?.length) },
      { label: "APT repository", done: Boolean(repositories.data?.length && repositories.data.some((repo) => repo.packages.length > 0)) }
    ];
  }, [adDomain.data, authorities.data, dashboard.data, dhcpPools.data, dnsZones.data, repositories.data]);

  const isLoading = dashboard.isLoading || settings.isLoading || adDomain.isLoading || directory.isLoading || dnsZones.isLoading || dhcpPools.isLoading || authorities.isLoading || certificates.isLoading || repositories.isLoading;
  const updateDraft = (patch: Partial<SetupDraft>) => setDraft((current) => ({ ...current, ...patch }));

  const applySetup = async () => {
    setError(null);
    setResult([]);
    const messages: string[] = [];
    try {
      const parentDn = `ou=${draft.directoryOu},${draft.directoryBaseDn}`;
      if (!adDomain.data) {
        await createDomain.mutateAsync({
          dnsName: draft.domain,
          netbiosName: draft.netbiosName,
          baseDn: draft.directoryBaseDn,
          adminSamAccount: draft.adminUid,
          adminDisplayName: draft.adminName,
          adminPassword: draft.adminPassword,
          domainControllerHost: draft.domainControllerHost,
          domainControllerAddress: draft.domainControllerAddress
        });
        messages.push("Windows domain model created");
      }
      if (!directory.data?.some((entry) => entry.dn === parentDn)) {
        await createDirectoryObject.mutateAsync({
          dn: parentDn,
          parentDn: draft.directoryBaseDn,
          kind: "organizationalUnit",
          objectClasses: ["organizationalUnit"],
          attributes: { ou: draft.directoryOu, description: "Primary user container" }
        });
        messages.push("LDAP OU created");
      }
      const userDn = `uid=${draft.adminUid},${parentDn}`;
      if (!directory.data?.some((entry) => entry.dn === userDn)) {
        await createDirectoryObject.mutateAsync({
          dn: userDn,
          parentDn,
          kind: "user",
          objectClasses: ["inetOrgPerson", "organizationalPerson", "person"],
          attributes: { uid: draft.adminUid, cn: draft.adminName, sn: draft.adminName.split(" ").at(-1) ?? draft.adminName, mail: draft.adminMail },
          password: draft.adminPassword
        });
        messages.push("LDAP user created");
      }
      if (!dnsZones.data?.some((zone) => zone.name === draft.dnsZone)) {
        await createDnsZone.mutateAsync({ name: draft.dnsZone });
        messages.push("DNS zone created");
      }
      await createDnsRecord.mutateAsync({ zoneName: draft.dnsZone, record: { name: draft.dnsHost, type: "A", value: draft.dnsAddress, class: "IN", ttl: 300, priority: 0 } });
      messages.push("DNS host record published");
      if (!dhcpPools.data?.some((pool) => pool.name === draft.dhcpPool)) {
        await createDhcpPool.mutateAsync({
          name: draft.dhcpPool,
          subnet: draft.dhcpSubnet,
          rangeStart: draft.dhcpStart,
          rangeEnd: draft.dhcpEnd,
          options: { router: draft.dhcpRouter, dns: draft.dnsAddress, "domain-name": draft.domain, "lease-time": "86400" }
        });
        messages.push("DHCP pool created");
      }
      if (!authorities.data?.some((authority) => authority.name === draft.caName)) {
        await createAuthority.mutateAsync({ name: draft.caName, commonName: draft.caCommonName, organization: "Endorium", sans: [`ca.${draft.domain}`], daysValid: 3650 });
        messages.push("Root CA created");
      }
      if (!certificates.data?.some((certificate) => certificate.commonName === draft.certCommonName)) {
        await createCertificate.mutateAsync({ authorityName: draft.caName, commonName: draft.certCommonName, organization: "Endorium", sans: [draft.certCommonName], daysValid: 365 });
        messages.push("First certificate issued");
      }
      if (!repositories.data?.some((repo) => repo.distribution === draft.repoDistribution && repo.component === draft.repoComponent)) {
        await createRepository.mutateAsync({ distribution: draft.repoDistribution, component: draft.repoComponent });
        messages.push("APT repository created");
      }
      await createPackage.mutateAsync({
        distribution: draft.repoDistribution,
        component: draft.repoComponent,
        package: {
          name: draft.packageName,
          version: draft.packageVersion,
          architecture: "amd64",
          filename: `pool/main/${draft.packageName[0]}/${draft.packageName}_${draft.packageVersion}_amd64.deb`,
          sha256: "replace-with-real-sha256",
          size: 1
        }
      });
      messages.push("APT package metadata added");
      setResult(messages);
    } catch (caught) {
      setResult(messages);
      setError(caught instanceof Error ? caught.message : "Setup failed");
    }
  };

  if (isLoading || !settings.data) {
    return <div className="text-sm text-slate-500">Chargement de l'assistant de démarrage...</div>;
  }

  return (
    <div className="space-y-6">
      <Panel
        title="Setup Wizard"
        eyebrow="First configuration"
        actions={<Link className="rounded-full border border-slate-200 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50" to="/dashboard">Retour au tableau de bord</Link>}
      >
        <div className="grid gap-3 md:grid-cols-3">
          {readiness.map((item) => (
            <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3" key={item.label}>
              <p className="text-sm font-medium text-slate-900">{item.label}</p>
              <p className={["mt-1 text-xs uppercase tracking-[0.16em]", item.done ? "text-emerald-700" : "text-amber-700"].join(" ")}>
                {item.done ? "Configured" : "Needs setup"}
              </p>
            </div>
          ))}
        </div>
      </Panel>

      <Wizard
        title="Configure Endorium Nexus"
        steps={steps}
        currentStep={step}
        error={error}
        actions={
          <>
            <button className="rounded-2xl border border-slate-200 px-4 py-3 font-medium text-slate-600 disabled:opacity-50" disabled={step === 0} onClick={() => setStep((current) => Math.max(0, current - 1))} type="button">Back</button>
            {step < steps.length - 1 ? (
              <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-white" onClick={() => setStep((current) => Math.min(steps.length - 1, current + 1))} type="button">Next</button>
            ) : (
              <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-white" onClick={() => void applySetup()} type="button">Apply setup</button>
            )}
          </>
        }
      >
        {step === 0 ? (
          <div className="grid gap-3">
            <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-500">Business domain</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ domain: event.target.value, dnsZone: event.target.value, directoryBaseDn: event.target.value.split(".").filter(Boolean).map((part) => `dc=${part}`).join(","), netbiosName: event.target.value.split(".")[0]?.toUpperCase().slice(0, 15) ?? draft.netbiosName })} value={draft.domain} /></label>
            <WizardSummary items={[{ label: "Current environment", value: settings.data.environment }, { label: "Default state root", value: settings.data.stateRoot }]} />
          </div>
        ) : null}
        {step === 1 ? (
          <div className="grid gap-3">
            <div className="grid gap-3 md:grid-cols-2">
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-500">Base DN</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ directoryBaseDn: event.target.value })} value={draft.directoryBaseDn} /></label>
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-500">NetBIOS name</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ netbiosName: event.target.value.toUpperCase().slice(0, 15) })} value={draft.netbiosName} /></label>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-500">Admin UID</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ adminUid: event.target.value })} value={draft.adminUid} /></label>
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-500">Temporary password</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ adminPassword: event.target.value })} type="password" value={draft.adminPassword} /></label>
            </div>
            <AdvancedSection><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ adminName: event.target.value })} value={draft.adminName} /><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ adminMail: event.target.value })} value={draft.adminMail} /><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ domainControllerHost: event.target.value })} value={draft.domainControllerHost} /><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ domainControllerAddress: event.target.value })} value={draft.domainControllerAddress} /></AdvancedSection>
          </div>
        ) : null}
        {step === 2 ? (
          <div className="grid gap-3">
            <div className="grid gap-3 md:grid-cols-3">
              <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ dnsZone: event.target.value })} value={draft.dnsZone} />
              <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ dnsHost: event.target.value })} value={draft.dnsHost} />
              <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ dnsAddress: event.target.value })} value={draft.dnsAddress} />
            </div>
            <AdvancedSection title="DHCP scope"><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ dhcpPool: event.target.value })} value={draft.dhcpPool} /><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ dhcpSubnet: event.target.value })} value={draft.dhcpSubnet} /><div className="grid gap-3 md:grid-cols-3"><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ dhcpStart: event.target.value })} value={draft.dhcpStart} /><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ dhcpEnd: event.target.value })} value={draft.dhcpEnd} /><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ dhcpRouter: event.target.value })} value={draft.dhcpRouter} /></div></AdvancedSection>
          </div>
        ) : null}
        {step === 3 ? (
          <div className="grid gap-3 md:grid-cols-2">
            <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ caName: event.target.value })} value={draft.caName} />
            <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ caCommonName: event.target.value })} value={draft.caCommonName} />
            <input className="field rounded-2xl px-4 py-3 outline-none md:col-span-2" onChange={(event) => updateDraft({ certCommonName: event.target.value })} value={draft.certCommonName} />
          </div>
        ) : null}
        {step === 4 ? (
          <div className="grid gap-3 md:grid-cols-2">
            <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ repoDistribution: event.target.value })} value={draft.repoDistribution} />
            <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ repoComponent: event.target.value })} value={draft.repoComponent} />
            <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ packageName: event.target.value })} value={draft.packageName} />
            <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateDraft({ packageVersion: event.target.value })} value={draft.packageVersion} />
          </div>
        ) : null}
        {step === 5 ? (
          <div className="grid gap-4">
            <WizardSummary items={[{ label: "LDAP", value: `${draft.adminUid} in ou=${draft.directoryOu}` }, { label: "DNS/DHCP", value: `${draft.dnsHost}.${draft.dnsZone} -> ${draft.dnsAddress}, pool ${draft.dhcpPool}` }, { label: "PKI", value: `${draft.caName}, certificate ${draft.certCommonName}` }, { label: "APT", value: `${draft.repoDistribution}/${draft.repoComponent}, ${draft.packageName} ${draft.packageVersion}` }]} />
            {result.length ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{result.map((line) => <p key={line}>{line}</p>)}</div> : null}
          </div>
        ) : null}
      </Wizard>
    </div>
  );
}
