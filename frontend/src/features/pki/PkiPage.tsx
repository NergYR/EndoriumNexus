import { useEffect, useMemo, useRef, useState } from "react";

import { Panel } from "../../components/Panel";
import { AdvancedSection, Wizard, WizardSummary } from "../../components/Wizard";
import {
  useCreatePkiAuthority,
  useCreatePkiCertificate,
  useCreateRevocation,
  usePkiAssistant,
  usePkiAuthorities,
  usePkiCertificates,
  useRevocations
} from "../../lib/api";

type WizardMode = "authority" | "certificate" | "revocation";

type PkiProfile = {
  id: string;
  label: string;
  description: string;
  mode: WizardMode;
  summary: string;
  risk: string;
  recommendation: string;
  authority?: {
    name: string;
    commonName: string;
    organization: string;
    sans: string;
    daysValid: number;
  };
  certificate?: {
    commonName: string;
    organization: string;
    sans: string;
    daysValid: number;
  };
  revocation?: {
    serial: string;
    commonName: string;
    reason: string;
  };
};

const REVOCATION_REASONS = [
  "keyCompromise",
  "cACompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "certificateHold",
  "removeFromCRL"
] as const;

const PKI_PROFILES: PkiProfile[] = [
  {
    id: "offline-root",
    label: "Offline root CA",
    description: "Create the trust anchor first, with a long lifetime and explicit naming.",
    mode: "authority",
    summary: "Best for a new PKI that needs a clean trust root.",
    risk: "Do not expose the root CA for routine issuance.",
    recommendation: "Keep the root offline and issue leaf certificates from intermediates later.",
    authority: {
      name: "root-ca",
      commonName: "Endorium Root CA",
      organization: "Endorium",
      sans: "ca.endorium.local",
      daysValid: 3650
    }
  },
  {
    id: "service-mtls",
    label: "Service mTLS",
    description: "Issue a short-lived certificate for an internal API or platform service.",
    mode: "certificate",
    summary: "Best for mutual TLS and service-to-service trust.",
    risk: "SANs must match the service DNS names exactly.",
    recommendation: "Use the currently selected CA and keep the validity close to the service rotation policy.",
    certificate: {
      commonName: "api.endorium.local",
      organization: "Endorium",
      sans: "api.endorium.local,api.internal.endorium.local",
      daysValid: 365
    }
  },
  {
    id: "vpn-edge",
    label: "VPN edge",
    description: "Prepare a certificate for an access gateway or remote connectivity endpoint.",
    mode: "certificate",
    summary: "Best for gateways that terminate TLS for users or sites.",
    risk: "The endpoint name should be stable before issuance.",
    recommendation: "Use the public-facing service name as the common name and list every alternate DNS entry.",
    certificate: {
      commonName: "vpn-edge.endorium.local",
      organization: "Endorium",
      sans: "vpn-edge.endorium.local,vpn.endorium.local",
      daysValid: 365
    }
  },
  {
    id: "incident-response",
    label: "Incident revocation",
    description: "Pre-fill a revocation flow when a key is suspected compromised.",
    mode: "revocation",
    summary: "Best for emergency response and clean certificate retirement.",
    risk: "Revocation is final for the target certificate.",
    recommendation: "Use the serial from the certificate inventory and explain the reason in operator language.",
    revocation: {
      serial: "",
      commonName: "",
      reason: "cessationOfOperation"
    }
  }
];

function splitSans(value: string) {
  return value.split(",").map((entry) => entry.trim()).filter(Boolean);
}

function splitProfileSans(value: string) {
  return splitSans(value).join(", ");
}

const AUTHORITY_STEPS = [
  { id: "purpose", title: "Purpose", description: "Name the authority for operators." },
  { id: "identity", title: "Identity", description: "Choose certificate subject details." },
  { id: "advanced", title: "Advanced", description: "Set SANs and lifetime." },
  { id: "review", title: "Review", description: "Create the root CA." }
];

const CERTIFICATE_STEPS = [
  { id: "authority", title: "Authority", description: "Select the CA that signs this certificate." },
  { id: "subject", title: "Subject", description: "Set the service name users know." },
  { id: "advanced", title: "Advanced", description: "Set SANs and validity." },
  { id: "review", title: "Review", description: "Issue the certificate." }
];

const REVOCATION_STEPS = [
  { id: "certificate", title: "Certificate", description: "Pick or enter the serial." },
  { id: "reason", title: "Reason", description: "Choose why it is revoked." },
  { id: "review", title: "Review", description: "Publish the revocation." }
];

export function PkiPage() {
  const assistant = usePkiAssistant();
  const authorities = usePkiAuthorities();
  const certificates = usePkiCertificates();
  const revocations = useRevocations();
  const createAuthority = useCreatePkiAuthority();
  const createCertificate = useCreatePkiCertificate();
  const createRevocation = useCreateRevocation();
  const [selectedAuthority, setSelectedAuthority] = useState("");
  const [authorityForm, setAuthorityForm] = useState({
    name: "root-ca",
    commonName: "Endorium Root CA",
    organization: "Endorium",
    sans: "ca.endorium.local",
    daysValid: 3650
  });
  const [certificateForm, setCertificateForm] = useState({
    authorityName: "",
    commonName: "vpn-edge.endorium.local",
    organization: "Endorium",
    sans: "vpn-edge.endorium.local",
    daysValid: 365
  });
  const [revocationForm, setRevocationForm] = useState({
    serial: "",
    commonName: "",
    reason: "cessationOfOperation"
  });
  const [wizardMode, setWizardMode] = useState<WizardMode>("authority");
  const [wizardStep, setWizardStep] = useState(0);
  const [selectedProfileId, setSelectedProfileId] = useState(PKI_PROFILES[0].id);
  const appliedAssistantProfileId = useRef<string | null>(null);

  const activeAuthority = useMemo(() => {
    if (!authorities.data?.length) {
      return undefined;
    }
    return authorities.data.find((authority) => authority.name === selectedAuthority) ?? authorities.data[0];
  }, [authorities.data, selectedAuthority]);

  const activeCertificates = useMemo(() => {
    if (!certificates.data || !activeAuthority) {
      return certificates.data ?? [];
    }
    return certificates.data.filter((certificate) => certificate.authorityName === activeAuthority.name);
  }, [activeAuthority, certificates.data]);

  const activeProfile = useMemo(() => PKI_PROFILES.find((profile) => profile.id === selectedProfileId) ?? PKI_PROFILES[0], [selectedProfileId]);

  useEffect(() => {
    const recommendedProfileId = assistant.data?.recommendedProfileId;
    if (!recommendedProfileId || appliedAssistantProfileId.current === recommendedProfileId) {
      return;
    }

    const recommendedProfile = PKI_PROFILES.find((profile) => profile.id === recommendedProfileId) ?? PKI_PROFILES[0];
    appliedAssistantProfileId.current = recommendedProfile.id;
    setSelectedProfileId(recommendedProfile.id);
    setWizardMode(recommendedProfile.mode);
    setWizardStep(0);

    if (recommendedProfile.authority) {
      setAuthorityForm(recommendedProfile.authority);
    }

    if (recommendedProfile.certificate) {
      const preferredAuthority = authorities.data?.[0]?.name ?? certificateForm.authorityName ?? "root-ca";
      setCertificateForm({
        authorityName: preferredAuthority,
        commonName: recommendedProfile.certificate.commonName,
        organization: recommendedProfile.certificate.organization,
        sans: recommendedProfile.certificate.sans,
        daysValid: recommendedProfile.certificate.daysValid
      });
      setSelectedAuthority(preferredAuthority);
    }

    if (recommendedProfile.revocation) {
      setRevocationForm(recommendedProfile.revocation);
    }
  }, [assistant.data?.recommendedProfileId, authorities.data, certificateForm.authorityName]);

  const pkiGuidance = useMemo(() => {
    if (assistant.data?.insights.length) {
      return assistant.data.insights.map((insight) => ({
        label: insight.title,
        value: insight.detail
      }));
    }

    const authorityCount = authorities.data?.length ?? 0;
    const certificateCount = certificates.data?.length ?? 0;
    const revocationCount = revocations.data?.length ?? 0;

    if (!authorityCount) {
      return [
        { label: "Next move", value: "Create the first root CA" },
        { label: "Why now", value: "A PKI cannot issue leaf material without a trust anchor." },
        { label: "Operating rule", value: "Keep the root offline after bootstrap." }
      ];
    }

    if (!certificateCount) {
      return [
        { label: "Next move", value: "Issue the first service certificate" },
        { label: "Why now", value: "The PKI is ready for an actual workload identity." },
        { label: "Operating rule", value: "Match SANs to service DNS names exactly." }
      ];
    }

    if (!revocationCount) {
      return [
        { label: "Next move", value: "Define the revocation playbook" },
        { label: "Why now", value: "Operational PKI needs a clean retirement path." },
        { label: "Operating rule", value: "Track the serial in your incident response notes." }
      ];
    }

    return [
      { label: "Next move", value: "Tune rotation and renewal policy" },
      { label: "Why now", value: "The main PKI lifecycle is already in motion." },
      { label: "Operating rule", value: "Prefer shorter-lived leaf certificates over long-lived ones." }
    ];
  }, [assistant.data?.insights, authorities.data?.length, certificates.data?.length, revocations.data?.length]);

  if (assistant.isLoading || authorities.isLoading || certificates.isLoading || revocations.isLoading || !authorities.data || !certificates.data || !revocations.data || !assistant.data) {
    return <div className="text-sm text-slate-400">Chargement de la PKI...</div>;
  }

  const authorityName = activeAuthority?.name ?? certificateForm.authorityName;
  const activeSteps = wizardMode === "authority" ? AUTHORITY_STEPS : wizardMode === "certificate" ? CERTIFICATE_STEPS : REVOCATION_STEPS;
  const wizardError = createAuthority.error?.message ?? createCertificate.error?.message ?? createRevocation.error?.message;

  const applyProfile = (profile: PkiProfile) => {
    setSelectedProfileId(profile.id);
    setWizardMode(profile.mode);
    setWizardStep(0);

    if (profile.authority) {
      setAuthorityForm(profile.authority);
    }

    if (profile.certificate) {
      const preferredAuthority = activeAuthority?.name ?? certificateForm.authorityName ?? authorities.data[0]?.name ?? "root-ca";
      setCertificateForm({
        authorityName: preferredAuthority,
        commonName: profile.certificate.commonName,
        organization: profile.certificate.organization,
        sans: profile.certificate.sans,
        daysValid: profile.certificate.daysValid
      });
      setSelectedAuthority(preferredAuthority);
    }

    if (profile.revocation) {
      setRevocationForm(profile.revocation);
    }
  };

  const runWizard = () => {
    if (wizardMode === "authority") {
      createAuthority.mutate({ ...authorityForm, sans: splitSans(authorityForm.sans) });
      return;
    }
    if (wizardMode === "certificate") {
      createCertificate.mutate({ ...certificateForm, authorityName: certificateForm.authorityName || authorityName, sans: splitSans(certificateForm.sans) });
      return;
    }
    createRevocation.mutate(revocationForm);
  };

  return (
    <div className="grid gap-6 xl:grid-cols-[1fr_0.95fr]">
      <div className="space-y-6">
        <Panel title="PKI Guidance" eyebrow="Assistant mode">
          <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
            <div className="space-y-4">
              <div>
                <p className="text-sm text-slate-200">{assistant.data.headline}</p>
                <p className="mt-2 text-sm text-slate-400">Choisissez un profil et laissez l'assistant préremplir le chemin le plus utile.</p>
              </div>
              <div className="grid gap-2 md:grid-cols-2">
                {PKI_PROFILES.map((profile) => (
                  <button
                    className={[
                      "rounded-2xl border px-4 py-3 text-left transition",
                      selectedProfileId === profile.id ? "border-cyan-400/30 bg-cyan-400/10" : "border-slate-700/70 bg-slate-900/50 hover:border-slate-600/70"
                    ].join(" ")}
                    key={profile.id}
                    onClick={() => applyProfile(profile)}
                    type="button"
                  >
                    <p className="font-semibold text-slate-50">{profile.label}</p>
                    <p className="mt-1 text-sm text-slate-300">{profile.description}</p>
                  </button>
                ))}
              </div>
            </div>

            <WizardSummary
              items={[
                { label: "Recommended path", value: activeProfile.summary },
                { label: "Risk to watch", value: activeProfile.risk },
                { label: "Operator hint", value: activeProfile.recommendation },
                { label: "Backend mode", value: assistant.data.recommendedMode }
              ]}
            />
          </div>
        </Panel>

        <Panel title="Certificate Authorities" eyebrow="Trust Roots">
          <div className="grid gap-3">
            {authorities.data.length ? authorities.data.map((authority) => (
              <button
                className={[
                  "rounded-3xl border p-4 text-left transition",
                  activeAuthority?.name === authority.name ? "border-cyan-400/30 bg-cyan-400/10" : "border-slate-700/70 bg-slate-900/50 hover:border-slate-600/70"
                ].join(" ")}
                key={authority.name}
                onClick={() => {
                  setSelectedAuthority(authority.name);
                  setCertificateForm((current) => ({ ...current, authorityName: authority.name }));
                }}
                type="button"
              >
                <p className="font-semibold text-slate-50">{authority.name}</p>
                <p className="mt-1 text-sm text-slate-300">{authority.commonName}</p>
                <p className="mt-2 break-all text-xs uppercase tracking-[0.16em] text-slate-400">{authority.serial}</p>
              </button>
            )) : (
              <p className="rounded-2xl border border-slate-700/70 bg-slate-900/40 px-4 py-3 text-sm text-slate-300">
                No authority exists yet. Create a root CA to issue leaf certificates.
              </p>
            )}
          </div>
        </Panel>

        <Panel title="Issued Certificates" eyebrow="Leaf Material">
          <div className="space-y-3">
            {activeCertificates.map((certificate) => (
              <article className="rounded-2xl border border-slate-700/70 bg-slate-900/50 px-4 py-4" key={certificate.serial}>
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div>
                    <p className="font-medium text-slate-50">{certificate.commonName}</p>
                    <p className="mt-1 text-sm text-slate-300">{certificate.sans.join(", ") || "No SAN"}</p>
                    <p className="mt-2 break-all text-xs uppercase tracking-[0.18em] text-slate-400">{certificate.serial}</p>
                  </div>
                  <button
                    className="rounded-full border border-rose-200 px-3 py-1 text-xs uppercase tracking-[0.16em] text-rose-700 transition hover:bg-rose-50 disabled:opacity-50"
                    disabled={certificate.revoked}
                    onClick={() => {
                      setRevocationForm({
                        serial: certificate.serial,
                        commonName: certificate.commonName,
                        reason: "cessationOfOperation"
                      });
                    }}
                    type="button"
                  >
                    {certificate.revoked ? "Revoked" : "Revoke"}
                  </button>
                </div>
                <details className="mt-3">
                  <summary className="cursor-pointer text-sm text-slate-300">Afficher les PEM</summary>
                  <pre className="mt-3 max-h-72 overflow-auto rounded-2xl border border-slate-700/70 bg-slate-900/40 p-4 text-xs text-slate-200">{certificate.certificatePem}</pre>
                  <pre className="mt-3 max-h-72 overflow-auto rounded-2xl border border-slate-700/70 bg-slate-900/40 p-4 text-xs text-slate-200">{certificate.privateKeyPem}</pre>
                </details>
              </article>
            ))}
          </div>
        </Panel>

        <Panel title="Revocation Register" eyebrow="CRL Feed">
          <div className="space-y-3">
            {revocations.data.map((revocation) => (
              <article className="rounded-2xl border border-slate-700/70 bg-slate-900/50 px-4 py-4" key={revocation.serial}>
                <p className="font-medium text-slate-50">{revocation.commonName || revocation.serial}</p>
                <p className="mt-1 break-all text-sm text-slate-300">{revocation.serial}</p>
                <p className="mt-2 text-xs uppercase tracking-[0.18em] text-rose-700">{revocation.reason}</p>
              </article>
            ))}
          </div>
        </Panel>
      </div>

      <div className="space-y-6">
        <Panel title="PKI Copilot Signals" eyebrow="Policy assistant">
          <div className="grid gap-3 md:grid-cols-3">
            {pkiGuidance.map((item) => (
              <div className="rounded-2xl border border-slate-700/70 bg-slate-900/40 px-4 py-3" key={item.label}>
                <p className="text-xs uppercase tracking-[0.18em] text-slate-400">{item.label}</p>
                <p className="mt-2 text-sm text-slate-200">{item.value}</p>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="PKI Task Wizard" eyebrow="Guided actions">
          <div className="mb-4 flex flex-wrap gap-2">
            {[
              ["authority", "Create Root CA"],
              ["certificate", "Issue Certificate"],
              ["revocation", "Revoke Certificate"]
            ].map(([mode, label]) => (
              <button className={["rounded-full border px-3 py-2 text-xs uppercase tracking-[0.14em]", wizardMode === mode ? "border-cyan-300/30 bg-cyan-300/10 text-cyan-50" : "border-white/10 text-slate-200"].join(" ")} key={mode} onClick={() => { setWizardMode(mode as typeof wizardMode); setWizardStep(0); }} type="button">{label}</button>
            ))}
          </div>
          <Wizard
            title={wizardMode === "authority" ? "Create a trusted root" : wizardMode === "certificate" ? "Issue a service certificate" : "Revoke a certificate"}
            steps={activeSteps}
            currentStep={wizardStep}
            error={wizardError}
            actions={
              <>
                <button className="rounded-2xl border border-white/10 px-4 py-3 font-medium text-slate-200 disabled:opacity-50" disabled={wizardStep === 0} onClick={() => setWizardStep((current) => Math.max(0, current - 1))} type="button">Back</button>
                {wizardStep < activeSteps.length - 1 ? (
                  <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" onClick={() => setWizardStep((current) => Math.min(activeSteps.length - 1, current + 1))} type="button">Next</button>
                ) : (
                  <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" onClick={runWizard} type="button">Apply</button>
                )}
              </>
            }
          >
            {wizardMode === "authority" && wizardStep === 0 ? <input className="w-full rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setAuthorityForm((current) => ({ ...current, name: event.target.value }))} placeholder="Authority name" value={authorityForm.name} /> : null}
            {wizardMode === "authority" && wizardStep === 1 ? <div className="grid gap-3"><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setAuthorityForm((current) => ({ ...current, commonName: event.target.value }))} placeholder="Common name" value={authorityForm.commonName} /><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setAuthorityForm((current) => ({ ...current, organization: event.target.value }))} placeholder="Organization" value={authorityForm.organization} /></div> : null}
            {wizardMode === "authority" && wizardStep === 2 ? <AdvancedSection title="Authority policy"><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setAuthorityForm((current) => ({ ...current, sans: event.target.value }))} placeholder="SANs" value={authorityForm.sans} /><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" min={1} onChange={(event) => setAuthorityForm((current) => ({ ...current, daysValid: Number(event.target.value) }))} type="number" value={authorityForm.daysValid} /></AdvancedSection> : null}
            {wizardMode === "authority" && wizardStep === 3 ? <WizardSummary items={[{ label: "Authority", value: authorityForm.name }, { label: "Subject", value: `${authorityForm.organization} / ${authorityForm.commonName}` }, { label: "SANs", value: splitProfileSans(authorityForm.sans) }, { label: "Validity", value: `${authorityForm.daysValid} days` }]} /> : null}

            {wizardMode === "certificate" && wizardStep === 0 ? <select className="w-full rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setCertificateForm((current) => ({ ...current, authorityName: event.target.value }))} value={certificateForm.authorityName || authorityName}><option value="">Select authority</option>{authorities.data.map((authority) => <option key={authority.name} value={authority.name}>{authority.name}</option>)}</select> : null}
            {wizardMode === "certificate" && wizardStep === 1 ? <div className="grid gap-3"><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setCertificateForm((current) => ({ ...current, commonName: event.target.value }))} placeholder="Common name" value={certificateForm.commonName} /><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setCertificateForm((current) => ({ ...current, organization: event.target.value }))} placeholder="Organization" value={certificateForm.organization} /></div> : null}
            {wizardMode === "certificate" && wizardStep === 2 ? <AdvancedSection title="Certificate policy"><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setCertificateForm((current) => ({ ...current, sans: event.target.value }))} placeholder="SANs" value={certificateForm.sans} /><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" min={1} onChange={(event) => setCertificateForm((current) => ({ ...current, daysValid: Number(event.target.value) }))} type="number" value={certificateForm.daysValid} /></AdvancedSection> : null}
            {wizardMode === "certificate" && wizardStep === 3 ? <WizardSummary items={[{ label: "Authority", value: certificateForm.authorityName || authorityName }, { label: "Subject", value: certificateForm.commonName }, { label: "SANs", value: splitProfileSans(certificateForm.sans) }, { label: "Validity", value: `${certificateForm.daysValid} days` }]} /> : null}

            {wizardMode === "revocation" && wizardStep === 0 ? <div className="grid gap-3"><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setRevocationForm((current) => ({ ...current, serial: event.target.value }))} placeholder="Serial" value={revocationForm.serial} /><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setRevocationForm((current) => ({ ...current, commonName: event.target.value }))} placeholder="Common name" value={revocationForm.commonName} /></div> : null}
            {wizardMode === "revocation" && wizardStep === 1 ? <select className="w-full rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setRevocationForm((current) => ({ ...current, reason: event.target.value }))} value={revocationForm.reason}>{REVOCATION_REASONS.map((reason) => <option key={reason}>{reason}</option>)}</select> : null}
            {wizardMode === "revocation" && wizardStep === 2 ? <WizardSummary items={[{ label: "Serial", value: revocationForm.serial }, { label: "Common name", value: revocationForm.commonName || "Not provided" }, { label: "Reason", value: revocationForm.reason }]} /> : null}
          </Wizard>
        </Panel>
      </div>
    </div>
  );
}
