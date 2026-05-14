import { useMemo, useState } from "react";

import { Panel } from "../../components/Panel";
import { AdvancedSection, Wizard, WizardSummary } from "../../components/Wizard";
import {
  useCreatePkiAuthority,
  useCreatePkiCertificate,
  useCreateRevocation,
  usePkiAuthorities,
  usePkiCertificates,
  useRevocations
} from "../../lib/api";

const REVOCATION_REASONS = [
  "keyCompromise",
  "cACompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "certificateHold",
  "removeFromCRL"
] as const;

function splitSans(value: string) {
  return value.split(",").map((entry) => entry.trim()).filter(Boolean);
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
  const [wizardMode, setWizardMode] = useState<"authority" | "certificate" | "revocation">("authority");
  const [wizardStep, setWizardStep] = useState(0);

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

  if (authorities.isLoading || certificates.isLoading || revocations.isLoading || !authorities.data || !certificates.data || !revocations.data) {
    return <div className="text-sm text-slate-400">Loading PKI material...</div>;
  }

  const authorityName = activeAuthority?.name ?? certificateForm.authorityName;
  const activeSteps = wizardMode === "authority" ? AUTHORITY_STEPS : wizardMode === "certificate" ? CERTIFICATE_STEPS : REVOCATION_STEPS;
  const wizardError = createAuthority.error?.message ?? createCertificate.error?.message ?? createRevocation.error?.message;
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
        <Panel title="Certificate Authorities" eyebrow="Trust Roots">
          <div className="grid gap-3">
            {authorities.data.length ? authorities.data.map((authority) => (
              <button
                className={[
                  "rounded-3xl border p-4 text-left transition",
                  activeAuthority?.name === authority.name ? "border-cyan-300/30 bg-cyan-400/10" : "border-white/8 bg-white/4 hover:border-blue-300/20"
                ].join(" ")}
                key={authority.name}
                onClick={() => {
                  setSelectedAuthority(authority.name);
                  setCertificateForm((current) => ({ ...current, authorityName: authority.name }));
                }}
                type="button"
              >
                <p className="font-semibold text-slate-100">{authority.name}</p>
                <p className="mt-1 text-sm text-slate-400">{authority.commonName}</p>
                <p className="mt-2 break-all text-xs uppercase tracking-[0.16em] text-slate-500">{authority.serial}</p>
              </button>
            )) : (
              <p className="rounded-2xl border border-white/8 bg-black/15 px-4 py-3 text-sm text-slate-400">
                No authority exists yet. Create a root CA to issue leaf certificates.
              </p>
            )}
          </div>
        </Panel>

        <Panel title="Issued Certificates" eyebrow="Leaf Material">
          <div className="space-y-3">
            {activeCertificates.map((certificate) => (
              <article className="rounded-2xl border border-white/8 bg-white/4 px-4 py-4" key={certificate.serial}>
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div>
                    <p className="font-medium text-slate-100">{certificate.commonName}</p>
                    <p className="mt-1 text-sm text-slate-400">{certificate.sans.join(", ") || "No SAN"}</p>
                    <p className="mt-2 break-all text-xs uppercase tracking-[0.18em] text-slate-500">{certificate.serial}</p>
                  </div>
                  <button
                    className="rounded-full border border-rose-300/20 px-3 py-1 text-xs uppercase tracking-[0.16em] text-rose-100 transition hover:bg-rose-300/10 disabled:opacity-50"
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
                  <summary className="cursor-pointer text-sm text-cyan-100">Show PEM material</summary>
                  <pre className="mt-3 max-h-72 overflow-auto rounded-2xl border border-white/8 bg-slate-950/70 p-4 text-xs text-cyan-50">{certificate.certificatePem}</pre>
                  <pre className="mt-3 max-h-72 overflow-auto rounded-2xl border border-white/8 bg-slate-950/70 p-4 text-xs text-amber-50">{certificate.privateKeyPem}</pre>
                </details>
              </article>
            ))}
          </div>
        </Panel>

        <Panel title="Revocation Register" eyebrow="CRL Feed">
          <div className="space-y-3">
            {revocations.data.map((revocation) => (
              <article className="rounded-2xl border border-white/8 bg-white/4 px-4 py-4" key={revocation.serial}>
                <p className="font-medium text-slate-100">{revocation.commonName || revocation.serial}</p>
                <p className="mt-1 break-all text-sm text-slate-400">{revocation.serial}</p>
                <p className="mt-2 text-xs uppercase tracking-[0.18em] text-rose-200">{revocation.reason}</p>
              </article>
            ))}
          </div>
        </Panel>
      </div>

      <div className="space-y-6">
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
            {wizardMode === "authority" && wizardStep === 2 ? <AdvancedSection><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setAuthorityForm((current) => ({ ...current, sans: event.target.value }))} placeholder="SANs" value={authorityForm.sans} /><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" min={1} onChange={(event) => setAuthorityForm((current) => ({ ...current, daysValid: Number(event.target.value) }))} type="number" value={authorityForm.daysValid} /></AdvancedSection> : null}
            {wizardMode === "authority" && wizardStep === 3 ? <WizardSummary items={[{ label: "Authority", value: authorityForm.name }, { label: "Subject", value: `${authorityForm.organization} / ${authorityForm.commonName}` }, { label: "SANs", value: authorityForm.sans }, { label: "Validity", value: `${authorityForm.daysValid} days` }]} /> : null}

            {wizardMode === "certificate" && wizardStep === 0 ? <select className="w-full rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setCertificateForm((current) => ({ ...current, authorityName: event.target.value }))} value={certificateForm.authorityName || authorityName}><option value="">Select authority</option>{authorities.data.map((authority) => <option key={authority.name} value={authority.name}>{authority.name}</option>)}</select> : null}
            {wizardMode === "certificate" && wizardStep === 1 ? <div className="grid gap-3"><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setCertificateForm((current) => ({ ...current, commonName: event.target.value }))} placeholder="Common name" value={certificateForm.commonName} /><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setCertificateForm((current) => ({ ...current, organization: event.target.value }))} placeholder="Organization" value={certificateForm.organization} /></div> : null}
            {wizardMode === "certificate" && wizardStep === 2 ? <AdvancedSection><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setCertificateForm((current) => ({ ...current, sans: event.target.value }))} placeholder="SANs" value={certificateForm.sans} /><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" min={1} onChange={(event) => setCertificateForm((current) => ({ ...current, daysValid: Number(event.target.value) }))} type="number" value={certificateForm.daysValid} /></AdvancedSection> : null}
            {wizardMode === "certificate" && wizardStep === 3 ? <WizardSummary items={[{ label: "Authority", value: certificateForm.authorityName || authorityName }, { label: "Subject", value: certificateForm.commonName }, { label: "SANs", value: certificateForm.sans }, { label: "Validity", value: `${certificateForm.daysValid} days` }]} /> : null}

            {wizardMode === "revocation" && wizardStep === 0 ? <div className="grid gap-3"><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setRevocationForm((current) => ({ ...current, serial: event.target.value }))} placeholder="Serial" value={revocationForm.serial} /><input className="rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setRevocationForm((current) => ({ ...current, commonName: event.target.value }))} placeholder="Common name" value={revocationForm.commonName} /></div> : null}
            {wizardMode === "revocation" && wizardStep === 1 ? <select className="w-full rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none" onChange={(event) => setRevocationForm((current) => ({ ...current, reason: event.target.value }))} value={revocationForm.reason}>{REVOCATION_REASONS.map((reason) => <option key={reason}>{reason}</option>)}</select> : null}
            {wizardMode === "revocation" && wizardStep === 2 ? <WizardSummary items={[{ label: "Serial", value: revocationForm.serial }, { label: "Common name", value: revocationForm.commonName || "Not provided" }, { label: "Reason", value: revocationForm.reason }]} /> : null}
          </Wizard>
        </Panel>
      </div>
    </div>
  );
}
