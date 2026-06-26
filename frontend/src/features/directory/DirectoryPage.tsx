import { useMemo, useState } from "react";

import { ObjectPropertiesTabs } from "../../components/ObjectPropertiesTabs";
import { Panel } from "../../components/Panel";
import { AdvancedSection, Wizard, WizardSummary } from "../../components/Wizard";
import {
  useActiveDirectoryDomain,
  useActiveDirectoryJoinGuide,
  useActiveDirectoryReadiness,
  useCreateActiveDirectoryDomain,
  useCreateDirectoryObject,
  useDeleteDirectoryObject,
  useDirectoryObjects,
  useUpdateDirectoryObject
} from "../../lib/api";
import type { DirectoryObject, DirectoryObjectPayload } from "../../lib/types";

const TEMPLATES = {
  user: {
    label: "New User",
    kind: "user",
    rdnPrefix: "cn",
    objectClasses: ["top", "person", "organizationalPerson", "user"],
    attributes: { cn: "Alice Admin", displayName: "Alice Admin", sAMAccountName: "alice", userPrincipalName: "alice@endorium.local", userAccountControl: "512" }
  },
  group: {
    label: "New Group",
    kind: "group",
    rdnPrefix: "cn",
    objectClasses: ["top", "group"],
    attributes: { cn: "Network Admins", sAMAccountName: "Network Admins", groupType: "-2147483646", member: "cn=Alice Admin,ou=Users,dc=endorium,dc=local" }
  },
  ou: {
    label: "New OU",
    kind: "organizationalUnit",
    rdnPrefix: "ou",
    objectClasses: ["organizationalUnit"],
    attributes: { ou: "People", description: "Directory container" }
  },
  service: {
    label: "New Service Account",
    kind: "serviceAccount",
    rdnPrefix: "cn",
    objectClasses: ["top", "person", "organizationalPerson", "user"],
    attributes: { cn: "svc-nexus", sAMAccountName: "svc-nexus", userPrincipalName: "svc-nexus@endorium.local", description: "Automation account", userAccountControl: "66048" }
  }
} as const;

const wizardSteps = [
  { id: "type", title: "Object type", description: "Choose the account or container to create." },
  { id: "identity", title: "Identity", description: "Set names users recognize." },
  { id: "advanced", title: "Advanced", description: "Review classes and raw attributes." },
  { id: "review", title: "Review", description: "Confirm before writing to LDAP state." }
];

type TemplateKey = keyof typeof TEMPLATES;

type AttributeRow = {
  id: number;
  key: string;
  value: string;
};

type DirectoryForm = {
  template: TemplateKey;
  dn: string;
  parentDn: string;
  kind: string;
  objectClasses: string;
  password: string;
  attributes: AttributeRow[];
};

type DomainForm = {
  dnsName: string;
  netbiosName: string;
  baseDn: string;
  adminSamAccount: string;
  adminDisplayName: string;
  adminPassword: string;
  domainControllerHost: string;
  domainControllerAddress: string;
};

function makeId() {
  return Date.now() + Math.floor(Math.random() * 1000);
}

function rowsFromAttributes(attributes: Record<string, string>) {
  return Object.entries(attributes)
    .filter(([key]) => key !== "userPasswordHash")
    .map(([key, value], index) => ({ id: makeId() + index, key, value }));
}

function defaultForm(templateKey: TemplateKey = "user", parentDn = "ou=Users,dc=endorium,dc=local"): DirectoryForm {
  const template = TEMPLATES[templateKey];
  const resolvedParent = templateKey === "group" ? "ou=Groups,dc=endorium,dc=local" : parentDn;
  const rdnValue = template.attributes[template.rdnPrefix as keyof typeof template.attributes] ?? "new";
  return {
    template: templateKey,
    dn: `${template.rdnPrefix}=${rdnValue},${resolvedParent}`,
    parentDn: resolvedParent,
    kind: template.kind,
    objectClasses: template.objectClasses.join(", "),
    password: "",
    attributes: rowsFromAttributes(template.attributes)
  };
}

function formFromObject(object: DirectoryObject): DirectoryForm {
  const template = Object.entries(TEMPLATES).find(([, candidate]) => candidate.kind === object.kind)?.[0] as TemplateKey | undefined;
  return {
    template: template ?? "user",
    dn: object.dn,
    parentDn: object.parentDn,
    kind: object.kind,
    objectClasses: object.objectClasses.join(", "),
    password: "",
    attributes: rowsFromAttributes(object.attributes)
  };
}

function payloadFromForm(form: DirectoryForm): DirectoryObjectPayload {
  const attributes: Record<string, string> = {};
  for (const row of form.attributes) {
    if (row.key.trim() && row.value.trim()) {
      attributes[row.key.trim()] = row.value.trim();
    }
  }
  return {
    dn: form.dn.trim(),
    parentDn: form.parentDn.trim(),
    kind: form.kind.trim(),
    objectClasses: form.objectClasses.split(",").map((entry) => entry.trim()).filter(Boolean),
    attributes,
    ...(form.password.trim() ? { password: form.password } : {})
  };
}

function objectLabel(object: DirectoryObject) {
  return object.attributes.displayName ?? object.attributes.cn ?? object.attributes.sAMAccountName ?? object.attributes.uid ?? object.attributes.ou ?? object.dn.split(",")[0] ?? object.dn;
}

export function DirectoryPage() {
  const adDomain = useActiveDirectoryDomain();
  const readiness = useActiveDirectoryReadiness();
  const joinGuide = useActiveDirectoryJoinGuide();
  const createDomain = useCreateActiveDirectoryDomain();
  const directory = useDirectoryObjects();
  const createObject = useCreateDirectoryObject();
  const updateObject = useUpdateDirectoryObject();
  const deleteObject = useDeleteDirectoryObject();
  const [query, setQuery] = useState("");
  const [selectedDn, setSelectedDn] = useState<string | null>(null);
  const [selectedParent, setSelectedParent] = useState("ou=People,dc=endorium,dc=local");
  const [editingDn, setEditingDn] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [domainWizardOpen, setDomainWizardOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [domainStep, setDomainStep] = useState(0);
  const [form, setForm] = useState<DirectoryForm>(() => defaultForm());
  const [domainForm, setDomainForm] = useState<DomainForm>({
    dnsName: "endorium.local",
    netbiosName: "ENDORIUM",
    baseDn: "dc=endorium,dc=local",
    adminSamAccount: "Administrator",
    adminDisplayName: "Administrator",
    adminPassword: "ChangeMe-AD-1",
    domainControllerHost: "dc1",
    domainControllerAddress: "10.10.10.10"
  });
  const [formError, setFormError] = useState<string | null>(null);

  const containers = useMemo(() => {
    const baseDn = adDomain.data?.baseDn ?? "dc=endorium,dc=local";
    const parents = new Set<string>([baseDn, `ou=Users,${baseDn}`, `ou=Groups,${baseDn}`, `cn=Computers,${baseDn}`]);
    for (const object of directory.data ?? []) {
      if (object.kind === "organizationalUnit") {
        parents.add(object.dn);
      }
      if (object.parentDn) {
        parents.add(object.parentDn);
      }
    }
    return Array.from(parents).sort();
  }, [adDomain.data?.baseDn, directory.data]);

  const filteredObjects = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (directory.data ?? []).filter((object) => {
      const matchesParent = !selectedParent || object.parentDn === selectedParent || object.dn === selectedParent;
      const matchesQuery = !needle || object.dn.toLowerCase().includes(needle) || object.kind.toLowerCase().includes(needle) || Object.values(object.attributes).some((value) => value.toLowerCase().includes(needle));
      return matchesParent && matchesQuery;
    });
  }, [directory.data, query, selectedParent]);

  const selectedObject = useMemo(() => {
    if (!directory.data?.length) {
      return undefined;
    }
    return directory.data.find((object) => object.dn === selectedDn) ?? filteredObjects[0];
  }, [directory.data, filteredObjects, selectedDn]);

  if (directory.isLoading || !directory.data || adDomain.isLoading || readiness.isLoading || joinGuide.isLoading) {
    return <div className="text-sm text-slate-400">Chargement de l'annuaire...</div>;
  }

  const openWizard = (template: TemplateKey, object?: DirectoryObject) => {
    setWizardStep(0);
    setFormError(null);
    if (object) {
      setEditingDn(object.dn);
      setForm(formFromObject(object));
    } else {
      setEditingDn(null);
      setForm(defaultForm(template, selectedParent));
    }
    setWizardOpen(true);
  };

  const applyTemplate = (templateKey: TemplateKey) => {
    setForm(defaultForm(templateKey, selectedParent));
    setFormError(null);
  };

  const updateAttribute = (id: number, patch: Partial<AttributeRow>) => {
    setForm((current) => ({
      ...current,
      attributes: current.attributes.map((row) => (row.id === id ? { ...row, ...patch } : row))
    }));
  };

  const submitWizard = () => {
    const payload = payloadFromForm(form);
    if (!payload.dn || !payload.kind || !payload.objectClasses.length) {
      setFormError("Complete the object identity and object classes before applying.");
      return;
    }
    if (editingDn) {
      updateObject.mutate({ dn: editingDn, object: payload }, { onSuccess: () => setWizardOpen(false) });
      return;
    }
    createObject.mutate(payload, { onSuccess: () => setWizardOpen(false) });
  };

  const submitDomainWizard = () => {
    createDomain.mutate(domainForm, { onSuccess: () => setDomainWizardOpen(false) });
  };

  return (
    <div className="space-y-6">
      <Panel
        title="Windows Domain"
        eyebrow={readiness.data?.supported ? "Active Directory supported" : "Active Directory blocked"}
        actions={
          adDomain.data ? null : (
            <button className="accent-gradient rounded-2xl px-4 py-3 text-sm font-medium text-slate-950" onClick={() => setDomainWizardOpen(true)} type="button">
              Create Windows domain
            </button>
          )
        }
      >
        <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
          <div className="rounded-2xl border border-slate-700/70 bg-slate-900/50 p-4">
            {adDomain.data ? (
              <WizardSummary
                items={[
                  { label: "Domain", value: adDomain.data.dnsName },
                  { label: "NetBIOS", value: adDomain.data.netbiosName },
                  { label: "Realm", value: adDomain.data.realm },
                  { label: "Base DN", value: adDomain.data.baseDn },
                  { label: "Domain SID", value: adDomain.data.domainSid }
                ]}
              />
            ) : (
              <p className="text-sm text-slate-300">Aucun domaine Windows n'est configuré. Créez-en un avant de préparer des clients Windows.</p>
            )}
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            {(readiness.data?.items ?? []).map((item) => (
              <div className="rounded-2xl border border-slate-700/70 bg-slate-900/40 px-4 py-3" key={item.id}>
                <p className="text-[0.65rem] uppercase tracking-[0.16em] text-slate-500">{item.category}</p>
                <p className="mt-1 text-sm font-medium text-slate-50">{item.label}</p>
                <p className={["mt-1 text-xs uppercase tracking-[0.16em]", item.ready ? "text-emerald-200" : "text-amber-200"].join(" ")}>
                  {item.ready ? "Ready" : item.blocking ? "Blocked" : "Pending"}
                </p>
                <p className="mt-2 text-xs text-slate-400">{item.detail}</p>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-4 rounded-2xl border border-amber-300/20 bg-amber-300/10 px-4 py-3 text-sm text-amber-50">
          {joinGuide.data?.message}
        </div>
      </Panel>

      <Panel
        title="Active Directory Users and Computers"
        eyebrow="Windows-style console"
        actions={
          <div className="flex flex-wrap gap-2">
            {(Object.keys(TEMPLATES) as TemplateKey[]).map((key) => (
              <button className="rounded-full border border-slate-700/70 px-3 py-2 text-xs uppercase tracking-[0.14em] text-slate-300 hover:bg-slate-900/40" key={key} onClick={() => openWizard(key)} type="button">
                    {TEMPLATES[key].label}
              </button>
            ))}
          </div>
        }
      >
        <div className="grid min-h-[36rem] gap-4 xl:grid-cols-[260px_1fr_360px]">
          <aside className="rounded-2xl border border-slate-700/70 bg-slate-900/50 p-3">
            <p className="px-2 text-xs uppercase tracking-[0.18em] text-slate-400">Tree</p>
            <div className="mt-3 space-y-1">
              {containers.map((container) => (
                <button
                  className={[
                    "w-full rounded-xl px-3 py-2 text-left text-sm transition",
                    selectedParent === container ? "bg-cyan-400/10 text-slate-50" : "text-slate-300 hover:bg-slate-900/40"
                  ].join(" ")}
                  key={container}
                  onClick={() => setSelectedParent(container)}
                  type="button"
                >
                  {container}
                </button>
              ))}
            </div>
          </aside>

          <section className="surface p-3">
            <input className="field mb-3 w-full rounded-2xl px-4 py-3 outline-none" onChange={(event) => setQuery(event.target.value)} placeholder="Search users, groups, OUs..." value={query} />
            <div className="overflow-hidden rounded-2xl border border-slate-700/70">
              <div className="grid grid-cols-[1fr_130px_120px] bg-slate-900/40 px-3 py-2 text-xs uppercase tracking-[0.16em] text-slate-400">
                <span>Name</span><span>Type</span><span>Account</span>
              </div>
              <div className="max-h-[30rem] overflow-auto">
                {filteredObjects.map((object) => (
                  <button
                    className={[
                      "grid w-full grid-cols-[1fr_130px_120px] gap-3 border-t border-slate-100 px-3 py-3 text-left text-sm",
                      selectedObject?.dn === object.dn ? "bg-cyan-400/10" : "hover:bg-slate-900/40"
                    ].join(" ")}
                    key={object.dn}
                    onClick={() => setSelectedDn(object.dn)}
                    type="button"
                  >
                    <span className="min-w-0">
                      <span className="block truncate font-medium text-slate-50">{objectLabel(object)}</span>
                      <span className="block truncate text-xs text-slate-400">{object.dn}</span>
                    </span>
                    <span className="text-slate-300">{object.kind}</span>
                    <span className={object.attributes.userPasswordHash ? "text-emerald-200" : "text-slate-400"}>{object.attributes.userPasswordHash ? "Secret set" : "No secret"}</span>
                  </button>
                ))}
              </div>
            </div>
          </section>

          <aside className="surface p-4">
            {selectedObject ? (
              <>
                <div className="mb-4 flex items-start justify-between gap-3">
                  <div>
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Properties</p>
                    <h3 className="mt-2 break-all text-lg font-semibold text-slate-50">{objectLabel(selectedObject)}</h3>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button className="rounded-full border border-slate-700/70 px-3 py-1 text-xs uppercase tracking-[0.16em] text-slate-300" onClick={() => openWizard((formFromObject(selectedObject).template), selectedObject)} type="button">Edit</button>
                    <button className="rounded-full border border-rose-300/20 px-3 py-1 text-xs uppercase tracking-[0.16em] text-rose-100" onClick={() => deleteObject.mutate({ dn: selectedObject.dn })} type="button">Delete</button>
                  </div>
                </div>
                <ObjectPropertiesTabs
                  tabs={[
                    { id: "general", label: "General", content: <WizardSummary items={[{ label: "DN", value: selectedObject.dn }, { label: "Parent", value: selectedObject.parentDn || "Domain root" }, { label: "Kind", value: selectedObject.kind }]} /> },
                    { id: "account", label: "Account", content: <WizardSummary items={[{ label: "SAM account", value: selectedObject.attributes.sAMAccountName ?? selectedObject.attributes.uid ?? "Not set" }, { label: "UPN", value: selectedObject.attributes.userPrincipalName ?? "Not set" }, { label: "UAC", value: selectedObject.attributes.userAccountControl ?? "Not set" }, { label: "Secret", value: selectedObject.attributes.userPasswordHash ? "Secret configured" : "No secret configured" }]} /> },
                    { id: "membership", label: "Membership", content: <p className="text-sm text-slate-300">{selectedObject.attributes.member ?? "No membership attribute configured."}</p> },
                    { id: "attributes", label: "Attributes", content: <dl className="grid gap-2 text-sm">{Object.entries(selectedObject.attributes).map(([key, value]) => <div className="grid gap-1 rounded-xl border border-slate-700/70 bg-slate-900/40 px-3 py-2" key={key}><dt className="text-xs uppercase tracking-[0.16em] text-slate-400">{key}</dt><dd className="break-all text-slate-50">{key === "userPasswordHash" ? "Secret configured" : value}</dd></div>)}</dl> },
                    { id: "advanced", label: "Advanced", content: <WizardSummary items={[{ label: "Object classes", value: selectedObject.objectClasses.join(", ") }, { label: "Raw DN", value: selectedObject.dn }]} /> }
                  ]}
                />
              </>
            ) : (
              <p className="text-sm text-slate-400">Select an object to view properties.</p>
            )}
          </aside>
        </div>
      </Panel>

      {wizardOpen ? (
        <Wizard
          title={editingDn ? "Edit directory object" : TEMPLATES[form.template].label}
          steps={wizardSteps}
          currentStep={wizardStep}
          error={formError ?? createObject.error?.message ?? updateObject.error?.message ?? deleteObject.error?.message}
          actions={
            <>
              <button className="rounded-2xl border border-slate-700/70 px-4 py-3 font-medium text-slate-300" onClick={() => setWizardOpen(false)} type="button">Close</button>
              <button className="rounded-2xl border border-slate-700/70 px-4 py-3 font-medium text-slate-300 disabled:opacity-50" disabled={wizardStep === 0} onClick={() => setWizardStep((current) => Math.max(0, current - 1))} type="button">Back</button>
              {wizardStep < wizardSteps.length - 1 ? (
                <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" onClick={() => setWizardStep((current) => Math.min(wizardSteps.length - 1, current + 1))} type="button">Next</button>
              ) : (
                <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" onClick={submitWizard} type="button">{editingDn ? "Save object" : "Create object"}</button>
              )}
            </>
          }
        >
          {wizardStep === 0 ? (
            <div className="grid gap-3 md:grid-cols-2">
              {(Object.keys(TEMPLATES) as TemplateKey[]).map((key) => (
                <button className={["rounded-2xl border px-4 py-4 text-left transition", form.template === key ? "border-cyan-400/30 bg-cyan-400/10" : "border-slate-700/70 bg-slate-900/50 hover:bg-slate-900/40"].join(" ")} key={key} onClick={() => applyTemplate(key)} type="button">
                  <p className="font-medium text-slate-50">{TEMPLATES[key].label}</p>
                  <p className="mt-1 text-sm text-slate-400">{TEMPLATES[key].objectClasses.join(", ")}</p>
                </button>
              ))}
            </div>
          ) : null}
          {wizardStep === 1 ? (
            <div className="grid gap-3">
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">Distinguished Name</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setForm((current) => ({ ...current, dn: event.target.value }))} value={form.dn} /></label>
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">Parent container</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setForm((current) => ({ ...current, parentDn: event.target.value }))} value={form.parentDn} /></label>
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">Password</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))} placeholder={editingDn ? "Leave blank to keep existing secret" : "Optional"} type="password" value={form.password} /></label>
            </div>
          ) : null}
          {wizardStep === 2 ? (
            <div className="grid gap-3">
              <AdvancedSection title="Object classes"><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setForm((current) => ({ ...current, objectClasses: event.target.value }))} value={form.objectClasses} /></AdvancedSection>
              <AdvancedSection title="Raw attributes">
                {form.attributes.map((row) => (
                  <div className="grid gap-2 md:grid-cols-[0.7fr_1fr_auto]" key={row.id}>
                    <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateAttribute(row.id, { key: event.target.value })} placeholder="attribute" value={row.key} />
                    <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => updateAttribute(row.id, { value: event.target.value })} placeholder="value" value={row.value} />
                    <button className="rounded-2xl border border-rose-300/20 px-4 py-3 text-sm text-rose-100" onClick={() => setForm((current) => ({ ...current, attributes: current.attributes.filter((entry) => entry.id !== row.id) }))} type="button">Remove</button>
                  </div>
                ))}
                <button className="rounded-2xl border border-slate-700/70 px-4 py-3 text-sm font-medium text-slate-300" onClick={() => setForm((current) => ({ ...current, attributes: [...current.attributes, { id: makeId(), key: "", value: "" }] }))} type="button">Add attribute</button>
              </AdvancedSection>
            </div>
          ) : null}
          {wizardStep === 3 ? (
            <WizardSummary items={[{ label: "DN", value: form.dn }, { label: "Parent", value: form.parentDn }, { label: "Kind", value: form.kind }, { label: "Object classes", value: form.objectClasses }, { label: "Secret", value: form.password ? "Will set secret" : "No secret change" }]} />
          ) : null}
        </Wizard>
      ) : null}

      {domainWizardOpen ? (
        <Wizard
          title="Create Windows domain"
          steps={[
            { id: "domain", title: "Domain", description: "Name the Windows domain." },
            { id: "admin", title: "Administrator", description: "Create the first domain admin." },
            { id: "dc", title: "Domain controller", description: "Publish DNS records for this controller." },
            { id: "review", title: "Review", description: "Create the AD model and readiness checklist." }
          ]}
          currentStep={domainStep}
          error={createDomain.error?.message}
          actions={
            <>
              <button className="rounded-2xl border border-slate-700/70 px-4 py-3 font-medium text-slate-300" onClick={() => setDomainWizardOpen(false)} type="button">Close</button>
              <button className="rounded-2xl border border-slate-700/70 px-4 py-3 font-medium text-slate-300 disabled:opacity-50" disabled={domainStep === 0} onClick={() => setDomainStep((current) => Math.max(0, current - 1))} type="button">Back</button>
              {domainStep < 3 ? (
                <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" onClick={() => setDomainStep((current) => Math.min(3, current + 1))} type="button">Next</button>
              ) : (
                <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" onClick={submitDomainWizard} type="button">Create domain</button>
              )}
            </>
          }
        >
          {domainStep === 0 ? (
            <div className="grid gap-3">
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">DNS domain</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setDomainForm((current) => ({ ...current, dnsName: event.target.value, baseDn: event.target.value.split(".").filter(Boolean).map((part) => `dc=${part}`).join(","), netbiosName: event.target.value.split(".")[0]?.toUpperCase().slice(0, 15) ?? current.netbiosName }))} value={domainForm.dnsName} /></label>
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">NetBIOS name</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setDomainForm((current) => ({ ...current, netbiosName: event.target.value.toUpperCase().slice(0, 15) }))} value={domainForm.netbiosName} /></label>
              <AdvancedSection title="LDAP naming context"><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setDomainForm((current) => ({ ...current, baseDn: event.target.value }))} value={domainForm.baseDn} /></AdvancedSection>
            </div>
          ) : null}
          {domainStep === 1 ? (
            <div className="grid gap-3 md:grid-cols-2">
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">SAM account</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setDomainForm((current) => ({ ...current, adminSamAccount: event.target.value }))} value={domainForm.adminSamAccount} /></label>
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">Display name</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setDomainForm((current) => ({ ...current, adminDisplayName: event.target.value }))} value={domainForm.adminDisplayName} /></label>
              <label className="grid gap-2 md:col-span-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">Temporary password</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setDomainForm((current) => ({ ...current, adminPassword: event.target.value }))} type="password" value={domainForm.adminPassword} /></label>
            </div>
          ) : null}
          {domainStep === 2 ? (
            <div className="grid gap-3 md:grid-cols-2">
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">Controller hostname</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setDomainForm((current) => ({ ...current, domainControllerHost: event.target.value }))} value={domainForm.domainControllerHost} /></label>
              <label className="grid gap-2"><span className="text-xs uppercase tracking-[0.18em] text-slate-400">Controller IP</span><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setDomainForm((current) => ({ ...current, domainControllerAddress: event.target.value }))} value={domainForm.domainControllerAddress} /></label>
            </div>
          ) : null}
          {domainStep === 3 ? (
            <WizardSummary
              items={[
                { label: "Domain", value: domainForm.dnsName },
                { label: "NetBIOS", value: domainForm.netbiosName },
                { label: "Base DN", value: domainForm.baseDn },
                { label: "Administrator", value: domainForm.adminSamAccount },
                { label: "Domain controller", value: `${domainForm.domainControllerHost}.${domainForm.dnsName} (${domainForm.domainControllerAddress})` },
                { label: "Windows join", value: "Blocked until LDAP AD, Kerberos, Netlogon and SMB SYSVOL are implemented" }
              ]}
            />
          ) : null}
        </Wizard>
      ) : null}
    </div>
  );
}
