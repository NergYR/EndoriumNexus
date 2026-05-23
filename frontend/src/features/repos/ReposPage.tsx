import { useMemo, useState } from "react";

import { Panel } from "../../components/Panel";
import { AdvancedSection, Wizard, WizardSummary } from "../../components/Wizard";
import {
  useCreateRepository,
  useCreateRepositoryPackage,
  useDeleteRepository,
  useDeleteRepositoryPackage,
  useRepositories,
  useRepositoryRender,
  useUpdateRepositoryPackage
} from "../../lib/api";
import type { AptPackage, AptPackagePayload } from "../../lib/types";

function defaultPackageForm(): AptPackagePayload {
  return {
    name: "endorium-agent",
    version: "0.1.0",
    architecture: "amd64",
    filename: "pool/main/e/endorium-agent_0.1.0_amd64.deb",
    sha256: "abc123",
    size: 12345
  };
}

const REPO_STEPS = [
  { id: "distribution", title: "Distribution", description: "Name the APT release." },
  { id: "component", title: "Component", description: "Choose the repository component." },
  { id: "review", title: "Review", description: "Create the catalog." }
];

const PACKAGE_STEPS = [
  { id: "identity", title: "Package", description: "Set name and version." },
  { id: "artifact", title: "Artifact", description: "Set filename and architecture." },
  { id: "advanced", title: "Integrity", description: "Set size and checksum metadata." },
  { id: "review", title: "Review", description: "Add package metadata." }
];

export function ReposPage() {
  const repositories = useRepositories();
  const createRepository = useCreateRepository();
  const deleteRepository = useDeleteRepository();
  const createPackage = useCreateRepositoryPackage();
  const updatePackage = useUpdateRepositoryPackage();
  const deletePackage = useDeleteRepositoryPackage();
  const [selectedKey, setSelectedKey] = useState("");
  const [repoForm, setRepoForm] = useState({ distribution: "bookworm", component: "main" });
  const [packageForm, setPackageForm] = useState<AptPackagePayload>(() => defaultPackageForm());
  const [editingPackageIndex, setEditingPackageIndex] = useState<number | null>(null);
  const [renderKind, setRenderKind] = useState<"packages" | "release">("packages");
  const [wizardMode, setWizardMode] = useState<"repository" | "package">("repository");
  const [wizardStep, setWizardStep] = useState(0);

  const activeRepository = useMemo(() => {
    if (!repositories.data?.length) {
      return undefined;
    }
    return repositories.data.find((repository) => `${repository.distribution}/${repository.component}` === selectedKey) ?? repositories.data[0];
  }, [repositories.data, selectedKey]);

  const rendered = useRepositoryRender(activeRepository?.distribution, activeRepository?.component, renderKind);

  if (repositories.isLoading || !repositories.data) {
    return <div className="text-sm text-slate-500">Chargement des dépôts...</div>;
  }

  const editPackage = (pkg: AptPackage, index: number) => {
    setEditingPackageIndex(index);
    setPackageForm({
      name: pkg.name,
      version: pkg.version,
      architecture: pkg.architecture,
      filename: pkg.filename,
      sha256: pkg.sha256,
      size: pkg.size
    });
  };

  const resetPackage = () => {
    setEditingPackageIndex(null);
    setPackageForm(defaultPackageForm());
  };
  const activeSteps = wizardMode === "repository" ? REPO_STEPS : PACKAGE_STEPS;
  const wizardError = createRepository.error?.message ?? createPackage.error?.message ?? updatePackage.error?.message ?? deleteRepository.error?.message ?? deletePackage.error?.message;
  const runWizard = () => {
    if (wizardMode === "repository") {
      createRepository.mutate(repoForm, { onSuccess: () => setSelectedKey(`${repoForm.distribution}/${repoForm.component}`) });
      return;
    }
    if (!activeRepository) {
      return;
    }
    if (editingPackageIndex === null) {
      createPackage.mutate({ distribution: activeRepository.distribution, component: activeRepository.component, package: packageForm }, { onSuccess: resetPackage });
      return;
    }
    updatePackage.mutate({ distribution: activeRepository.distribution, component: activeRepository.component, index: editingPackageIndex, package: packageForm }, { onSuccess: resetPackage });
  };

  return (
    <div className="grid gap-6 xl:grid-cols-[1fr_0.95fr]">
      <div className="space-y-6">
        <Panel title="APT Repositories" eyebrow="Metadata Catalog">
          <div className="space-y-5">
            {repositories.data.map((repository) => (
              <section
                className={[
                  "rounded-3xl border p-5 transition",
                  activeRepository?.distribution === repository.distribution && activeRepository.component === repository.component
                    ? "border-blue-200 bg-blue-50"
                    : "border-slate-200 bg-white"
                ].join(" ")}
                key={`${repository.distribution}-${repository.component}`}
              >
                <button
                  className="w-full text-left"
                  onClick={() => setSelectedKey(`${repository.distribution}/${repository.component}`)}
                  type="button"
                >
                  <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-slate-900">{repository.distribution}</h3>
                      <p className="text-sm text-slate-600">Component: {repository.component}</p>
                    </div>
                    <div className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs uppercase tracking-[0.18em] text-slate-600">
                      {repository.packages.length} packages
                    </div>
                  </div>
                </button>

                <div className="mt-4 grid gap-3">
                  {repository.packages.map((pkg, index) => (
                    <article className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3" key={`${pkg.filename}-${index}`}>
                      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                        <div>
                          <p className="font-medium text-slate-900">
                            {pkg.name} <span className="text-slate-500">{pkg.version}</span>
                          </p>
                          <p className="mt-1 break-all text-sm text-slate-600">{pkg.filename}</p>
                          <p className="mt-2 break-all text-xs uppercase tracking-[0.16em] text-slate-500">{pkg.sha256}</p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <span className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs uppercase tracking-[0.18em] text-slate-600">
                            {pkg.architecture}
                          </span>
                          <button className="rounded-full border border-slate-200 px-3 py-1 text-xs uppercase tracking-[0.16em] text-slate-600" onClick={() => editPackage(pkg, index)} type="button">Edit</button>
                          <button className="rounded-full border border-rose-200 px-3 py-1 text-xs uppercase tracking-[0.16em] text-rose-700" onClick={() => deletePackage.mutate({ distribution: repository.distribution, component: repository.component, index })} type="button">Delete</button>
                        </div>
                      </div>
                    </article>
                  ))}
                </div>
              </section>
            ))}
          </div>
        </Panel>

        <Panel title="APT Index Preview" eyebrow={renderKind === "packages" ? "Packages" : "Release"}>
          <div className="mb-3 flex flex-wrap gap-2">
            <button className={["rounded-full border px-3 py-1 text-xs uppercase tracking-[0.16em]", renderKind === "packages" ? "border-blue-200 bg-blue-50 text-slate-900" : "border-slate-200 text-slate-600"].join(" ")} onClick={() => setRenderKind("packages")} type="button">Packages</button>
            <button className={["rounded-full border px-3 py-1 text-xs uppercase tracking-[0.16em]", renderKind === "release" ? "border-blue-200 bg-blue-50 text-slate-900" : "border-slate-200 text-slate-600"].join(" ")} onClick={() => setRenderKind("release")} type="button">Release</button>
          </div>
          <pre className="max-h-[32rem] overflow-auto rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
            {rendered.data?.text ?? "Select or create a repository to render metadata."}
          </pre>
        </Panel>
      </div>

      <div className="space-y-6">
        <Panel title="Repository Task Wizard" eyebrow="Guided actions">
          <div className="mb-4 flex flex-wrap gap-2">
            <button className={["rounded-full border px-3 py-2 text-xs uppercase tracking-[0.14em]", wizardMode === "repository" ? "border-blue-200 bg-blue-50 text-slate-900" : "border-slate-200 text-slate-600"].join(" ")} onClick={() => { setWizardMode("repository"); setWizardStep(0); }} type="button">Create repository</button>
            <button className={["rounded-full border px-3 py-2 text-xs uppercase tracking-[0.14em]", wizardMode === "package" ? "border-blue-200 bg-blue-50 text-slate-900" : "border-slate-200 text-slate-600"].join(" ")} onClick={() => { setWizardMode("package"); setWizardStep(0); }} type="button">Add package</button>
            {activeRepository ? <button className="rounded-full border border-rose-200 px-3 py-2 text-xs uppercase tracking-[0.14em] text-rose-700" onClick={() => deleteRepository.mutate({ distribution: activeRepository.distribution, component: activeRepository.component })} type="button">Delete active</button> : null}
          </div>
          <Wizard
            title={wizardMode === "repository" ? "Create an APT repository" : editingPackageIndex === null ? "Add package metadata" : "Edit package metadata"}
            steps={activeSteps}
            currentStep={wizardStep}
            error={wizardError}
            actions={
              <>
                <button className="rounded-2xl border border-slate-200 px-4 py-3 font-medium text-slate-600 disabled:opacity-50" disabled={wizardStep === 0} onClick={() => setWizardStep((current) => Math.max(0, current - 1))} type="button">Back</button>
                {wizardStep < activeSteps.length - 1 ? (
                  <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-white" onClick={() => setWizardStep((current) => Math.min(activeSteps.length - 1, current + 1))} type="button">Next</button>
                ) : (
                  <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-white" disabled={wizardMode === "package" && !activeRepository} onClick={runWizard} type="button">Apply</button>
                )}
              </>
            }
          >
            {wizardMode === "repository" && wizardStep === 0 ? <input className="field w-full rounded-2xl px-4 py-3 outline-none" onChange={(event) => setRepoForm((current) => ({ ...current, distribution: event.target.value }))} placeholder="bookworm" value={repoForm.distribution} /> : null}
            {wizardMode === "repository" && wizardStep === 1 ? <input className="field w-full rounded-2xl px-4 py-3 outline-none" onChange={(event) => setRepoForm((current) => ({ ...current, component: event.target.value }))} placeholder="main" value={repoForm.component} /> : null}
            {wizardMode === "repository" && wizardStep === 2 ? <WizardSummary items={[{ label: "Distribution", value: repoForm.distribution }, { label: "Component", value: repoForm.component }]} /> : null}

            {wizardMode === "package" && wizardStep === 0 ? <div className="grid gap-3"><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setPackageForm((current) => ({ ...current, name: event.target.value }))} placeholder="Package name" value={packageForm.name} /><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setPackageForm((current) => ({ ...current, version: event.target.value }))} placeholder="Version" value={packageForm.version} /></div> : null}
            {wizardMode === "package" && wizardStep === 1 ? <div className="grid gap-3"><select className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setPackageForm((current) => ({ ...current, architecture: event.target.value }))} value={packageForm.architecture}><option>amd64</option><option>arm64</option><option>all</option></select><input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setPackageForm((current) => ({ ...current, filename: event.target.value }))} placeholder="pool/main/e/pkg.deb" value={packageForm.filename} /></div> : null}
            {wizardMode === "package" && wizardStep === 2 ? <AdvancedSection><input className="field rounded-2xl px-4 py-3 font-mono text-sm outline-none" onChange={(event) => setPackageForm((current) => ({ ...current, sha256: event.target.value }))} placeholder="sha256" value={packageForm.sha256} /><input className="field rounded-2xl px-4 py-3 outline-none" min={1} onChange={(event) => setPackageForm((current) => ({ ...current, size: Number(event.target.value) }))} placeholder="Size" type="number" value={packageForm.size} /></AdvancedSection> : null}
            {wizardMode === "package" && wizardStep === 3 ? <WizardSummary items={[{ label: "Repository", value: activeRepository ? `${activeRepository.distribution}/${activeRepository.component}` : "Select a repository first" }, { label: "Package", value: `${packageForm.name} ${packageForm.version}` }, { label: "Artifact", value: `${packageForm.architecture} - ${packageForm.filename}` }, { label: "SHA256", value: packageForm.sha256 }]} /> : null}
          </Wizard>
        </Panel>
      </div>
    </div>
  );
}
