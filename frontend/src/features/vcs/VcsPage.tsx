import { useMemo, useState } from "react";

import { Panel } from "../../components/Panel";
import {
  useCreateVcsToken,
  useCreateVcsRepository,
  useDeleteVcsRepository,
  useRepairVcsRepository,
  useRevokeVcsToken,
  useUpdateVcsRepository,
  useVcsActivity,
  useVcsRefs,
  useVcsRepositories,
  useVcsTokens
} from "../../lib/api";
import type { VcsAccessTokenCreatePayload, VcsRepository, VcsRepositoryCreatePayload } from "../../lib/types";

function defaultForm(): VcsRepositoryCreatePayload {
  return {
    name: "",
    description: "",
    isPrivate: true,
    httpPushEnabled: true,
    defaultBranch: "main"
  };
}

function defaultTokenForm(): VcsAccessTokenCreatePayload {
  return {
    name: "ci-deploy",
    scope: "read"
  };
}

type VcsTab = "refs" | "tokens" | "activity" | "settings";

function absoluteGitUrl(path: string) {
  return `${window.location.origin}${path}`;
}

function mutationError(...messages: Array<string | undefined>) {
  return messages.find(Boolean);
}

export function VcsPage() {
  const repositories = useVcsRepositories();
  const createRepository = useCreateVcsRepository();
  const createToken = useCreateVcsToken();
  const revokeToken = useRevokeVcsToken();
  const updateRepository = useUpdateVcsRepository();
  const repairRepository = useRepairVcsRepository();
  const deleteRepository = useDeleteVcsRepository();
  const [form, setForm] = useState(() => defaultForm());
  const [tokenForm, setTokenForm] = useState(() => defaultTokenForm());
  const [selectedId, setSelectedId] = useState("");
  const [copiedId, setCopiedId] = useState("");
  const [createdSecret, setCreatedSecret] = useState("");
  const [activeTab, setActiveTab] = useState<VcsTab>("refs");

  const activeRepository = useMemo(() => {
    if (!repositories.data?.length) {
      return undefined;
    }
    return repositories.data.find((repository) => repository.id === selectedId) ?? repositories.data[0];
  }, [repositories.data, selectedId]);

  const refs = useVcsRefs(activeRepository?.id);
  const tokens = useVcsTokens(activeRepository?.id);
  const activity = useVcsActivity(activeRepository?.id);

  const error = mutationError(
    createRepository.error?.message,
    createToken.error?.message,
    revokeToken.error?.message,
    updateRepository.error?.message,
    repairRepository.error?.message,
    deleteRepository.error?.message,
    refs.error?.message,
    tokens.error?.message,
    activity.error?.message,
    repositories.error?.message
  );

  if (repositories.isLoading || !repositories.data) {
    return <div className="text-sm text-slate-400">Chargement des dépôts Git...</div>;
  }

  const create = () => {
    createRepository.mutate(form, {
      onSuccess: (repository) => {
        setSelectedId(repository.id);
        setForm(defaultForm());
      }
    });
  };

  const togglePrivacy = (repository: VcsRepository) => {
    updateRepository.mutate({
      id: repository.id,
      repository: { isPrivate: !repository.isPrivate }
    });
  };

  const togglePush = (repository: VcsRepository) => {
    updateRepository.mutate({
      id: repository.id,
      repository: { httpPushEnabled: !repository.httpPushEnabled }
    });
  };

  const updateDescription = (repository: VcsRepository, description: string) => {
    updateRepository.mutate({
      id: repository.id,
      repository: { description }
    });
  };

  const copyUrl = async (repository: VcsRepository) => {
    await navigator.clipboard.writeText(absoluteGitUrl(repository.cloneUrl));
    setCopiedId(repository.id);
    window.setTimeout(() => setCopiedId(""), 1600);
  };

  const createAccessToken = () => {
    if (!activeRepository) {
      return;
    }
    createToken.mutate(
      { repositoryId: activeRepository.id, token: tokenForm },
      {
        onSuccess: (created) => {
          setCreatedSecret(created.secret);
          setTokenForm(defaultTokenForm());
        }
      }
    );
  };

  return (
    <div className="grid gap-6 xl:grid-cols-[1fr_0.8fr]">
      <div className="space-y-6">
        <Panel title="Serveur Git" eyebrow="Smart HTTP">
          <div className="space-y-4">
            {error ? <div className="rounded-2xl border border-rose-400/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">{error}</div> : null}

            {repositories.data.length === 0 ? (
              <div className="rounded-2xl border border-slate-700/70 bg-slate-900/40 p-5 text-sm text-slate-400">
                Aucun dépôt Git.
              </div>
            ) : null}

            {repositories.data.map((repository) => (
              <article
                className={[
                  "rounded-2xl border p-5 transition",
                  activeRepository?.id === repository.id
                    ? "border-cyan-400/30 bg-cyan-400/10"
                    : "border-slate-700/70 bg-slate-900/50"
                ].join(" ")}
                key={repository.id}
              >
                <button className="w-full text-left" onClick={() => { setSelectedId(repository.id); setCreatedSecret(""); }} type="button">
                  <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-slate-50">{repository.name}</h3>
                      <p className="mt-1 break-all font-mono text-xs text-cyan-200">{absoluteGitUrl(repository.cloneUrl)}</p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <span className="rounded-full border border-slate-700/70 bg-slate-950/40 px-3 py-1 text-xs uppercase tracking-[0.16em] text-slate-300">
                        {repository.isPrivate ? "Privé" : "Public"}
                      </span>
                      <span className="rounded-full border border-slate-700/70 bg-slate-950/40 px-3 py-1 text-xs uppercase tracking-[0.16em] text-slate-300">
                        {repository.httpPushEnabled ? "Push actif" : "Push fermé"}
                      </span>
                      <span className={["rounded-full border px-3 py-1 text-xs uppercase tracking-[0.16em]", repository.storageReady ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-100" : "border-amber-300/40 bg-amber-400/10 text-amber-100"].join(" ")}>
                        {repository.storageReady ? "Prêt" : "À réparer"}
                      </span>
                    </div>
                  </div>
                </button>

                <div className="mt-4 grid gap-3">
                  <input
                    className="field rounded-2xl px-4 py-3 text-sm outline-none"
                    defaultValue={repository.description}
                    onBlur={(event) => {
                      if (event.target.value !== repository.description) {
                        updateDescription(repository, event.target.value);
                      }
                    }}
                    placeholder="Description"
                  />
                  <div className="flex flex-wrap gap-2">
                    <button className="rounded-full border border-slate-700/70 px-3 py-2 text-xs uppercase tracking-[0.14em] text-slate-300" onClick={() => void copyUrl(repository)} type="button">
                      {copiedId === repository.id ? "Copié" : "Copier URL"}
                    </button>
                    <button className="rounded-full border border-slate-700/70 px-3 py-2 text-xs uppercase tracking-[0.14em] text-slate-300" onClick={() => togglePrivacy(repository)} type="button">
                      {repository.isPrivate ? "Rendre public" : "Rendre privé"}
                    </button>
                    <button className="rounded-full border border-slate-700/70 px-3 py-2 text-xs uppercase tracking-[0.14em] text-slate-300" onClick={() => togglePush(repository)} type="button">
                      {repository.httpPushEnabled ? "Fermer push" : "Ouvrir push"}
                    </button>
                    <button className="rounded-full border border-slate-700/70 px-3 py-2 text-xs uppercase tracking-[0.14em] text-slate-300" onClick={() => repairRepository.mutate({ id: repository.id })} type="button">
                      Réparer
                    </button>
                    <button className="rounded-full border border-rose-300/70 px-3 py-2 text-xs uppercase tracking-[0.14em] text-rose-200" onClick={() => deleteRepository.mutate({ id: repository.id })} type="button">
                      Supprimer
                    </button>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </Panel>
      </div>

      <div className="space-y-6">
        <Panel title="Nouveau Dépôt" eyebrow="Provisioning">
          <div className="space-y-4">
            <input
              className="field w-full rounded-2xl px-4 py-3 outline-none"
              onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
              placeholder="nom-du-depot"
              value={form.name}
            />
            <input
              className="field w-full rounded-2xl px-4 py-3 outline-none"
              onChange={(event) => setForm((current) => ({ ...current, defaultBranch: event.target.value }))}
              placeholder="main"
              value={form.defaultBranch}
            />
            <textarea
              className="field min-h-28 w-full rounded-2xl px-4 py-3 outline-none"
              onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
              placeholder="Description"
              value={form.description}
            />
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="flex items-center gap-3 rounded-2xl border border-slate-700/70 bg-slate-900/40 px-4 py-3 text-sm text-slate-200">
                <input checked={form.isPrivate} onChange={(event) => setForm((current) => ({ ...current, isPrivate: event.target.checked }))} type="checkbox" />
                Privé
              </label>
              <label className="flex items-center gap-3 rounded-2xl border border-slate-700/70 bg-slate-900/40 px-4 py-3 text-sm text-slate-200">
                <input checked={form.httpPushEnabled} onChange={(event) => setForm((current) => ({ ...current, httpPushEnabled: event.target.checked }))} type="checkbox" />
                Push HTTP
              </label>
            </div>
            <button
              className="accent-gradient w-full rounded-2xl px-4 py-3 font-medium text-white disabled:opacity-50"
              disabled={!form.name || !form.defaultBranch || createRepository.isPending}
              onClick={create}
              type="button"
            >
              Créer
            </button>
          </div>
        </Panel>

        {activeRepository ? (
          <Panel title={activeRepository.name} eyebrow="Forge">
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {(["refs", "tokens", "activity", "settings"] as VcsTab[]).map((tab) => (
                  <button
                    className={[
                      "rounded-2xl border px-3 py-2 text-xs uppercase tracking-[0.14em]",
                      activeTab === tab ? "border-cyan-400/30 bg-cyan-400/10 text-slate-50" : "border-slate-700/70 text-slate-300"
                    ].join(" ")}
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    type="button"
                  >
                    {tab === "refs" ? "Refs" : tab === "tokens" ? "Tokens" : tab === "activity" ? "Activity" : "Settings"}
                  </button>
                ))}
              </div>

              {activeTab === "refs" ? (
                <div className="space-y-3">
                  {(refs.data ?? []).length === 0 ? <p className="text-sm text-slate-400">Aucune branche ou tag publié.</p> : null}
                  {(refs.data ?? []).map((ref) => (
                    <div className="rounded-2xl border border-slate-700/70 bg-slate-950/40 p-3" key={ref.name}>
                      <div className="flex items-center justify-between gap-3">
                        <span className="rounded-full border border-slate-700/70 px-3 py-1 text-xs uppercase tracking-[0.16em] text-slate-300">{ref.type}</span>
                        <span className="break-all font-mono text-xs text-slate-400">{ref.objectId.slice(0, 12)}</span>
                      </div>
                      <p className="mt-2 break-all font-mono text-sm text-slate-100">{ref.shortName}</p>
                    </div>
                  ))}
                </div>
              ) : null}

              {activeTab === "tokens" ? (
                <div className="space-y-4">
                  {createdSecret ? (
                    <div className="rounded-2xl border border-amber-300/40 bg-amber-400/10 p-3 text-sm text-amber-100">
                      <p className="font-medium">Token créé, à copier maintenant.</p>
                      <p className="mt-2 break-all font-mono text-xs">{createdSecret}</p>
                    </div>
                  ) : null}
                  <div className="grid gap-3">
                    <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setTokenForm((current) => ({ ...current, name: event.target.value }))} placeholder="Nom du token" value={tokenForm.name} />
                    <select className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setTokenForm((current) => ({ ...current, scope: event.target.value as "read" | "write" }))} value={tokenForm.scope}>
                      <option value="read">Lecture</option>
                      <option value="write">Lecture + push</option>
                    </select>
                    <input className="field rounded-2xl px-4 py-3 outline-none" onChange={(event) => setTokenForm((current) => ({ ...current, expiresAt: event.target.value || undefined }))} placeholder="Expiration optionnelle ISO" value={tokenForm.expiresAt ?? ""} />
                    <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-white disabled:opacity-50" disabled={!tokenForm.name || createToken.isPending} onClick={createAccessToken} type="button">
                      Créer token
                    </button>
                  </div>
                  <div className="space-y-3">
                    {(tokens.data ?? []).map((token) => (
                      <div className="rounded-2xl border border-slate-700/70 bg-slate-950/40 p-3" key={token.id}>
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                          <div>
                            <p className="font-medium text-slate-100">{token.name}</p>
                            <p className="mt-1 font-mono text-xs text-slate-400">{token.tokenPrefix}...</p>
                            <p className="mt-1 text-xs text-slate-500">Dernier usage: {token.lastUsedAt || "jamais"}</p>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <span className="rounded-full border border-slate-700/70 px-3 py-1 text-xs uppercase tracking-[0.16em] text-slate-300">{token.scope}</span>
                            <button className="rounded-full border border-rose-300/70 px-3 py-1 text-xs uppercase tracking-[0.14em] text-rose-200 disabled:opacity-50" disabled={token.revoked} onClick={() => revokeToken.mutate({ repositoryId: activeRepository.id, tokenId: token.id })} type="button">
                              {token.revoked ? "Révoqué" : "Révoquer"}
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              {activeTab === "activity" ? (
                <div className="space-y-3">
                  {(activity.data ?? []).length === 0 ? <p className="text-sm text-slate-400">Aucune activité Git enregistrée.</p> : null}
                  {(activity.data ?? []).map((event, index) => (
                    <div className="rounded-2xl border border-slate-700/70 bg-slate-950/40 p-3" key={`${event.id}-${index}`}>
                      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                        <p className="font-medium text-slate-100">{event.action}</p>
                        <p className="text-xs text-slate-500">{event.happenedAt}</p>
                      </div>
                      <p className="mt-1 text-sm text-slate-300">{event.actor}</p>
                      {event.refName ? <p className="mt-2 break-all font-mono text-xs text-cyan-200">{event.refName}</p> : null}
                      {event.detail ? <p className="mt-2 break-all text-xs text-slate-500">{event.detail}</p> : null}
                    </div>
                  ))}
                </div>
              ) : null}

              {activeTab === "settings" ? (
                <dl className="space-y-3 text-sm">
                  <div className="flex justify-between gap-4">
                    <dt className="text-slate-400">Branche</dt>
                    <dd className="font-mono text-slate-100">{activeRepository.defaultBranch}</dd>
                  </div>
                  <div className="flex justify-between gap-4">
                    <dt className="text-slate-400">HEAD</dt>
                    <dd className="break-all font-mono text-slate-100">{activeRepository.headTarget || "refs/heads/main"}</dd>
                  </div>
                  <div className="flex justify-between gap-4">
                    <dt className="text-slate-400">Créé</dt>
                    <dd className="text-slate-100">{activeRepository.createdAt}</dd>
                  </div>
                  <div className="rounded-2xl border border-slate-700/70 bg-slate-950/50 p-4">
                    <dt className="mb-2 text-slate-400">Commande</dt>
                    <dd className="break-all font-mono text-cyan-200">git clone {absoluteGitUrl(activeRepository.cloneUrl)}</dd>
                    <dd className="mt-2 break-all font-mono text-cyan-200">git -c http.extraHeader=&quot;Authorization: Basic ...&quot; push</dd>
                  </div>
                </dl>
              ) : null}
            </div>
          </Panel>
        ) : null}
      </div>
    </div>
  );
}
