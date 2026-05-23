import { Panel } from "../../components/Panel";
import { ServiceBadge } from "../../components/ServiceBadge";
import { StatCard } from "../../components/StatCard";
import { useDashboard } from "../../lib/api";
import { Link } from "react-router-dom";

export function DashboardPage() {
  const dashboard = useDashboard();

  if (dashboard.isLoading || !dashboard.data) {
    return <div className="text-sm text-slate-500">Chargement du tableau de bord...</div>;
  }

  return (
    <div className="space-y-6">
      {dashboard.data.services.some((service) => service.blockingReason || service.enabled === false) ? (
        <div className="rounded-3xl border border-amber-200 bg-amber-50 px-5 py-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-xs uppercase tracking-[0.2em] text-amber-700">Configuration requise</p>
              <p className="mt-2 text-sm text-slate-700">
                Quelques services doivent encore être configurés avant utilisation.
              </p>
            </div>
            <Link className="accent-gradient rounded-2xl px-4 py-3 text-sm font-medium text-white" to="/setup">
              Ouvrir l'assistant
            </Link>
          </div>
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Directory Objects" value={dashboard.data.directoryObjects} />
        <StatCard label="DNS Records" value={dashboard.data.dnsRecords} />
        <StatCard label="Pending Jobs" value={dashboard.data.pendingJobs} />
        <StatCard label="Repo Packages" value={dashboard.data.repoPackages} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.35fr_0.9fr]">
        <Panel title="Service State" eyebrow="Runtime Health">
          <div className="space-y-4">
            {dashboard.data.services.map((service) => (
              <article
                className={[
                  "rounded-2xl border px-4 py-4 transition",
                  service.enabled === false
                    ? "border-slate-200 bg-slate-50 opacity-80"
                    : "border-slate-200 bg-white"
                ].join(" ")}
                key={service.id}
              >
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-lg font-medium text-slate-900">{service.label}</h3>
                      <span className="rounded-full border border-slate-200 bg-slate-100 px-2.5 py-0.5 text-[10px] uppercase tracking-[0.16em] text-slate-600">
                        {service.enabled === false ? "Disabled" : "Enabled"}
                      </span>
                    </div>
                    <p className="mt-1 text-sm text-slate-600">{service.summary}</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {service.capabilities.map((capability) => (
                        <span
                          className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs uppercase tracking-[0.16em] text-slate-600"
                          key={capability}
                        >
                          {capability}
                        </span>
                      ))}
                    </div>
                  </div>
                  <ServiceBadge state={service.state} />
                </div>
              </article>
            ))}
          </div>
        </Panel>

        <div className="space-y-6">
          <Panel title="Recent Jobs" eyebrow="Schedulers">
            <div className="space-y-3">
              {dashboard.data.jobs.map((job) => (
                <div
                    className="rounded-2xl border border-slate-200 bg-white px-4 py-3"
                  key={job.id}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                        <p className="font-medium text-slate-900">{job.description}</p>
                        <p className="mt-1 text-xs uppercase tracking-[0.16em] text-slate-500">
                        {job.domain}
                      </p>
                    </div>
                    <ServiceBadge state={job.status === "done" ? "healthy" : "degraded"} />
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Audit Tail" eyebrow="Last Mutations">
            <div className="space-y-3">
              {dashboard.data.audit.map((event) => (
                <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3" key={event.happenedAt + event.action}>
                  <p className="font-medium text-slate-900">{event.action}</p>
                  <p className="mt-1 text-sm text-slate-600">{event.detail}</p>
                  <p className="mt-2 text-xs uppercase tracking-[0.16em] text-slate-500">
                    {event.actor} • {event.domain}
                  </p>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
