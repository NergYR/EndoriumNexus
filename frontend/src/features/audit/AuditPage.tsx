import { Panel } from "../../components/Panel";
import { useAuditEvents } from "../../lib/api";

export function AuditPage() {
  const audit = useAuditEvents();

  if (audit.isLoading || !audit.data) {
    return <div className="text-sm text-slate-500">Chargement du journal...</div>;
  }

  return (
    <Panel title="Audit Log" eyebrow="Traceability">
      <div className="space-y-3">
        {audit.data.map((event) => (
          <article className="rounded-2xl border border-slate-200 bg-white px-4 py-4" key={event.happenedAt + event.action}>
            <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="font-medium text-slate-900">{event.action}</p>
                <p className="mt-1 text-sm text-slate-600">{event.detail}</p>
              </div>
              <div className="text-xs uppercase tracking-[0.16em] text-slate-500">
                {event.domain}
              </div>
            </div>
            <p className="mt-3 text-xs uppercase tracking-[0.16em] text-slate-500">
              {event.actor} • {event.happenedAt}
            </p>
          </article>
        ))}
      </div>
    </Panel>
  );
}

