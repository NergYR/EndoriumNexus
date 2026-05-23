import type { PropsWithChildren, ReactNode } from "react";

type WizardStep = {
  id: string;
  title: string;
  description: string;
};

export function Wizard({
  title,
  steps,
  currentStep,
  children,
  actions,
  error
}: PropsWithChildren<{
  title: string;
  steps: WizardStep[];
  currentStep: number;
  actions?: ReactNode;
  error?: string | null;
}>) {
  return (
    <div className="rounded-3xl border border-slate-700/70 bg-slate-950/80">
      <div className="border-b border-slate-700/70 px-4 py-4">
        <p className="text-xs uppercase tracking-[0.22em] text-slate-400">Guided wizard</p>
        <h3 className="mt-2 text-lg font-semibold text-slate-50">{title}</h3>
      </div>

      <div className="grid gap-4 p-4 lg:grid-cols-[220px_1fr]">
        <ol className="space-y-2">
          {steps.map((step, index) => (
            <li
              className={[
                "rounded-2xl border px-3 py-3",
                index === currentStep
                  ? "border-cyan-400/30 bg-cyan-400/10"
                  : index < currentStep
                    ? "border-emerald-400/30 bg-emerald-400/10"
                    : "border-slate-700 bg-slate-900/50"
              ].join(" ")}
              key={step.id}
            >
              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Step {index + 1}</p>
              <p className="mt-1 text-sm font-medium text-slate-50">{step.title}</p>
              <p className="mt-1 text-xs text-slate-400">{step.description}</p>
            </li>
          ))}
        </ol>

        <div className="min-w-0">
          {children}
          {error ? <p className="mt-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</p> : null}
          {actions ? <div className="mt-4 flex flex-wrap gap-3">{actions}</div> : null}
        </div>
      </div>
    </div>
  );
}

export function AdvancedSection({ title, children }: PropsWithChildren<{ title?: string }>) {
  return (
    <details className="rounded-2xl border border-slate-700/70 bg-slate-950/55 p-4">
      <summary className="cursor-pointer text-sm font-medium text-slate-50">
        {title ?? "Advanced options"}
      </summary>
      <div className="mt-4 grid gap-3">{children}</div>
    </details>
  );
}

export function WizardSummary({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="grid gap-2 rounded-2xl border border-slate-700/70 bg-slate-950/70 p-4 text-sm">
      {items.map((item) => (
        <div className="grid gap-1 border-b border-slate-700/70 pb-2 last:border-b-0 last:pb-0" key={item.label}>
          <dt className="text-xs uppercase tracking-[0.16em] text-slate-400">{item.label}</dt>
          <dd className="break-all text-slate-50">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}
