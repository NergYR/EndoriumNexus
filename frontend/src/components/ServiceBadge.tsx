const stateStyles: Record<string, string> = {
  healthy: "border-cyan-300/30 bg-cyan-300/10 text-cyan-100",
  degraded: "border-amber-300/30 bg-amber-300/10 text-amber-100",
  disabled: "border-slate-300/20 bg-slate-300/10 text-slate-100",
  offline: "border-rose-300/30 bg-rose-300/10 text-rose-100"
};

export function ServiceBadge({ state }: { state: string }) {
  return (
    <span
      className={[
        "inline-flex rounded-full border px-3 py-1 text-xs font-medium uppercase tracking-[0.18em]",
        stateStyles[state] ?? "border-slate-300/20 bg-slate-300/10 text-slate-100"
      ].join(" ")}
    >
      {state}
    </span>
  );
}

