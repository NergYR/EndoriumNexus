const stateStyles: Record<string, string> = {
  healthy: "border-emerald-200 bg-emerald-50 text-emerald-700",
  degraded: "border-amber-200 bg-amber-50 text-amber-700",
  disabled: "border-slate-200 bg-slate-100 text-slate-600",
  offline: "border-rose-200 bg-rose-50 text-rose-700"
};

export function ServiceBadge({ state }: { state: string }) {
  return (
    <span
      className={[
        "inline-flex rounded-full border px-3 py-1 text-xs font-medium uppercase tracking-[0.16em]",
        stateStyles[state] ?? "border-slate-200 bg-slate-100 text-slate-600"
      ].join(" ")}
    >
      {state}
    </span>
  );
}

