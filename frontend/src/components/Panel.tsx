import type { PropsWithChildren, ReactNode } from "react";

export function Panel({
  title,
  eyebrow,
  actions,
  children
}: PropsWithChildren<{ title: string; eyebrow?: string; actions?: ReactNode }>) {
  return (
    <section className="glow-panel overflow-hidden rounded-3xl p-5">
      <div className="relative z-10 flex items-start justify-between gap-4">
        <div>
          {eyebrow ? <p className="text-xs uppercase tracking-[0.28em] text-cyan-200/55">{eyebrow}</p> : null}
          <h2 className="mt-2 text-xl font-semibold text-slate-100">{title}</h2>
        </div>
        {actions}
      </div>
      <div className="relative z-10 mt-5">{children}</div>
    </section>
  );
}

