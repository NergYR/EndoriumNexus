export function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="glow-panel rounded-3xl p-5">
      <p className="relative z-10 text-xs uppercase tracking-[0.2em] text-slate-400">{label}</p>
      <p className="relative z-10 mt-3 text-4xl font-semibold text-slate-50">{value}</p>
    </div>
  );
}

