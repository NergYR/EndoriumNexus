import { useState, type ReactNode } from "react";

export type PropertyTab = {
  id: string;
  label: string;
  content: ReactNode;
};

export function ObjectPropertiesTabs({ tabs }: { tabs: PropertyTab[] }) {
  const [activeTab, setActiveTab] = useState(tabs[0]?.id ?? "");
  const active = tabs.find((tab) => tab.id === activeTab) ?? tabs[0];

  return (
    <div>
      <div className="flex flex-wrap gap-2 border-b border-white/8 pb-3">
        {tabs.map((tab) => (
          <button
            className={[
              "rounded-full border px-3 py-1 text-xs uppercase tracking-[0.16em] transition",
              active?.id === tab.id
                ? "border-cyan-300/30 bg-cyan-300/10 text-cyan-50"
                : "border-white/10 text-slate-300 hover:bg-white/5"
            ].join(" ")}
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div className="mt-4">{active?.content}</div>
    </div>
  );
}
