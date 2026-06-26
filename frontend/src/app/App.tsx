import { useEffect } from "react";
import { QueryClient, QueryClientProvider, useQueryClient } from "@tanstack/react-query";
import { BrowserRouter, Navigate, NavLink, Route, Routes } from "react-router-dom";

import { AuditPage } from "../features/audit/AuditPage";
import { DashboardPage } from "../features/dashboard/DashboardPage";
import { DhcpPage } from "../features/dhcp/DhcpPage";
import { DirectoryPage } from "../features/directory/DirectoryPage";
import { DnsPage } from "../features/dns/DnsPage";
import { SetupWizardPage } from "../features/setup/SetupWizardPage";
import { LoginPage } from "../features/settings/LoginPage";
import { PkiPage } from "../features/pki/PkiPage";
import { ReposPage } from "../features/repos/ReposPage";
import { SettingsPage } from "../features/settings/SettingsPage";
import { VcsPage } from "../features/vcs/VcsPage";
import { useAuth } from "../lib/api";

const queryClient = new QueryClient();

const navItems = [
  { to: "/dashboard", label: "Vue d'ensemble" },
  { to: "/directory", label: "Annuaire" },
  { to: "/dns", label: "DNS" },
  { to: "/dhcp", label: "DHCP" },
  { to: "/pki", label: "PKI" },
  { to: "/repos", label: "Dépôts APT" },
  { to: "/vcs", label: "Serveur Git" },
  { to: "/audit", label: "Journal" },
  { to: "/settings", label: "Réglages" }
];

function Shell() {
  const auth = useAuth();
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!auth.data) {
      return;
    }

    const stream = new EventSource("/api/v1/dashboard/stream");
    const handleStateChanged = () => {
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      void queryClient.invalidateQueries({ queryKey: ["jobs"] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
      void queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
      void queryClient.invalidateQueries({ queryKey: ["pki-revocations"] });
    };

    stream.addEventListener("state-changed", handleStateChanged);

    return () => {
      stream.removeEventListener("state-changed", handleStateChanged);
      stream.close();
    };
  }, [auth.data, queryClient]);

  if (auth.isLoading) {
    return (
      <div className="grid min-h-screen place-items-center px-4">
        <div className="glow-panel rounded-3xl px-8 py-6 text-sm text-slate-300">
          Loading Endorium Nexus...
        </div>
      </div>
    );
  }

  if (auth.isError || !auth.data) {
    return <LoginPage />;
  }

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-slate-700/60 bg-slate-950/85 px-4 py-4 backdrop-blur md:px-8">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-4">
            <div className="glow-panel grid-sheen rounded-2xl px-4 py-3">
              <p className="text-xs uppercase tracking-[0.28em] text-slate-400">Endorium</p>
              <h1 className="mt-2 text-lg font-semibold text-slate-50">Nexus</h1>
            </div>
            <p className="hidden text-sm text-slate-400 md:block">Console d'administration pour les services essentiels.</p>
          </div>

          <nav className="flex flex-wrap gap-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              className={({ isActive }) =>
                [
                  "rounded-full border px-4 py-2 text-sm transition",
                  isActive
                    ? "border-cyan-400/30 bg-cyan-400/10 text-slate-50"
                    : "border-slate-700 bg-slate-900/60 text-slate-300 hover:border-slate-600 hover:bg-slate-800"
                ].join(" ")
              }
              to={item.to}
            >
              {item.label}
            </NavLink>
          ))}
          </nav>
        </div>
      </header>

      <main className="px-4 py-4 md:px-8 md:py-6">
        <header className="mb-6 flex flex-col gap-3 rounded-3xl border border-slate-700/60 bg-slate-950/80 px-5 py-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.26em] text-slate-400">Console d'administration</p>
            <p className="mt-2 text-sm text-slate-300">
              Connecté en tant que <span className="text-slate-50">{auth.data.email}</span>
            </p>
          </div>
        </header>

        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/setup" element={<SetupWizardPage />} />
          <Route path="/directory" element={<DirectoryPage />} />
          <Route path="/dns" element={<DnsPage />} />
          <Route path="/dhcp" element={<DhcpPage />} />
          <Route path="/pki" element={<PkiPage />} />
          <Route path="/repos" element={<ReposPage />} />
          <Route path="/vcs" element={<VcsPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  );
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Shell />
      </BrowserRouter>
    </QueryClientProvider>
  );
}
