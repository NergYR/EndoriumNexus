import { useEffect } from "react";
import { QueryClient, QueryClientProvider, useQueryClient } from "@tanstack/react-query";
import { BrowserRouter, Navigate, NavLink, Route, Routes } from "react-router-dom";

import { AuditPage } from "../features/audit/AuditPage";
import { DashboardPage } from "../features/dashboard/DashboardPage";
import { DhcpPage } from "../features/dhcp/DhcpPage";
import { DirectoryPage } from "../features/directory/DirectoryPage";
import { DnsPage } from "../features/dns/DnsPage";
import { LoginPage } from "../features/settings/LoginPage";
import { PkiPage } from "../features/pki/PkiPage";
import { ReposPage } from "../features/repos/ReposPage";
import { SettingsPage } from "../features/settings/SettingsPage";
import { SetupWizardPage } from "../features/setup/SetupWizardPage";
import { useAuth } from "../lib/api";

const queryClient = new QueryClient();

const navItems = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/setup", label: "Setup Wizard" },
  { to: "/directory", label: "Active Directory" },
  { to: "/dns", label: "DNS Zones" },
  { to: "/dhcp", label: "DHCP Pools" },
  { to: "/pki", label: "PKI Revocations" },
  { to: "/repos", label: "APT Repositories" },
  { to: "/audit", label: "Audit Log" },
  { to: "/settings", label: "Control Room" }
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
      void queryClient.invalidateQueries({ queryKey: ["ad-domain"] });
      void queryClient.invalidateQueries({ queryKey: ["ad-readiness"] });
      void queryClient.invalidateQueries({ queryKey: ["ad-join-guide"] });
      void queryClient.invalidateQueries({ queryKey: ["jobs"] });
      void queryClient.invalidateQueries({ queryKey: ["audit"] });
      void queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
      void queryClient.invalidateQueries({ queryKey: ["dhcp-pools"] });
      void queryClient.invalidateQueries({ queryKey: ["directory"] });
      void queryClient.invalidateQueries({ queryKey: ["pki-authorities"] });
      void queryClient.invalidateQueries({ queryKey: ["pki-certificates"] });
      void queryClient.invalidateQueries({ queryKey: ["pki-revocations"] });
      void queryClient.invalidateQueries({ queryKey: ["repos"] });
    };

    stream.addEventListener("state-changed", handleStateChanged);

    return () => {
      stream.removeEventListener("state-changed", handleStateChanged);
      stream.close();
    };
  }, [auth.data, queryClient]);

  if (auth.isLoading) {
    return (
      <div className="grid min-h-screen place-items-center">
        <div className="glow-panel rounded-3xl px-8 py-6 text-sm text-slate-200">
          Loading Endorium Nexus...
        </div>
      </div>
    );
  }

  if (auth.isError || !auth.data) {
    return <LoginPage />;
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-[260px_1fr]">
      <aside className="border-r border-white/5 bg-slate-950/70 px-5 py-6">
        <div className="glow-panel grid-sheen rounded-3xl p-5">
          <p className="text-xs uppercase tracking-[0.32em] text-cyan-200/70">Endorium</p>
          <h1 className="mt-3 text-3xl font-semibold text-accent">Nexus</h1>
          <p className="mt-3 text-sm text-slate-400">
            Unified control plane for directory, network, PKI and repository services.
          </p>
        </div>

        <nav className="mt-6 space-y-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              className={({ isActive }) =>
                [
                  "block rounded-2xl border px-4 py-3 text-sm transition",
                  isActive
                    ? "border-cyan-300/30 bg-cyan-300/10 text-cyan-100 shadow-[0_0_28px_rgba(63,255,255,0.09)]"
                    : "border-transparent bg-white/3 text-slate-300 hover:border-blue-300/20 hover:bg-white/6"
                ].join(" ")
              }
              to={item.to}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <main className="px-4 py-4 md:px-8 md:py-6">
        <header className="mb-6 flex flex-col gap-3 rounded-3xl border border-white/6 bg-black/20 px-5 py-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-cyan-200/60">Operations Console</p>
            <p className="mt-2 text-sm text-slate-400">
              Signed in as <span className="text-slate-100">{auth.data.email}</span>
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {auth.data.roles.map((role) => (
              <span
                className="rounded-full border border-blue-300/20 bg-blue-400/10 px-3 py-1 text-xs uppercase tracking-[0.18em] text-blue-100"
                key={role}
              >
                {role}
              </span>
            ))}
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
