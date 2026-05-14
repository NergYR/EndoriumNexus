import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import type {
  ActiveDirectoryDomain,
  ActiveDirectoryDomainCreatePayload,
  ActiveDirectoryJoinGuide,
  ActiveDirectoryReadiness,
  AptRepository,
  AptPackagePayload,
  AuditEvent,
  AuthSession,
  DashboardSnapshot,
  DhcpPoolCreatePayload,
  DhcpPoolUpdatePayload,
  DhcpPool,
  DirectoryObject,
  DirectoryObjectPayload,
  FeatureFlagEntry,
  DnsRecordCreatePayload,
  DnsRecordUpdatePayload,
  DnsZone,
  DnsZoneUpdatePayload,
  JobSummary,
  PkiAuthority,
  PkiAuthorityCreatePayload,
  PkiCertificate,
  PkiCertificateCreatePayload,
  PkiRevocation,
  ServiceStatus,
  SettingsSnapshot,
  SettingsUpdatePayload
} from "./types";

const CSRF_STORAGE_KEY = "endorium.csrf";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const csrf = sessionStorage.getItem(CSRF_STORAGE_KEY);
  if (csrf && init?.method && init.method !== "GET") {
    headers.set("X-CSRF-Token", csrf);
  }

  const response = await fetch(path, {
    ...init,
    credentials: "include",
    headers
  });

  if (response.status === 401) {
    throw new Error("unauthorized");
  }

  if (!response.ok) {
    const payload = (await response.json().catch(() => ({ error: "request failed" }))) as {
      error?: string;
    };
    throw new Error(payload.error ?? "request failed");
  }

  return (await response.json()) as T;
}

export function useAuth() {
  return useQuery<AuthSession>({
    queryKey: ["auth"],
    queryFn: () => request<AuthSession>("/api/v1/auth/me"),
    retry: false
  });
}

export function useLogin() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { email: string; password: string; totp: string }) =>
      request<{ email: string; roles: string[]; csrfToken: string }>("/api/v1/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: (data) => {
      sessionStorage.setItem(CSRF_STORAGE_KEY, data.csrfToken);
      void queryClient.invalidateQueries({ queryKey: ["auth"] });
    }
  });
}

export function useDashboard() {
  return useQuery<DashboardSnapshot>({
    queryKey: ["dashboard"],
    queryFn: () => request<DashboardSnapshot>("/api/v1/dashboard")
  });
}

export function useServices() {
  return useQuery<ServiceStatus[]>({
    queryKey: ["services"],
    queryFn: () => request<ServiceStatus[]>("/api/v1/services")
  });
}

export function useDirectoryObjects() {
  return useQuery<DirectoryObject[]>({
    queryKey: ["directory"],
    queryFn: () => request<DirectoryObject[]>("/api/v1/directory/objects")
  });
}

export function useActiveDirectoryDomain() {
  return useQuery<ActiveDirectoryDomain | null>({
    queryKey: ["ad-domain"],
    queryFn: async () => {
      try {
        return await request<ActiveDirectoryDomain>("/api/v1/ad/domain");
      } catch (error) {
        if (error instanceof Error && error.message.includes("active directory domain is not configured")) {
          return null;
        }
        throw error;
      }
    }
  });
}

export function useActiveDirectoryReadiness() {
  return useQuery<ActiveDirectoryReadiness>({
    queryKey: ["ad-readiness"],
    queryFn: () => request<ActiveDirectoryReadiness>("/api/v1/ad/readiness")
  });
}

export function useActiveDirectoryJoinGuide() {
  return useQuery<ActiveDirectoryJoinGuide>({
    queryKey: ["ad-join-guide"],
    queryFn: () => request<ActiveDirectoryJoinGuide>("/api/v1/ad/join-guide")
  });
}

export function useCreateActiveDirectoryDomain() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ActiveDirectoryDomainCreatePayload) =>
      request<{ ok: boolean; domain: ActiveDirectoryDomain }>("/api/v1/ad/domain", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["ad-domain"] });
      await queryClient.invalidateQueries({ queryKey: ["ad-readiness"] });
      await queryClient.invalidateQueries({ queryKey: ["ad-join-guide"] });
      await queryClient.invalidateQueries({ queryKey: ["directory"] });
      await queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useCreateDirectoryObject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: DirectoryObjectPayload) =>
      request<{ ok: boolean; dn: string }>("/api/v1/directory/objects", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["directory"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useUpdateDirectoryObject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { dn: string; object: DirectoryObjectPayload }) =>
      request<{ ok: boolean; dn: string }>(`/api/v1/directory/objects/${encodeURIComponent(payload.dn)}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload.object)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["directory"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useDeleteDirectoryObject() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { dn: string }) =>
      request<{ ok: boolean }>(`/api/v1/directory/objects/${encodeURIComponent(payload.dn)}`, {
        method: "DELETE"
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["directory"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useDnsZones() {
  return useQuery<DnsZone[]>({
    queryKey: ["dns-zones"],
    queryFn: () => request<DnsZone[]>("/api/v1/dns/zones")
  });
}

export function useZoneRender(zoneName?: string) {
  return useQuery<{ zone: string; text: string }>({
    queryKey: ["dns-zone-render", zoneName],
    queryFn: () => request<{ zone: string; text: string }>(`/api/v1/dns/zones/${zoneName}/render`),
    enabled: Boolean(zoneName)
  });
}

export function useCreateDnsRecord() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { zoneName: string; record: DnsRecordCreatePayload }) =>
      request<{ ok: boolean }>("/api/v1/dns/zones/" + payload.zoneName + "/records", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload.record)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useUpdateDnsZone() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { zoneName: string; zone: DnsZoneUpdatePayload }) =>
      request<{ ok: boolean; zone: string }>(`/api/v1/dns/zones/${payload.zoneName}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload.zone)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useDeleteDnsZone() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { zoneName: string }) =>
      request<{ ok: boolean }>(`/api/v1/dns/zones/${payload.zoneName}`, {
        method: "DELETE"
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useUpdateDnsRecord() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { zoneName: string; index: number; record: DnsRecordUpdatePayload }) =>
      request<{ ok: boolean }>(`/api/v1/dns/zones/${payload.zoneName}/records/${payload.index}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload.record)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useDeleteDnsRecord() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { zoneName: string; index: number }) =>
      request<{ ok: boolean }>(`/api/v1/dns/zones/${payload.zoneName}/records/${payload.index}`, {
        method: "DELETE"
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useCreateDnsZone() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { name: string }) =>
      request<{ ok: boolean; zone: string }>("/api/v1/dns/zones", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dns-zones"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useDhcpPools() {
  return useQuery<DhcpPool[]>({
    queryKey: ["dhcp-pools"],
    queryFn: () => request<DhcpPool[]>("/api/v1/dhcp/pools")
  });
}

export function useCreateDhcpPool() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: DhcpPoolCreatePayload) =>
      request<{ ok: boolean; pool: string }>("/api/v1/dhcp/pools", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dhcp-pools"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useUpdateDhcpPool() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { poolName: string; pool: DhcpPoolUpdatePayload }) =>
      request<{ ok: boolean; pool: string }>(`/api/v1/dhcp/pools/${payload.poolName}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload.pool)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dhcp-pools"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useDeleteDhcpPool() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { poolName: string }) =>
      request<{ ok: boolean }>(`/api/v1/dhcp/pools/${payload.poolName}`, {
        method: "DELETE"
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dhcp-pools"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useRevocations() {
  return useQuery<PkiRevocation[]>({
    queryKey: ["pki-revocations"],
    queryFn: () => request<PkiRevocation[]>("/api/v1/pki/revocations")
  });
}

export function usePkiAuthorities() {
  return useQuery<PkiAuthority[]>({
    queryKey: ["pki-authorities"],
    queryFn: () => request<PkiAuthority[]>("/api/v1/pki/authorities")
  });
}

export function useCreatePkiAuthority() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: PkiAuthorityCreatePayload) =>
      request<{ ok: boolean; authority: string }>("/api/v1/pki/authorities", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["pki-authorities"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      await queryClient.invalidateQueries({ queryKey: ["services"] });
    }
  });
}

export function usePkiCertificates() {
  return useQuery<PkiCertificate[]>({
    queryKey: ["pki-certificates"],
    queryFn: () => request<PkiCertificate[]>("/api/v1/pki/certificates")
  });
}

export function useCreatePkiCertificate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: PkiCertificateCreatePayload) =>
      request<{ ok: boolean }>("/api/v1/pki/certificates", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["pki-certificates"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useCreateRevocation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { serial: string; commonName: string; reason: string }) =>
      request<{ ok: boolean }>("/api/v1/pki/revocations", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["pki-revocations"] });
      await queryClient.invalidateQueries({ queryKey: ["pki-certificates"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useRepositories() {
  return useQuery<AptRepository[]>({
    queryKey: ["repos"],
    queryFn: () => request<AptRepository[]>("/api/v1/repos")
  });
}

export function useCreateRepository() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { distribution: string; component: string }) =>
      request<{ ok: boolean }>("/api/v1/repos", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repos"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      await queryClient.invalidateQueries({ queryKey: ["services"] });
    }
  });
}

export function useDeleteRepository() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { distribution: string; component: string }) =>
      request<{ ok: boolean }>(`/api/v1/repos/${payload.distribution}/${payload.component}`, {
        method: "DELETE"
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repos"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useCreateRepositoryPackage() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { distribution: string; component: string; package: AptPackagePayload }) =>
      request<{ ok: boolean }>(`/api/v1/repos/${payload.distribution}/${payload.component}/packages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload.package)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repos"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useUpdateRepositoryPackage() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { distribution: string; component: string; index: number; package: AptPackagePayload }) =>
      request<{ ok: boolean }>(`/api/v1/repos/${payload.distribution}/${payload.component}/packages/${payload.index}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload.package)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repos"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useDeleteRepositoryPackage() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { distribution: string; component: string; index: number }) =>
      request<{ ok: boolean }>(`/api/v1/repos/${payload.distribution}/${payload.component}/packages/${payload.index}`, {
        method: "DELETE"
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repos"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    }
  });
}

export function useRepositoryRender(distribution?: string, component?: string, kind: "packages" | "release" = "packages") {
  return useQuery<{ text: string }>({
    queryKey: ["repo-render", distribution, component, kind],
    queryFn: () => request<{ text: string }>(`/api/v1/repos/${distribution}/${component}/render/${kind}`),
    enabled: Boolean(distribution && component)
  });
}

export function useAuditEvents() {
  return useQuery<AuditEvent[]>({
    queryKey: ["audit"],
    queryFn: () => request<AuditEvent[]>("/api/v1/audit")
  });
}

export function useJobs() {
  return useQuery<JobSummary[]>({
    queryKey: ["jobs"],
    queryFn: () => request<JobSummary[]>("/api/v1/jobs")
  });
}

export function useSettings() {
  return useQuery<SettingsSnapshot>({
    queryKey: ["settings"],
    queryFn: () => request<SettingsSnapshot>("/api/v1/settings")
  });
}

export function useFeatureFlags() {
  return useQuery<FeatureFlagEntry[]>({
    queryKey: ["feature-flags"],
    queryFn: () => request<FeatureFlagEntry[]>("/api/v1/feature-flags")
  });
}

export function useUpdateFeatureFlags() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { features: Record<string, boolean> }) =>
      request<{ ok: boolean; features: Array<{ serviceId: string; enabled: boolean }> }>("/api/v1/feature-flags", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["feature-flags"] });
      await queryClient.invalidateQueries({ queryKey: ["settings"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      await queryClient.invalidateQueries({ queryKey: ["services"] });
    }
  });
}

export function useUpdateSettings() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: SettingsUpdatePayload) =>
      request<SettingsSnapshot & { ok: boolean }>("/api/v1/settings", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["settings"] });
      await queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      await queryClient.invalidateQueries({ queryKey: ["auth"] });
    }
  });
}

export function useRestartDnsService() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      request<{ ok: boolean }>("/api/v1/dns/restart", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        }
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dns"] });
    }
  });
}

export function useRestartDhcpService() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      request<{ ok: boolean }>("/api/v1/dhcp/restart", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        }
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["dhcp"] });
    }
  });
}
