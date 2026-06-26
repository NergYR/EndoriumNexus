export interface AuthSession {
  email: string;
  roles: string[];
}

export interface ServiceStatus {
  id: string;
  label: string;
  state: string;
  summary: string;
  endpoints: string[];
  capabilities: string[];
  critical: boolean;
  enabled?: boolean;

  blockingReason?: string;
}
export interface DashboardSnapshot {
  services: ServiceStatus[];
  directoryObjects: number;
  dnsRecords: number;
  dhcpLeases: number;
  pendingJobs: number;
  pkiRevocations: number;
  repoPackages: number;
  jobs: JobSummary[];
  audit: AuditEvent[];
}

export interface FeatureFlagEntry {
  serviceId: string;
  label: string;
  featureFlag: string;
  priority: number;
  critical: boolean;
  enabled: boolean;
}

export interface DirectoryObject {
  dn: string;
  parentDn: string;
  kind: string;
  objectClasses: string[];
  attributes: Record<string, string>;
}

export interface DirectoryObjectPayload extends DirectoryObject {
  password?: string;
}

export interface ActiveDirectoryAttributeValue {
  value: string;
  encoding: "utf8" | "uuid" | "sddl" | "decimal" | "base64" | string;
}

export interface ActiveDirectoryAttribute {
  name: string;
  type: "string" | "guid" | "sid" | "integer" | "security-descriptor" | string;
  multiValued: boolean;
  values: ActiveDirectoryAttributeValue[];
}

export interface ActiveDirectoryObject {
  objectGuid: string;
  domainDnsName: string;
  dn: string;
  parentDn: string;
  rdn: string;
  kind: string;
  objectSid: string;
  rid: number;
  uSNCreated: number;
  uSNChanged: number;
  whenCreated: string;
  whenChanged: string;
  objectClasses: string[];
  attributes: Record<string, ActiveDirectoryAttribute>;
}

export interface DnsRecord {
  name: string;
  type: string;
  value: string;
  class?: string;
  ttl: number;
  priority: number;
  weight?: number;
  port?: number;
  flags?: string;
}

export interface DnsZone {
  name: string;
  serial: number;
  records: DnsRecord[];
}

export interface DnsZoneCreatePayload {
  name: string;
}

export interface DnsZoneUpdatePayload {
  name: string;
}

export interface DnsRecordCreatePayload {
  name: string;
  type: string;
  value: string;
  class?: string;
  ttl: number;
  priority: number;
  weight?: number;
  port?: number;
  flags?: string;
}

export type DnsRecordUpdatePayload = DnsRecordCreatePayload;

export interface DhcpLease {
  ipAddress: string;
  clientId: string;
  hostname: string;
  state: string;
  expiresAt: string;
}

export interface DhcpPool {
  name: string;
  subnet: string;
  rangeStart: string;
  rangeEnd: string;
  options: Record<string, string>;
  leases: DhcpLease[];
}

export interface DhcpPoolCreatePayload {
  name: string;
  subnet: string;
  rangeStart: string;
  rangeEnd: string;
  options: Record<string, string>;
}

export type DhcpPoolUpdatePayload = DhcpPoolCreatePayload;

export interface ActiveDirectoryDomainSnapshot {
  dnsName: string;
  netbiosName: string;
  realm: string;
  baseDn: string;
  domainSid: string;
  domainControllerHost: string;
  domainControllerAddress: string;
}

export interface ActiveDirectoryDomainCreatePayload {
  dnsName: string;
  netbiosName: string;
  baseDn: string;
  adminSamAccount: string;
  adminDisplayName: string;
  adminPassword: string;
  domainControllerHost: string;
  domainControllerAddress: string;
}

export interface ActiveDirectoryReadinessItem {
  id: string;
  label: string;
  category: string;
  detail: string;
  ready: boolean;
  blocking: boolean;
}

export interface ActiveDirectoryReadiness {
  supported: boolean;
  dnsName: string;
  realm: string;
  baseDn: string;
  items: ActiveDirectoryReadinessItem[];
}

export interface ActiveDirectoryJoinGuide {
  message: string;
}

export interface PkiRevocation {
  serial: string;
  commonName: string;
  reason: string;
  revokedAt: string;
}

export interface PkiInsight {
  category: string;
  title: string;
  detail: string;
  severity: string;
}

export interface PkiAssistantSnapshot {
  recommendedMode: string;
  recommendedProfileId: string;
  headline: string;
  insights: PkiInsight[];
  authorityCount: number;
  certificateCount: number;
  revocationCount: number;
  leafDaysValid: number;
}

export interface PkiAuthority {
  name: string;
  commonName: string;
  organization: string;
  serial: string;
  certificatePem: string;
  privateKeyPem: string;
  createdAt: string;
}

export interface PkiCertificate {
  serial: string;
  authorityName: string;
  commonName: string;
  organization: string;
  sans: string[];
  certificatePem: string;
  privateKeyPem: string;
  revoked: boolean;
  createdAt: string;
}

export interface PkiAuthorityCreatePayload {
  name: string;
  commonName: string;
  organization: string;
  sans: string[];
  daysValid: number;
}

export interface PkiCertificateCreatePayload {
  authorityName: string;
  commonName: string;
  organization: string;
  sans: string[];
  daysValid: number;
}

export interface AptPackage {
  id: string;
  name: string;
  version: string;
  architecture: string;
  component: string;
  filename: string;
  storagePath: string;
  sha256: string;
  size: number;
  controlJson: string;
  uploadedBy: string;
  uploadedAt: string;
  downloadUrl: string;
}

export interface AptPackagePayload {
  name: string;
  version: string;
  architecture: string;
  filename: string;
  sha256: string;
  size: number;
}

export interface AptRepository {
  distribution: string;
  component: string;
  packages: AptPackage[];
}

export interface VcsRepository {
  id: string;
  name: string;
  description: string;
  isPrivate: boolean;
  is_private?: boolean;
  httpPushEnabled: boolean;
  defaultBranch: string;
  createdAt: string;
  created_at?: string;
  updatedAt: string;
  storageReady: boolean;
  headTarget: string;
  cloneUrl: string;
  pushUrl: string;
}

export interface VcsRepositoryCreatePayload {
  name: string;
  description: string;
  isPrivate: boolean;
  httpPushEnabled: boolean;
  defaultBranch: string;
}

export interface VcsRepositoryUpdatePayload {
  description?: string;
  isPrivate?: boolean;
  httpPushEnabled?: boolean;
  defaultBranch?: string;
}

export interface VcsRef {
  name: string;
  shortName: string;
  type: "branch" | "tag" | "ref";
  objectId: string;
}

export interface VcsAccessToken {
  id: string;
  repositoryId: string;
  repositoryName: string;
  name: string;
  scope: "read" | "write";
  tokenPrefix: string;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string;
  revoked: boolean;
}

export interface VcsAccessTokenCreatePayload {
  name: string;
  scope: "read" | "write";
  expiresAt?: string;
}

export interface VcsAccessTokenCreateResponse {
  token: VcsAccessToken;
  secret: string;
}

export interface VcsEvent {
  id: number;
  repositoryId: string;
  repositoryName: string;
  actor: string;
  action: string;
  detail: string;
  refName: string;
  oldOid: string;
  newOid: string;
  happenedAt: string;
}

export interface AuditEvent {
  happenedAt: string;
  actor: string;
  domain: string;
  action: string;
  detail: string;
}

export interface JobSummary {
  id: string;
  domain: string;
  status: string;
  description: string;
  submittedAt: string;
}

export interface SettingsSnapshot {
  environment: string;
  domain: string;
  adPortProfile?: string;
  blobRoot: string;
  stateRoot: string;
  databaseConfigured: boolean;
  databaseUrl: string;
  adminEmail: string;
  adminPasswordHash: string;
  adminTotpSecret: string;
  ports: {
    http: number;
    ldap: number;
    ldaps: number;
    gc: number;
    kerberos: number;
    kpasswd: number;
    rpc: number;
    smb: number;
    dnsTcp: number;
    dnsUdp: number;
    dhcp: number;
  };
  directory: {
    baseDn: string;
    organization: string;
    realm: string;
    siteName: string;
    domainControllerHost: string;
    domainControllerAddress: string;
    keyEncryptionKeyFile?: string;
  };
  dns: {
    primaryNs: string;
    adminMailbox: string;
    defaultTtl: number;
  };
  dhcp: {
    subnet: string;
    rangeStart: string;
    rangeEnd: string;
    router: string;
  };
  pki: {
    organization: string;
    commonName: string;
    leafDaysValid: number;
  };
  repo: {
    origin: string;
    distribution: string;
    component: string;
  };
  features?: Record<string, boolean>;
}

export interface SettingsUpdatePayload {
  environment: string;
  domain: string;
  adPortProfile?: string;
  blobRoot: string;
  stateRoot: string;
  databaseUrl: string;
  adminEmail: string;
  adminPasswordHash: string;
  adminTotpSecret: string;
  httpPort: number;
  ldapPort: number;
  ldapsPort: number;
  gcPort: number;
  kerberosPort: number;
  kpasswdPort: number;
  rpcPort: number;
  smbPort: number;
  dnsTcpPort: number;
  dnsUdpPort: number;
  dhcpPort: number;
  directory: {
    baseDn: string;
    organization: string;
    realm: string;
    siteName: string;
    domainControllerHost: string;
    domainControllerAddress: string;
    keyEncryptionKeyFile?: string;
  };
  dns: {
    primaryNs: string;
    adminMailbox: string;
    defaultTtl: number;
  };
  dhcp: {
    subnet: string;
    rangeStart: string;
    rangeEnd: string;
    router: string;
  };
  pki: {
    organization: string;
    commonName: string;
    leafDaysValid: number;
  };
  repo: {
    origin: string;
    distribution: string;
    component: string;
  };
  features?: Record<string, boolean>;
}
