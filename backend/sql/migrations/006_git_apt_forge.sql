create table if not exists vcs_access_tokens (
    id uuid primary key default gen_random_uuid(),
    repository_id uuid not null references vcs_repositories(id) on delete cascade,
    name text not null,
    token_hash text not null unique,
    token_prefix text not null,
    scope text not null check (scope in ('read', 'write')),
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked boolean not null default false,
    created_at timestamptz not null default now()
);

create index if not exists vcs_access_tokens_repository_idx on vcs_access_tokens(repository_id);
create index if not exists vcs_access_tokens_hash_idx on vcs_access_tokens(token_hash);

create table if not exists vcs_events (
    id bigserial primary key,
    repository_id uuid not null references vcs_repositories(id) on delete cascade,
    actor text not null,
    action text not null,
    detail text not null default '',
    ref_name text not null default '',
    old_oid text not null default '',
    new_oid text not null default '',
    happened_at timestamptz not null default now()
);

create index if not exists vcs_events_repository_happened_idx on vcs_events(repository_id, happened_at desc);

alter table repo_packages
    add column if not exists storage_path text,
    add column if not exists control_json jsonb not null default '{}'::jsonb,
    add column if not exists uploaded_by text not null default 'system',
    add column if not exists uploaded_at timestamptz not null default now();

update repo_packages
set
    storage_path = coalesce(storage_path, filename),
    control_json = coalesce(control_json, '{}'::jsonb),
    uploaded_by = coalesce(uploaded_by, 'system'),
    uploaded_at = coalesce(uploaded_at, now());

create table if not exists repo_signing_keys (
    fingerprint text primary key,
    public_key text not null,
    active boolean not null default true,
    created_at timestamptz not null default now()
);

create index if not exists repo_packages_distribution_component_idx
    on repo_packages(distribution, component);

insert into audit_events (actor, domain, action, detail)
values ('system', 'Platform', 'Migrate', 'Applied 006_git_apt_forge.sql');
