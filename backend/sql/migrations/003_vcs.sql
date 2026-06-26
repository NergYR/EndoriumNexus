create table if not exists vcs_repositories (
    id uuid primary key default gen_random_uuid(),
    name text not null unique,
    description text default '',
    is_private boolean not null default true,
    http_push_enabled boolean not null default true,
    default_branch text not null default 'main',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists vcs_repositories_name_idx on vcs_repositories(name);

insert into audit_events (actor, domain, action, detail)
values ('system', 'Platform', 'Migrate', 'Applied 003_vcs.sql');
