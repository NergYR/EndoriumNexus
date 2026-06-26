alter table vcs_repositories
    add column if not exists http_push_enabled boolean not null default true,
    add column if not exists default_branch text not null default 'main',
    add column if not exists updated_at timestamptz not null default now();

update vcs_repositories
set
    description = coalesce(description, ''),
    default_branch = coalesce(nullif(default_branch, ''), 'main'),
    updated_at = coalesce(updated_at, created_at, now());

create index if not exists vcs_repositories_name_idx on vcs_repositories(name);

insert into audit_events (actor, domain, action, detail)
values ('system', 'Platform', 'Migrate', 'Applied 005_vcs_repository_controls.sql');
