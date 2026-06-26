delete from repo_packages older
using repo_packages newer
where older.distribution = newer.distribution
  and older.component = newer.component
  and older.name = newer.name
  and older.version = newer.version
  and older.architecture = newer.architecture
  and older.id < newer.id;

create unique index if not exists repo_packages_identity_idx
    on repo_packages(distribution, component, name, version, architecture);

insert into audit_events (actor, domain, action, detail)
values ('system', 'Platform', 'Migrate', 'Applied 007_apt_package_identity.sql');
