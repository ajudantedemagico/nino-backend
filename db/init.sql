-- Roda uma única vez, na criação do volume do Postgres.
create extension if not exists pgcrypto;  -- usada depois para criptografar colunas

create table usuario (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  senha_hash text not null,                         -- BCrypt, nunca a senha
  perfil text not null check (perfil in ('Responsavel','Terapeuta')),
  senha_alterada_em timestamptz not null default now(),
  tentativas_falhas int not null default 0,
  bloqueado_ate timestamptz,
  criado_em timestamptz not null default now()
);

create table reset_senha (
  id uuid primary key default gen_random_uuid(),
  usuario_id uuid not null references usuario(id) on delete cascade,
  token_hash text unique not null,                  -- SHA-256 do token enviado
  expira_em timestamptz not null,
  usado boolean not null default false
);

-- Etapa 3: crianças e emoções criptografadas
create table crianca (
  id uuid primary key default gen_random_uuid(),
  terapeuta_id uuid not null references usuario(id) on delete cascade,
  nome text not null,
  criada_em timestamptz not null default now()
);

create table registro_emocional (
  id uuid primary key default gen_random_uuid(),
  crianca_id uuid not null references crianca(id) on delete cascade,
  emocao bytea not null,                 -- criptografada com pgp_sym_encrypt (pgcrypto)
  registrado_em timestamptz not null default now()
);
