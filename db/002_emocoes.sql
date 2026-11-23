
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
