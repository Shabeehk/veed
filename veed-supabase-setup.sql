-- Veed accounts: run this once in your Supabase project "veed"
-- (Supabase dashboard -> SQL Editor -> New query -> paste everything -> Run)
--
-- It creates one private table of accounts (name, hashed password, saved game)
-- and five small functions the game calls. Nobody can read the table directly:
-- the game can only load or save an account with the right name and password/session.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.veed_users (
  id           text primary key,              -- the name in lower case
  display_name text not null,
  pass_hash    text not null,                 -- bcrypt hash, never the password itself
  tokens       text[] not null default '{}',  -- signed-in devices (newest first)
  data         jsonb not null default '{}'::jsonb,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

alter table public.veed_users enable row level security;   -- no policies: no direct access
revoke all on public.veed_users from anon, authenticated;

create or replace function public.veed_register(p_name text, p_pass text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare
  v_name  text := regexp_replace(trim(coalesce(p_name, '')), '\s+', ' ', 'g');
  v_token text := encode(gen_random_bytes(24), 'hex');
begin
  if char_length(v_name) < 2 or char_length(v_name) > 24 then raise exception 'Your name must be 2 to 24 letters.'; end if;
  if char_length(coalesce(p_pass, '')) < 4 then raise exception 'Your password must be at least 4 characters.'; end if;
  if exists (select 1 from veed_users where id = lower(v_name)) then
    raise exception 'That name already has an account. Log in, or choose another name.';
  end if;
  insert into veed_users (id, display_name, pass_hash, tokens)
  values (lower(v_name), v_name, crypt(p_pass, gen_salt('bf')), array[v_token]);
  return json_build_object('token', v_token, 'name', v_name, 'data', '{}'::jsonb);
end $$;

create or replace function public.veed_login(p_name text, p_pass text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare
  u veed_users;
  v_token text := encode(gen_random_bytes(24), 'hex');
begin
  select * into u from veed_users where id = lower(regexp_replace(trim(coalesce(p_name, '')), '\s+', ' ', 'g'));
  if not found or u.pass_hash <> crypt(coalesce(p_pass, ''), u.pass_hash) then
    perform pg_sleep(1);                      -- slows down password guessing
    raise exception 'Wrong name or password.';
  end if;
  update veed_users set tokens = (array[v_token] || tokens)[1:8], updated_at = now() where id = u.id;
  return json_build_object('token', v_token, 'name', u.display_name, 'data', u.data);
end $$;

create or replace function public.veed_load(p_name text, p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare u veed_users;
begin
  select * into u from veed_users where id = lower(trim(coalesce(p_name, ''))) and p_token = any(tokens);
  if not found then raise exception 'Please log in again.'; end if;
  return json_build_object('name', u.display_name, 'data', u.data);
end $$;

create or replace function public.veed_save(p_name text, p_token text, p_data jsonb)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  if octet_length(coalesce(p_data, '{}'::jsonb)::text) > 3000000 then raise exception 'This save is too big.'; end if;
  update veed_users set data = coalesce(p_data, '{}'::jsonb), updated_at = now()
   where id = lower(trim(coalesce(p_name, ''))) and p_token = any(tokens);
  if not found then raise exception 'Please log in again.'; end if;
  return json_build_object('ok', true);
end $$;

create or replace function public.veed_logout(p_name text, p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
begin
  update veed_users set tokens = array_remove(tokens, p_token) where id = lower(trim(coalesce(p_name, '')));
  return json_build_object('ok', true);
end $$;

grant execute on function public.veed_register(text, text), public.veed_login(text, text), public.veed_load(text, text),
  public.veed_save(text, text, jsonb), public.veed_logout(text, text) to anon, authenticated;
