-- ============================================================
-- SOFIA — Aprovação de cadastros (versão 1)
--
-- O que muda:
--  * Cadastro novo fica "aguardando aprovação": não entra no app,
--    não salva nada e não usa a IA até o Bispo aprovar.
--  * Área do administrador dentro da Sofia, com o login do Bispo
--    (função eh_dono, criada pelo script das Despesas): aprovar,
--    bloquear, criar PIN novo e excluir conta.
--  * Limite de 30 cadastros aguardando ao mesmo tempo (impede alguém
--    de encher o banco de contas falsas).
--
-- As contas que já existem ficam "aguardando"; é só aprová-las na
-- área do administrador.
--
-- Cole no SQL Editor do Supabase e clique em RUN. Pode rodar de novo.
-- ============================================================

-- 1) Situação de cada conta
alter table sofia.alunas
  add column if not exists situacao text not null default 'pendente';

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'alunas_situacao_ok') then
    alter table sofia.alunas add constraint alunas_situacao_ok
      check (situacao in ('pendente', 'aprovado', 'bloqueado'));
  end if;
end $$;

-- 2) O crachá só vale para conta APROVADA.
--    Todas as funções da aluna (dados, aulas, plano e a IA no Worker)
--    passam por aqui, então a trava vale para tudo de uma vez.
create or replace function sofia._aluna_do_token(p_token text)
 returns uuid
 language sql
 stable security definer
 set search_path to ''
as $function$
  select s.aluna_id
  from sofia.sessoes s
  join sofia.alunas a on a.id = s.aluna_id
  where s.token = p_token and s.expira_em > now() and a.situacao = 'aprovado';
$function$;

-- 3) Cadastro: cria a conta como "aguardando" e NÃO entrega crachá
create or replace function sofia.cadastrar(p_nome text, p_curso text, p_ano integer, p_tempo text, p_adaptacao text, p_pin text)
 returns jsonb
 language plpgsql
 security definer
 set search_path to ''
as $function$
declare
  v_nome    text := btrim(coalesce(p_nome, ''));
  v_base    text;
  v_usuario text;
  v_n       int  := 1;
begin
  if length(v_nome) < 1 or length(v_nome) > 30 then
    return jsonb_build_object('erro', 'Digite um nome de até 30 letras.');
  end if;
  if p_pin is null or p_pin !~ '^[0-9]{4}$' then
    return jsonb_build_object('erro', 'O PIN precisa ter 4 números.');
  end if;
  if (select count(*) from sofia.alunas where situacao = 'pendente') >= 30 then
    return jsonb_build_object('erro', 'Os cadastros estão fechados no momento. Fale com o responsável pelo app.');
  end if;

  -- usuário = primeiro nome sem acentos; se já existir, ganha um número (julia, julia2...)
  v_base := regexp_replace(
              translate(lower(split_part(v_nome, ' ', 1)),
                        'áàâãäéèêëíìîïóòôõöúùûüçñ', 'aaaaaeeeeiiiiooooouuuucn'),
              '[^a-z0-9]', '', 'g');
  if v_base = '' then v_base := 'aluna'; end if;
  v_usuario := v_base;
  while exists (select 1 from sofia.alunas where usuario = v_usuario) loop
    v_n := v_n + 1;
    v_usuario := v_base || v_n;
  end loop;

  insert into sofia.alunas (usuario, nome, curso, ano_enem, tempo_diario, adaptacao, pin_hash, situacao)
  values (v_usuario, v_nome, left(p_curso, 40), p_ano, left(p_tempo, 30), left(p_adaptacao, 60),
          extensions.crypt(p_pin, extensions.gen_salt('bf')), 'pendente');

  return jsonb_build_object('pendente', true, 'usuario', v_usuario, 'nome', v_nome);
end;
$function$;

-- 4) Entrar: confere o PIN; só entrega crachá se a conta estiver aprovada
create or replace function sofia.entrar(p_usuario text, p_pin text)
 returns jsonb
 language plpgsql
 security definer
 set search_path to ''
as $function$
declare
  a       sofia.alunas%rowtype;
  v_token text;
begin
  select * into a from sofia.alunas where usuario = lower(btrim(coalesce(p_usuario, '')));
  if not found then
    return jsonb_build_object('erro', 'Usuário ou PIN incorreto.');
  end if;

  if a.bloqueado_ate is not null and a.bloqueado_ate > now() then
    return jsonb_build_object('erro', 'Muitas tentativas erradas. Espere 15 minutos e tente de novo.');
  end if;

  if a.pin_hash <> extensions.crypt(coalesce(p_pin, ''), a.pin_hash) then
    update sofia.alunas
       set tentativas    = case when tentativas + 1 >= 5 then 0 else tentativas + 1 end,
           bloqueado_ate = case when tentativas + 1 >= 5 then now() + interval '15 minutes' else null end
     where id = a.id;
    return jsonb_build_object('erro', 'Usuário ou PIN incorreto.');
  end if;

  update sofia.alunas set tentativas = 0, bloqueado_ate = null where id = a.id;

  if a.situacao = 'bloqueado' then
    return jsonb_build_object('erro', 'Esta conta foi bloqueada. Fale com o responsável pelo app.');
  end if;
  if a.situacao <> 'aprovado' then
    return jsonb_build_object('pendente', true, 'usuario', a.usuario, 'nome', a.nome);
  end if;

  delete from sofia.sessoes where aluna_id = a.id and expira_em < now();

  v_token := replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
  insert into sofia.sessoes (token, aluna_id) values (v_token, a.id);

  return jsonb_build_object('token', v_token, 'usuario', a.usuario, 'nome', a.nome);
end;
$function$;

-- 5) Área do administrador (só o login do Bispo)
create or replace function sofia.adm_lista()
 returns jsonb
 language plpgsql
 stable security definer
 set search_path to ''
as $function$
begin
  if not coalesce(public.eh_dono(), false) then
    return jsonb_build_object('erro', 'Esta conta não é de administrador.');
  end if;
  return jsonb_build_object('alunas', coalesce((
    select jsonb_agg(jsonb_build_object(
             'id', a.id, 'usuario', a.usuario, 'nome', a.nome, 'curso', a.curso,
             'ano_enem', a.ano_enem, 'situacao', a.situacao,
             'criado_em', to_char(a.criado_em at time zone 'America/Sao_Paulo', 'DD/MM/YYYY'),
             'aulas', (select count(*) from sofia.aulas x where x.aluna_id = a.id),
             'ultimo_dia', (select to_char(max(d.dia), 'DD/MM/YYYY') from sofia.dias_estudo d where d.aluna_id = a.id))
           order by (a.situacao = 'pendente') desc, a.criado_em desc)
    from sofia.alunas a), '[]'::jsonb));
end;
$function$;

create or replace function sofia.adm_situacao(p_id uuid, p_situacao text)
 returns jsonb
 language plpgsql
 security definer
 set search_path to ''
as $function$
begin
  if not coalesce(public.eh_dono(), false) then
    return jsonb_build_object('erro', 'Esta conta não é de administrador.');
  end if;
  if p_situacao not in ('pendente', 'aprovado', 'bloqueado') then
    return jsonb_build_object('erro', 'Situação inválida.');
  end if;
  update sofia.alunas set situacao = p_situacao where id = p_id;
  if p_situacao <> 'aprovado' then
    delete from sofia.sessoes where aluna_id = p_id;   -- tira do app na hora
  end if;
  return jsonb_build_object('ok', true);
end;
$function$;

create or replace function sofia.adm_novo_pin(p_id uuid, p_pin text)
 returns jsonb
 language plpgsql
 security definer
 set search_path to ''
as $function$
begin
  if not coalesce(public.eh_dono(), false) then
    return jsonb_build_object('erro', 'Esta conta não é de administrador.');
  end if;
  if p_pin is null or p_pin !~ '^[0-9]{4}$' then
    return jsonb_build_object('erro', 'O PIN precisa ter 4 números.');
  end if;
  update sofia.alunas
     set pin_hash = extensions.crypt(p_pin, extensions.gen_salt('bf')),
         tentativas = 0, bloqueado_ate = null
   where id = p_id;
  delete from sofia.sessoes where aluna_id = p_id;
  return jsonb_build_object('ok', true);
end;
$function$;

create or replace function sofia.adm_excluir(p_id uuid)
 returns jsonb
 language plpgsql
 security definer
 set search_path to ''
as $function$
begin
  if not coalesce(public.eh_dono(), false) then
    return jsonb_build_object('erro', 'Esta conta não é de administrador.');
  end if;
  delete from sofia.sessoes     where aluna_id = p_id;
  delete from sofia.uso_ia      where aluna_id = p_id;
  delete from sofia.aulas       where aluna_id = p_id;
  delete from sofia.diagnosticos where aluna_id = p_id;
  delete from sofia.niveis      where aluna_id = p_id;
  delete from sofia.planos      where aluna_id = p_id;
  delete from sofia.dias_estudo where aluna_id = p_id;
  delete from sofia.redacoes    where aluna_id = p_id;
  delete from sofia.alunas      where id = p_id;
  return jsonb_build_object('ok', true);
end;
$function$;

-- 6) Permissões: as funções da aluna continuam abertas (elas mesmas conferem
--    PIN e crachá); as do administrador só para quem fez login.
grant usage on schema sofia to anon, authenticated;
revoke all on function sofia.adm_lista(), sofia.adm_situacao(uuid, text),
  sofia.adm_novo_pin(uuid, text), sofia.adm_excluir(uuid) from public, anon;
grant execute on function sofia.adm_lista(), sofia.adm_situacao(uuid, text),
  sofia.adm_novo_pin(uuid, text), sofia.adm_excluir(uuid) to authenticated;
grant execute on function sofia.cadastrar(text, text, integer, text, text, text),
  sofia.entrar(text, text) to anon, authenticated;
revoke all on function sofia._aluna_do_token(text) from public, anon, authenticated;

-- Conferência: mostra as contas e a situação de cada uma
select usuario, nome, situacao from sofia.alunas order by criado_em;
