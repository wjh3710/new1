-- Run this once in Supabase Dashboard > SQL Editor.
-- Admins are assigned manually through public.user_roles.

grant usage on schema public to anon, authenticated;

create table if not exists public.user_roles (
    user_id uuid primary key references auth.users(id) on delete cascade,
    role text not null default 'admin' check (role = 'admin'),
    created_at timestamptz not null default now()
);

alter table public.user_roles enable row level security;
revoke all on table public.user_roles from anon, authenticated;
grant select on table public.user_roles to authenticated;
drop policy if exists "Users can read their own role" on public.user_roles;
create policy "Users can read their own role"
on public.user_roles for select to authenticated
using ((select auth.uid()) = user_id);

create or replace function public.is_admin()
returns boolean
language sql stable security definer
set search_path = ''
as $$
    select exists (
        select 1 from public.user_roles
        where user_id = (select auth.uid()) and role = 'admin'
    );
$$;
revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- Let a signed-in user delete only their own account and vote records.
create or replace function public.delete_my_account()
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    current_user_id uuid := auth.uid();
begin
    if current_user_id is null then
        raise exception 'Sign in is required';
    end if;

    delete from public.vote_events where device_id = current_user_id;
    delete from auth.users where id = current_user_id;
    if not found then
        raise exception 'Account could not be deleted';
    end if;
end;
$$;
revoke all on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;

create table if not exists public.app_state (
    id smallint primary key default 1 check (id = 1),
    state jsonb not null default '{"tournaments":[],"regions":[],"settings":{}}'::jsonb,
    updated_at timestamptz not null default now()
);
alter table public.app_state enable row level security;
revoke all on table public.app_state from anon, authenticated;
grant select on table public.app_state to anon, authenticated;
grant insert, update on table public.app_state to authenticated;
drop policy if exists "App state is public to read" on public.app_state;
create policy "App state is public to read"
on public.app_state for select to anon, authenticated using (true);
drop policy if exists "Admins can create app state" on public.app_state;
create policy "Admins can create app state"
on public.app_state for insert to authenticated
with check ((select public.is_admin()));
drop policy if exists "Admins can update app state" on public.app_state;
create policy "Admins can update app state"
on public.app_state for update to authenticated
using ((select public.is_admin()))
with check ((select public.is_admin()));

create table if not exists public.vote_events (
    id bigint generated always as identity primary key,
    device_id uuid not null,
    tournament_id text not null,
    candidate_id text not null,
    vote_type text not null check (vote_type in ('restaurant', 'menu')),
    menu_name text,
    voted_on date not null default ((now() at time zone 'UTC')::date),
    created_at timestamptz not null default now(),
    check ((vote_type = 'restaurant' and menu_name is null) or
           (vote_type = 'menu' and menu_name is not null))
);
create unique index if not exists vote_events_one_restaurant_per_day
on public.vote_events (device_id, tournament_id, voted_on)
where vote_type = 'restaurant';
create unique index if not exists vote_events_one_menu_per_day
on public.vote_events (device_id, tournament_id, candidate_id, menu_name, voted_on)
where vote_type = 'menu';
create index if not exists vote_events_dashboard_lookup
on public.vote_events (tournament_id, candidate_id, vote_type, voted_on);

create table if not exists public.menu_search_events (
    id bigint generated always as identity primary key,
    search_term text not null check (char_length(search_term) between 1 and 80),
    region text not null,
    created_at timestamptz not null default now()
);
create index if not exists menu_search_events_region_term
on public.menu_search_events (region, lower(search_term));
alter table public.menu_search_events enable row level security;
revoke all on table public.menu_search_events from anon, authenticated;

create or replace function public.record_menu_search(p_search_term text, p_region text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    clean_term text := trim(coalesce(p_search_term, ''));
    clean_region text := trim(coalesce(p_region, '전체'));
begin
    if char_length(clean_term) < 1 or char_length(clean_term) > 80 then
        raise exception 'Search term must be between 1 and 80 characters';
    end if;
    if char_length(clean_region) < 1 or char_length(clean_region) > 80 then
        raise exception 'Invalid region';
    end if;
    insert into public.menu_search_events (search_term, region)
    values (clean_term, clean_region);
end;
$$;
revoke all on function public.record_menu_search(text, text) from public;
grant execute on function public.record_menu_search(text, text) to anon, authenticated;

create or replace function public.get_menu_search_trends(p_region text default '전체')
returns table(search_term text, search_count bigint)
language sql
stable
security definer
set search_path = ''
as $$
    select min(search_term) as search_term, count(*) as search_count
    from public.menu_search_events
    where coalesce(trim(p_region), '전체') = '전체' or region = trim(p_region)
    group by lower(search_term)
    order by count(*) desc, lower(min(search_term))
    limit 8;
$$;
revoke all on function public.get_menu_search_trends(text) from public;
grant execute on function public.get_menu_search_trends(text) to anon, authenticated;

create table if not exists public.community_posts (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    author_name text not null check (char_length(trim(author_name)) between 1 and 20),
    region text not null check (char_length(trim(region)) between 1 and 80),
    category text not null check (category in ('오늘의 먹픽', '내돈내산', '맛집 질문', '혼밥 메이트')),
    restaurant_name text check (restaurant_name is null or char_length(restaurant_name) <= 80),
    title text not null check (char_length(trim(title)) between 1 and 100),
    content text not null check (char_length(trim(content)) between 1 and 2000),
    created_at timestamptz not null default now()
);
create index if not exists community_posts_region_created
on public.community_posts (region, created_at desc);
alter table public.community_posts enable row level security;
revoke all on table public.community_posts from anon, authenticated;
grant select on table public.community_posts to anon, authenticated;
grant insert, update, delete on table public.community_posts to authenticated;
drop policy if exists "Community posts are public to read" on public.community_posts;
create policy "Community posts are public to read"
on public.community_posts for select to anon, authenticated using (true);
drop policy if exists "Users can create their own community posts" on public.community_posts;
create policy "Users can create their own community posts"
on public.community_posts for insert to authenticated with check ((select auth.uid()) = user_id);
drop policy if exists "Users can edit their own community posts" on public.community_posts;
create policy "Users can edit their own community posts"
on public.community_posts for update to authenticated
using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
drop policy if exists "Users can delete their own community posts" on public.community_posts;
create policy "Users can delete their own community posts"
on public.community_posts for delete to authenticated using ((select auth.uid()) = user_id);

create table if not exists public.community_reactions (
    post_id uuid not null references public.community_posts(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    reaction text not null check (reaction in ('yum', 'save')),
    created_at timestamptz not null default now(),
    primary key (post_id, user_id, reaction)
);
create index if not exists community_reactions_post on public.community_reactions (post_id);
alter table public.community_reactions enable row level security;
revoke all on table public.community_reactions from anon, authenticated;
grant select on table public.community_reactions to anon, authenticated;
grant insert, delete on table public.community_reactions to authenticated;
drop policy if exists "Community reactions are public to read" on public.community_reactions;
create policy "Community reactions are public to read"
on public.community_reactions for select to anon, authenticated using (true);
drop policy if exists "Users can add their own community reactions" on public.community_reactions;
create policy "Users can add their own community reactions"
on public.community_reactions for insert to authenticated with check ((select auth.uid()) = user_id);
drop policy if exists "Users can remove their own community reactions" on public.community_reactions;
create policy "Users can remove their own community reactions"
on public.community_reactions for delete to authenticated using ((select auth.uid()) = user_id);

create table if not exists public.community_comments (
    id uuid primary key default gen_random_uuid(),
    post_id uuid not null references public.community_posts(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    author_name text not null check (char_length(trim(author_name)) between 1 and 20),
    content text not null check (char_length(trim(content)) between 1 and 500),
    created_at timestamptz not null default now()
);
create index if not exists community_comments_post_created
on public.community_comments (post_id, created_at);
alter table public.community_comments enable row level security;
revoke all on table public.community_comments from anon, authenticated;
grant select on table public.community_comments to anon, authenticated;
grant insert, delete on table public.community_comments to authenticated;
drop policy if exists "Community comments are public to read" on public.community_comments;
create policy "Community comments are public to read"
on public.community_comments for select to anon, authenticated using (true);
drop policy if exists "Users can add their own community comments" on public.community_comments;
create policy "Users can add their own community comments"
on public.community_comments for insert to authenticated with check ((select auth.uid()) = user_id);
drop policy if exists "Users can delete their own community comments" on public.community_comments;
create policy "Users can delete their own community comments"
on public.community_comments for delete to authenticated using ((select auth.uid()) = user_id);

alter table public.vote_events enable row level security;
revoke all on table public.vote_events from anon, authenticated;

create table if not exists public.activity_logs (
    id bigint generated always as identity primary key,
    text text not null,
    created_at timestamptz not null default now()
);
alter table public.activity_logs enable row level security;
revoke all on table public.activity_logs from anon, authenticated;
grant select, insert, delete on table public.activity_logs to authenticated;
grant usage, select on sequence public.activity_logs_id_seq to authenticated;
drop policy if exists "Admins can read activity logs" on public.activity_logs;
create policy "Admins can read activity logs"
on public.activity_logs for select to authenticated
using ((select public.is_admin()));
drop policy if exists "Admins can add activity logs" on public.activity_logs;
create policy "Admins can add activity logs"
on public.activity_logs for insert to authenticated
with check ((select public.is_admin()));
drop policy if exists "Admins can clear activity logs" on public.activity_logs;
create policy "Admins can clear activity logs"
on public.activity_logs for delete to authenticated
using ((select public.is_admin()));

create or replace function public.cast_restaurant_vote(
    p_device_id uuid, p_tournament_id text, p_candidate_id text
)
returns boolean
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
    inserted_count integer;
begin
    if auth.uid() is null then raise exception 'Sign in is required to vote'; end if;
    if p_device_id is distinct from auth.uid() then raise exception 'Vote identity must match the signed-in user'; end if;
    if not exists (
        select 1
        from public.app_state s,
             jsonb_array_elements(coalesce(s.state->'tournaments', '[]'::jsonb)) as t(tournament),
             jsonb_array_elements(coalesce(t.tournament->'candidates', '[]'::jsonb)) as c(candidate)
        where s.id = 1 and t.tournament->>'id' = p_tournament_id
          and t.tournament->>'active' is distinct from 'false'
          and c.candidate->>'id' = p_candidate_id
    ) then
        raise exception 'Unknown tournament or restaurant';
    end if;

    insert into public.vote_events(device_id, tournament_id, candidate_id, vote_type)
    values (p_device_id, p_tournament_id, p_candidate_id, 'restaurant')
    on conflict (device_id, tournament_id, voted_on) where vote_type = 'restaurant' do nothing;
    get diagnostics inserted_count = row_count;
    if inserted_count = 1 then
        insert into public.activity_logs(text)
        values ('Restaurant vote: ' || p_tournament_id || ' / ' || p_candidate_id);
    end if;
    return inserted_count = 1;
end;
$$;

create or replace function public.cast_menu_vote(
    p_device_id uuid, p_tournament_id text, p_candidate_id text, p_menu_name text
)
returns boolean
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
    inserted_count integer;
begin
    if auth.uid() is null then raise exception 'Sign in is required to vote'; end if;
    if p_device_id is distinct from auth.uid() then raise exception 'Vote identity must match the signed-in user'; end if;
    if coalesce(trim(p_menu_name), '') = '' then raise exception 'Menu is required'; end if;
    if not exists (
        select 1 from public.vote_events
        where device_id = p_device_id and tournament_id = p_tournament_id
          and candidate_id = p_candidate_id and vote_type = 'restaurant'
          and voted_on = (now() at time zone 'UTC')::date
    ) then raise exception 'Vote for the restaurant first'; end if;
    if not exists (
        select 1
        from public.app_state s,
             jsonb_array_elements(coalesce(s.state->'tournaments', '[]'::jsonb)) as t(tournament),
             jsonb_array_elements(coalesce(t.tournament->'candidates', '[]'::jsonb)) as c(candidate)
        where s.id = 1 and t.tournament->>'id' = p_tournament_id
          and t.tournament->>'active' is distinct from 'false'
          and c.candidate->>'id' = p_candidate_id
    ) then raise exception 'Unknown tournament or restaurant'; end if;

    insert into public.vote_events(device_id, tournament_id, candidate_id, vote_type, menu_name)
    values (p_device_id, p_tournament_id, p_candidate_id, 'menu', trim(p_menu_name))
    on conflict (device_id, tournament_id, candidate_id, menu_name, voted_on) where vote_type = 'menu' do nothing;
    get diagnostics inserted_count = row_count;
    if inserted_count = 1 then
        insert into public.activity_logs(text)
        values ('Menu vote: ' || p_tournament_id || ' / ' || p_candidate_id || ' / ' || trim(p_menu_name));
    end if;
    return inserted_count = 1;
end;
$$;

create or replace function public.cancel_menu_vote(
    p_device_id uuid, p_tournament_id text, p_candidate_id text, p_menu_name text
)
returns boolean
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
    deleted_count integer;
begin
    if auth.uid() is null then raise exception 'Sign in is required to vote'; end if;
    if p_device_id is distinct from auth.uid() then raise exception 'Vote identity must match the signed-in user'; end if;
    delete from public.vote_events
    where device_id = p_device_id and tournament_id = p_tournament_id
      and candidate_id = p_candidate_id and vote_type = 'menu'
      and menu_name = p_menu_name and voted_on = (now() at time zone 'UTC')::date;
    get diagnostics deleted_count = row_count;
    if deleted_count = 1 then
        insert into public.activity_logs(text)
        values ('Menu vote cancelled: ' || p_tournament_id || ' / ' || p_candidate_id || ' / ' || p_menu_name);
    end if;
    return deleted_count = 1;
end;
$$;

create or replace function public.cancel_restaurant_vote(
    p_device_id uuid, p_tournament_id text, p_candidate_id text
)
returns boolean
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
    deleted_count integer;
begin
    if auth.uid() is null then raise exception 'Sign in is required to vote'; end if;
    if p_device_id is distinct from auth.uid() then raise exception 'Vote identity must match the signed-in user'; end if;
    delete from public.vote_events
    where device_id = p_device_id and tournament_id = p_tournament_id
      and candidate_id = p_candidate_id and voted_on = (now() at time zone 'UTC')::date;
    get diagnostics deleted_count = row_count;
    if deleted_count > 0 then
        insert into public.activity_logs(text)
        values ('Restaurant vote cancelled: ' || p_tournament_id || ' / ' || p_candidate_id);
    end if;
    return deleted_count > 0;
end;
$$;

create or replace function public.get_vote_dashboard(p_device_id uuid)
returns jsonb
language plpgsql stable security definer
set search_path = public, pg_temp
as $$
declare
    today_utc date := (now() at time zone 'UTC')::date;
    total_count bigint;
    today_count bigint;
    trend jsonb;
    candidate_counts jsonb;
    menu_counts jsonb;
    my_direct jsonb;
    my_menus jsonb;
begin
    if auth.uid() is null and p_device_id is not null then
        raise exception 'Vote summary identity must match the signed-in user';
    end if;
    if p_device_id is not null and (auth.uid() is null or p_device_id is distinct from auth.uid()) then
        raise exception 'Vote summary identity must match the signed-in user';
    end if;
    select count(*) into total_count from public.vote_events;
    select count(*) into today_count from public.vote_events where voted_on = today_utc;
    select coalesce(jsonb_agg(day_count order by day), '[]'::jsonb) into trend
    from (
        select today_utc - 6 + day_offset as day,
               (select count(*) from public.vote_events v where v.voted_on = today_utc - 6 + day_offset) as day_count
        from generate_series(0, 6) as days(day_offset)
    ) daily;
    select coalesce(jsonb_object_agg(tournament_id || '|' || candidate_id, amount), '{}'::jsonb)
      into candidate_counts
      from (select tournament_id, candidate_id, count(*) as amount
            from public.vote_events where vote_type = 'restaurant'
            group by tournament_id, candidate_id) counts;
    select coalesce(jsonb_object_agg(tournament_id || '|' || candidate_id || '|' || menu_name, amount), '{}'::jsonb)
      into menu_counts
      from (select tournament_id, candidate_id, menu_name, count(*) as amount
            from public.vote_events where vote_type = 'menu'
            group by tournament_id, candidate_id, menu_name) counts;
    select coalesce(jsonb_object_agg(tournament_id, candidate_id), '{}'::jsonb)
      into my_direct
      from (select tournament_id, candidate_id from public.vote_events
            where device_id = p_device_id and vote_type = 'restaurant' and voted_on = today_utc) mine;
    select coalesce(jsonb_object_agg(key, menus), '{}'::jsonb)
      into my_menus
      from (select tournament_id || '|' || candidate_id as key, jsonb_agg(menu_name) as menus
            from public.vote_events where device_id = p_device_id and vote_type = 'menu' and voted_on = today_utc
            group by tournament_id, candidate_id) mine;
    return jsonb_build_object(
        'stats', jsonb_build_object('totalVotes', total_count, 'todayVotes', today_count, 'dailyTrend', trend),
        'candidateCounts', candidate_counts, 'menuCounts', menu_counts,
        'myDirect', my_direct, 'myMenus', my_menus
    );
end;
$$;

create or replace function public.admin_reset_vote_data()
returns boolean
language plpgsql security definer
set search_path = public, pg_temp
as $$
begin
    if not public.is_admin() then raise exception 'Admin access required'; end if;
    delete from public.vote_events;
    delete from public.activity_logs;
    return true;
end;
$$;

-- Remove vote rows attached to the retired built-in sample tournaments only.
create or replace function public.admin_remove_legacy_demo_votes()
returns integer
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
    deleted_count integer;
begin
    if not public.is_admin() then raise exception 'Admin access required'; end if;
    delete from public.vote_events
    where tournament_id in ('gamjatang', 'dessert', 'pasta', 'konkuk-korean-demo', 'konkuk-grill-demo', 'konkuk-street-food-demo');
    get diagnostics deleted_count = row_count;
    return deleted_count;
end;
$$;

revoke all on function public.cast_restaurant_vote(uuid, text, text) from public;
revoke all on function public.cast_restaurant_vote(uuid, text, text) from anon;
revoke all on function public.cast_menu_vote(uuid, text, text, text) from public;
revoke all on function public.cast_menu_vote(uuid, text, text, text) from anon;
revoke all on function public.cancel_menu_vote(uuid, text, text, text) from public;
revoke all on function public.cancel_menu_vote(uuid, text, text, text) from anon;
revoke all on function public.cancel_restaurant_vote(uuid, text, text) from public;
revoke all on function public.cancel_restaurant_vote(uuid, text, text) from anon;
revoke all on function public.get_vote_dashboard(uuid) from public;
revoke all on function public.admin_reset_vote_data() from public, anon;
revoke all on function public.admin_remove_legacy_demo_votes() from public, anon;
grant execute on function public.cast_restaurant_vote(uuid, text, text) to authenticated;
grant execute on function public.cast_menu_vote(uuid, text, text, text) to authenticated;
grant execute on function public.cancel_menu_vote(uuid, text, text, text) to authenticated;
grant execute on function public.cancel_restaurant_vote(uuid, text, text) to authenticated;
grant execute on function public.get_vote_dashboard(uuid) to anon, authenticated;
grant execute on function public.admin_reset_vote_data() to authenticated;
grant execute on function public.admin_remove_legacy_demo_votes() to authenticated;
