-- ============================================================================
-- Doodle G Provider Panel — Row Level Security policies
-- ============================================================================
-- This file is additive to schema.sql. Run it once, after schema.sql, in the
-- Supabase SQL Editor (or via migration). It is written to be safely re-run
-- (CREATE OR REPLACE / DROP POLICY IF EXISTS / ADD COLUMN IF NOT EXISTS).
--
-- Why this file exists: every client query in app.js runs with the PUBLIC
-- ANON KEY. There is no separate backend. That means Postgres Row Level
-- Security is the *entire* access-control layer for this product — if a
-- table has RLS disabled, or has RLS enabled with no policies, or has a
-- policy that's too broad, anyone with the anon key (visible in any browser
-- devtools) can read or write it directly via the REST API, no UI required.
-- ============================================================================


-- ----------------------------------------------------------------------------
-- 0. SCHEMA ADDITIONS required to support the policies below
-- ----------------------------------------------------------------------------

-- 0a. providers needs a column that ties a row to the auth account that owns
--     it. This is set by a trigger below (never trusted from the client) —
--     see item 5 (registration IDOR) for why client-supplied ownership is
--     not acceptable here.
ALTER TABLE public.providers
  ADD COLUMN IF NOT EXISTS owner_user_id uuid REFERENCES auth.users(id);

-- 0b. Per-provider, per-line-item fulfillment status. Replaces updating
--     orders.status directly (item 2 — orders.status update was an IDOR:
--     one order can contain several providers' items, so a single
--     order-level status column can't be safely writable by any one of
--     them). provider_id is stored directly (denormalized) rather than
--     joined through order_items.product_id, because product_id is a
--     free-text column (not an FK — see schema.sql), so we resolve and
--     pin the owning provider once, at row-creation time.
CREATE TABLE IF NOT EXISTS public.order_item_fulfillment (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  order_item_id uuid NOT NULL UNIQUE,
  provider_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'confirmed'
    CHECK (status = ANY (ARRAY['confirmed'::text, 'processing'::text, 'shipped'::text, 'delivered'::text, 'cancelled'::text])),
  updated_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT order_item_fulfillment_pkey PRIMARY KEY (id),
  CONSTRAINT order_item_fulfillment_order_item_id_fkey FOREIGN KEY (order_item_id) REFERENCES public.order_items(id),
  CONSTRAINT order_item_fulfillment_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.providers(id)
);


-- ----------------------------------------------------------------------------
-- 0b2. EXTENSIONS
-- ----------------------------------------------------------------------------
-- pgcrypto provides gen_random_bytes()/hmac() (used for the Aadhaar/PAN
-- hashing below) and gen_random_uuid() (used throughout schema.sql's
-- defaults). Supabase enables this by default on every project, which is
-- why schema.sql never had to declare it — but this file should be
-- runnable against a plain Postgres instance too, so declare it explicitly
-- rather than silently depending on a Supabase-specific default.
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ----------------------------------------------------------------------------
-- 0c. BASE GRANTS
-- ----------------------------------------------------------------------------
-- On a real Supabase project, anon/authenticated already have broad table
-- grants provisioned automatically at project creation, and RLS is what
-- actually restricts access on top of that (this is documented Supabase
-- behavior, and it's the assumption the rest of this file — and app.js —
-- was written under: "RLS is the only real access-control layer"). This
-- file is meant to be testable against a plain Postgres instance too (see
-- the test harness used to verify it), which has no such defaults, so we
-- state them explicitly here. Re-running this on a real Supabase project is
-- harmless — it just reasserts grants that already exist.
--
-- IMPORTANT: granting INSERT/UPDATE/DELETE here does NOT mean anon/
-- authenticated can actually do those things — Postgres requires BOTH a
-- table-level grant AND a permissive RLS policy for the action to succeed.
-- Where no INSERT/UPDATE/DELETE policy exists below for a role (e.g. anon
-- on providers, authenticated on signin_main), the grant is inert.
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO anon, authenticated;


-- ----------------------------------------------------------------------------
-- 1. HELPER FUNCTIONS (SECURITY DEFINER — bypass RLS internally so policies
--    that call them don't recurse into RLS on signin_main/providers)
-- ----------------------------------------------------------------------------

-- Resolves the calling user's provider_id via signin_main. Returns NULL for
-- anonymous callers, admins, or providers who haven't finished registration.
CREATE OR REPLACE FUNCTION public.current_provider_id()
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT provider_id FROM public.signin_main WHERE id = auth.uid();
$$;

GRANT EXECUTE ON FUNCTION public.current_provider_id() TO anon, authenticated;

-- True if the calling user is an admin per signin_main.
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.signin_main WHERE id = auth.uid() AND role = 'admin'
  );
$$;

GRANT EXECUTE ON FUNCTION public.is_admin() TO anon, authenticated;

-- Resolves the calling user's own profile.id (customer-side equivalent of
-- current_provider_id()). Returns NULL for anyone without a profile row
-- (anon, providers/admins, or a forged/stale JWT for a deleted user).
CREATE OR REPLACE FUNCTION public.current_customer_profile_id()
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT id FROM public.profile WHERE user_id = auth.uid();
$$;

GRANT EXECUTE ON FUNCTION public.current_customer_profile_id() TO anon, authenticated;

-- The four functions below all exist for the same reason: profile<->follows
-- and orders<->order_items<->order_shipping each have RLS policies that
-- need to look at each other. A policy on table X that directly subqueries
-- table Y — where Y's own policy subqueries back into X — causes Postgres
-- to report "infinite recursion detected in policy". Wrapping the
-- cross-table lookup in a SECURITY DEFINER function breaks the cycle: the
-- function runs as its owner (bypassing RLS internally for that one
-- lookup), so evaluating it doesn't re-trigger the other table's policies.
-- This was caught by actually executing these policies against a live
-- database, not by re-reading them — see the POLICY TEST CHECKLIST at the
-- bottom of this file for the specific failing queries.
CREATE OR REPLACE FUNCTION public.provider_follower_ids(p_provider_id uuid)
RETURNS SETOF uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT follower_id FROM public.follows WHERE provider_id = p_provider_id;
$$;
GRANT EXECUTE ON FUNCTION public.provider_follower_ids(uuid) TO authenticated;

CREATE OR REPLACE FUNCTION public.provider_visible_product_ids()
RETURNS SETOF text
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT id::text FROM public.products_box WHERE provider_id = public.current_provider_id();
$$;
GRANT EXECUTE ON FUNCTION public.provider_visible_product_ids() TO authenticated;

CREATE OR REPLACE FUNCTION public.provider_visible_order_ids()
RETURNS SETOF uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT DISTINCT oi.order_id
  FROM public.order_items oi
  JOIN public.products_box pb ON pb.id::text = oi.product_id
  WHERE pb.provider_id = public.current_provider_id();
$$;
GRANT EXECUTE ON FUNCTION public.provider_visible_order_ids() TO authenticated;

CREATE OR REPLACE FUNCTION public.customer_own_order_ids()
RETURNS SETOF uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT id FROM public.orders WHERE user_id = auth.uid();
$$;
GRANT EXECUTE ON FUNCTION public.customer_own_order_ids() TO authenticated;


-- ----------------------------------------------------------------------------
-- 2. TRIGGERS — this is how signin_main and providers.owner_user_id get
--    populated. Clients never write these values directly (see policies
--    below: signin_main has no client-facing INSERT/UPDATE policy at all).
-- ----------------------------------------------------------------------------

-- 2a. Whenever a new Supabase Auth user is created, drop a matching
--     signin_main row immediately, with provider_id left NULL. This runs as
--     the function owner (bypasses RLS) so it works regardless of who/what
--     created the auth user (self-registration, admin invite, etc).
--     Role defaults to 'provider' since that's the only self-serve signup
--     flow in this app; pass options.data.role = 'admin' from a trusted
--     context (e.g. Supabase dashboard, service-role script) to seed admins.
CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.signin_main (id, email, role, provider_id)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'role', 'provider'),
    NULL
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_auth_user();

-- 2b. Force providers.owner_user_id to the caller's own auth.uid() on every
--     INSERT, ignoring whatever the client sent. Combined with the
--     providers_insert_own WITH CHECK policy below, this is what makes
--     "insert a providers row for someone else" impossible even if the
--     client-side code is bypassed entirely and the REST API is called by
--     hand.
CREATE OR REPLACE FUNCTION public.set_provider_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  NEW.owner_user_id := auth.uid();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_set_provider_owner ON public.providers;
CREATE TRIGGER trg_set_provider_owner
  BEFORE INSERT ON public.providers
  FOR EACH ROW EXECUTE FUNCTION public.set_provider_owner();

-- 2c. Once a providers row is created for a given owner, link it back onto
--     that owner's signin_main row. This is what lets a provider finish
--     registration in two authenticated steps (create auth user, then
--     create their providers row) without the client ever writing to
--     signin_main directly.
CREATE OR REPLACE FUNCTION public.link_provider_to_signin_main()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE public.signin_main
  SET provider_id = NEW.id
  WHERE id = NEW.owner_user_id
    AND provider_id IS NULL;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_link_provider_to_signin_main ON public.providers;
CREATE TRIGGER trg_link_provider_to_signin_main
  AFTER INSERT ON public.providers
  FOR EACH ROW EXECUTE FUNCTION public.link_provider_to_signin_main();


-- ----------------------------------------------------------------------------
-- 3. providers
-- ----------------------------------------------------------------------------
ALTER TABLE public.providers ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS providers_select_own ON public.providers;
CREATE POLICY providers_select_own ON public.providers
  FOR SELECT TO authenticated
  USING (owner_user_id = auth.uid());

-- No public/anon SELECT policy on the base table at all: it holds
-- aadhaar_number/pan_card, and Postgres RLS can't restrict individual
-- columns within one row policy. Storefront-safe public reads are served
-- from the providers_storefront view below instead, which only selects the
-- non-sensitive columns and is safe to expose to anon.
DROP VIEW IF EXISTS public.providers_storefront;
CREATE VIEW public.providers_storefront AS
SELECT id, name, bio, description, avatar_url, specialty, instagram_handle,
       internal_links, rating, is_verified, created_at
FROM public.providers;

GRANT SELECT ON public.providers_storefront TO anon, authenticated;

DROP POLICY IF EXISTS providers_insert_own ON public.providers;
CREATE POLICY providers_insert_own ON public.providers
  FOR INSERT TO authenticated
  WITH CHECK (owner_user_id = auth.uid());  -- trigger 2b sets this; this just double-checks

DROP POLICY IF EXISTS providers_update_own ON public.providers;
CREATE POLICY providers_update_own ON public.providers
  FOR UPDATE TO authenticated
  USING (owner_user_id = auth.uid())
  WITH CHECK (owner_user_id = auth.uid());

-- No DELETE policy: nobody (besides service_role) can delete a provider row.


-- ----------------------------------------------------------------------------
-- 4. products_box
-- ----------------------------------------------------------------------------
ALTER TABLE public.products_box ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS products_box_select_public ON public.products_box;
CREATE POLICY products_box_select_public ON public.products_box
  FOR SELECT
  USING (true);  -- storefront listing: no PII on this table, fine to be public

DROP POLICY IF EXISTS products_box_insert_own ON public.products_box;
CREATE POLICY products_box_insert_own ON public.products_box
  FOR INSERT TO authenticated
  WITH CHECK (provider_id = public.current_provider_id());

DROP POLICY IF EXISTS products_box_update_own ON public.products_box;
CREATE POLICY products_box_update_own ON public.products_box
  FOR UPDATE TO authenticated
  USING (provider_id = public.current_provider_id())
  WITH CHECK (provider_id = public.current_provider_id());

DROP POLICY IF EXISTS products_box_delete_own ON public.products_box;
CREATE POLICY products_box_delete_own ON public.products_box
  FOR DELETE TO authenticated
  USING (provider_id = public.current_provider_id());


-- ----------------------------------------------------------------------------
-- 5. follows
-- ----------------------------------------------------------------------------
ALTER TABLE public.follows ENABLE ROW LEVEL SECURITY;

-- A provider can see who follows them.
DROP POLICY IF EXISTS follows_select_provider ON public.follows;
CREATE POLICY follows_select_provider ON public.follows
  FOR SELECT TO authenticated
  USING (provider_id = public.current_provider_id());

-- A customer can see their own follow list. Uses the SECURITY DEFINER
-- helper (not a direct subquery on profile) — see the recursion note on
-- the helper functions above.
DROP POLICY IF EXISTS follows_select_own_customer ON public.follows;
CREATE POLICY follows_select_own_customer ON public.follows
  FOR SELECT TO authenticated
  USING (follower_id = public.current_customer_profile_id());

DROP POLICY IF EXISTS follows_insert_own_customer ON public.follows;
CREATE POLICY follows_insert_own_customer ON public.follows
  FOR INSERT TO authenticated
  WITH CHECK (follower_id = public.current_customer_profile_id());

DROP POLICY IF EXISTS follows_delete_own_customer ON public.follows;
CREATE POLICY follows_delete_own_customer ON public.follows
  FOR DELETE TO authenticated
  USING (follower_id = public.current_customer_profile_id());

-- No UPDATE policy: a follow row is created/removed, never edited in place.


-- ----------------------------------------------------------------------------
-- 0d. PROVIDER PII (Aadhaar/PAN) — real at-rest protection, not just UI mask
-- ----------------------------------------------------------------------------
-- Decision made here, and why: Aadhaar/PAN are collected once for provider
-- verification and aren't something the UI round-trips back for repeated
-- display (see app.js — settings now shows "on file, ending in 1234" rather
-- than fetching the live value back). Given that, we store a KEYED HASH
-- (HMAC-SHA256 with a server-side secret the anon/authenticated roles can
-- never read) plus the last 4 digits in plaintext for display, and never
-- persist the full number anywhere, in any column, at all.
--
-- TRADEOFF — flagging explicitly per the task: this means the full Aadhaar/
-- PAN number can NEVER be recovered again by anyone, including an admin,
-- including with direct database access. If this business has a real KYC-
-- dispute workflow where an admin needs to see the full number again (not
-- just confirm a value the provider re-enters matches what's on file), a
-- hash is the wrong tool — you'd want reversible encryption instead
-- (Supabase Vault, or pgcrypto with a key that's still never exposed to
-- anon/authenticated, decrypted only through a SECURITY DEFINER function
-- gated by is_admin()). That's a bigger lift and a real product decision,
-- not something to silently pick — if it turns out full retrieval IS
-- needed, come back to this section rather than the hash-only approach.
--
-- The secret lives in a table that anon/authenticated have zero grants on,
-- inside a schema they have zero USAGE on either — belt and suspenders.
-- Only a SECURITY DEFINER function (owned by the table owner) can reach it.
-- (Supabase Vault is the more turnkey version of this same idea if it's
-- available on your plan; this achieves the same isolation property with
-- plain Postgres privileges, which is what makes it testable outside
-- Supabase too.)
CREATE SCHEMA IF NOT EXISTS private;
REVOKE ALL ON SCHEMA private FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS private.pii_secrets (
  id int PRIMARY KEY DEFAULT 1,
  hmac_secret text NOT NULL,
  CONSTRAINT pii_secrets_single_row CHECK (id = 1)
);
REVOKE ALL ON private.pii_secrets FROM PUBLIC, anon, authenticated;

-- Seed a random secret once. Rotating this later invalidates every existing
-- hash for equality checks (old values will no longer verify) — if you ever
-- need to rotate, plan a re-verification flow, don't just swap it silently.
INSERT INTO private.pii_secrets (id, hmac_secret)
VALUES (1, encode(gen_random_bytes(32), 'hex'))
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION private.pii_hmac(value text)
RETURNS text
LANGUAGE sql
SECURITY DEFINER
SET search_path = private, public
STABLE
AS $$
  SELECT encode(hmac(value, (SELECT hmac_secret FROM private.pii_secrets WHERE id = 1), 'sha256'), 'hex');
$$;
REVOKE ALL ON FUNCTION private.pii_hmac(text) FROM PUBLIC, anon, authenticated;
-- Deliberately no GRANT EXECUTE to anon/authenticated. The only caller is
-- the trigger below, which runs as the function owner (SECURITY DEFINER),
-- so it can call this even though the connected client role cannot.

ALTER TABLE public.providers
  ADD COLUMN IF NOT EXISTS aadhaar_hash text,
  ADD COLUMN IF NOT EXISTS aadhaar_last4 text,
  ADD COLUMN IF NOT EXISTS pan_hash text,
  ADD COLUMN IF NOT EXISTS pan_last4 text;

-- aadhaar_number / pan_card (the original plaintext columns) are kept in
-- the schema as WRITE-ONLY, TRANSIENT input columns: a client can still
-- send a value through them on insert/update (app.js does, unchanged), but
-- the trigger below computes the hash + last4 and then hard-nulls the
-- plaintext column in the same row before it's ever written to disk. A
-- SELECT on aadhaar_number/pan_card will only ever return NULL from this
-- point forward, for every row, including rows written before this
-- migration (see the backfill below).
CREATE OR REPLACE FUNCTION public.protect_provider_pii()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private
AS $$
BEGIN
  IF NEW.aadhaar_number IS NOT NULL AND NEW.aadhaar_number <> '' THEN
    NEW.aadhaar_hash := private.pii_hmac(NEW.aadhaar_number);
    NEW.aadhaar_last4 := right(NEW.aadhaar_number, 4);
  END IF;
  NEW.aadhaar_number := NULL;  -- never persisted, regardless of the branch above

  IF NEW.pan_card IS NOT NULL AND NEW.pan_card <> '' THEN
    NEW.pan_hash := private.pii_hmac(NEW.pan_card);
    NEW.pan_last4 := right(upper(NEW.pan_card), 4);
  END IF;
  NEW.pan_card := NULL;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_provider_pii ON public.providers;
CREATE TRIGGER trg_protect_provider_pii
  BEFORE INSERT OR UPDATE ON public.providers
  FOR EACH ROW EXECUTE FUNCTION public.protect_provider_pii();

-- One-time backfill: hash any plaintext Aadhaar/PAN already sitting in the
-- table from before this migration, then the trigger's own NULL-out logic
-- takes it from there on every future write. Safe to re-run — once hashed,
-- aadhaar_number is NULL and this UPDATE becomes a no-op for that row.
UPDATE public.providers
SET aadhaar_number = aadhaar_number,  -- fires the trigger via UPDATE, no other change needed
    pan_card = pan_card
WHERE (aadhaar_number IS NOT NULL AND aadhaar_number <> '')
   OR (pan_card IS NOT NULL AND pan_card <> '');


-- ----------------------------------------------------------------------------
-- 0e. CUSTOMER IDENTITY MODEL — resolving the flagged gap
-- ----------------------------------------------------------------------------
-- Decision: I found no evidence anywhere in this codebase of a separate,
-- intentional customer auth system — no checkout/storefront code, no
-- reference to `signin`/`profile` outside their own table definitions and
-- the `follows`/`orders`/`reviews` FKs pointing at them. `signin` looks like
-- the same kind of hand-rolled, pre-Supabase-Auth table that `provider_signin`
-- was for providers before this project's Supabase-Auth migration (see
-- schema.sql's flag comment on both). Running two parallel auth systems in
-- one product — Supabase Auth for providers, a separate hand-rolled
-- password table for customers — is itself a red flag: it's two things to
-- keep secure instead of one, and it's why `signin`/`provider_signin` still
-- had live, unrestricted `password_hash` columns reachable by the anon key
-- (see section 10 below — that gets locked down now too, not just flagged).
--
-- So: customers are migrated onto Supabase Auth the same way providers were,
-- using `profile` (not a new table) as the customer-side equivalent of
-- `signin_main`. `profile.user_id`, `orders.user_id`, and `reviews.user_id`
-- now point at auth.users(id) instead of the legacy `signin` table.
--
-- New-signup role now defaults to 'customer', not 'provider' — see the
-- updated handle_new_auth_user() below. In the previous version of this
-- file, ANY new Supabase Auth user with no explicit role in their metadata
-- became a signin_main provider row; that was fine while this provider
-- panel was the only thing creating Supabase Auth users in the project, but
-- it's the wrong default the moment a customer-facing app starts signing
-- people up against the same project. app.js's provider registration flow
-- already passes role:'provider' explicitly, so this default change doesn't
-- affect it.

ALTER TABLE public.profile DROP CONSTRAINT IF EXISTS profile_user_id_fkey;
ALTER TABLE public.profile
  ADD CONSTRAINT profile_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id);

ALTER TABLE public.orders DROP CONSTRAINT IF EXISTS orders_user_id_fkey;
ALTER TABLE public.orders
  ADD CONSTRAINT orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id);

ALTER TABLE public.reviews DROP CONSTRAINT IF EXISTS reviews_user_id_fkey;
ALTER TABLE public.reviews
  ADD CONSTRAINT reviews_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id);

-- Replaces the section-2a trigger: same job for providers/admins (still
-- goes to signin_main), now branches to `profile` for everyone else.
CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_role text := COALESCE(NEW.raw_user_meta_data->>'role', 'customer');
BEGIN
  IF v_role IN ('provider', 'admin') THEN
    INSERT INTO public.signin_main (id, email, role, provider_id)
    VALUES (NEW.id, NEW.email, v_role, NULL)
    ON CONFLICT (id) DO NOTHING;
  ELSE
    INSERT INTO public.profile (user_id, name, avatar_url)
    VALUES (
      NEW.id,
      COALESCE(NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
      COALESCE(NEW.raw_user_meta_data->>'avatar_url', 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=150&q=80')
    )
    ON CONFLICT (user_id) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;
-- (trigger on_auth_user_created from section 2 already points at this
-- function by name, so no need to redefine the trigger itself here.
-- current_customer_profile_id() and the other cross-table helper functions
-- used below are defined up in section 1, alongside current_provider_id()
-- — they have to exist before any policy references them, and grouping
-- all SECURITY DEFINER helpers together also makes the recursion-avoidance
-- pattern they share easier to spot in one place.)


-- ----------------------------------------------------------------------------
-- 5b. profile
-- ----------------------------------------------------------------------------
ALTER TABLE public.profile ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS profile_select_own ON public.profile;
CREATE POLICY profile_select_own ON public.profile
  FOR SELECT TO authenticated
  USING (user_id = auth.uid());

-- A provider can see the profile of someone who follows them — needed for
-- the "Followers" tab in app.js, which embeds profile.name/avatar_url via
-- `follows.follower_id`. This is intentionally scoped to *their own*
-- followers only (not every customer in the system), but it is still a
-- full-row policy: a provider following this path also gets back
-- `age`/`date_of_birth`/`topic_interested`/`subscription_type`, which the
-- UI doesn't use and arguably shouldn't be exposed at all. RLS alone can't
-- restrict individual columns within one policy (same limitation noted on
-- `providers` above) — the correct follow-up is a `profile_public` view
-- (id, name, avatar_url only) with the Followers query re-pointed at it.
-- Not implemented here to keep this change set focused; flagged in
-- CUSTOMER_AUTH_TODO.md.
DROP POLICY IF EXISTS profile_select_by_followed_provider ON public.profile;
CREATE POLICY profile_select_by_followed_provider ON public.profile
  FOR SELECT TO authenticated
  USING (id IN (SELECT public.provider_follower_ids(public.current_provider_id())));

DROP POLICY IF EXISTS profile_update_own ON public.profile;
CREATE POLICY profile_update_own ON public.profile
  FOR UPDATE TO authenticated
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

-- No INSERT policy: profile rows are created only by the
-- handle_new_auth_user trigger (SECURITY DEFINER, bypasses RLS). No DELETE
-- policy: account deletion should go through the Supabase Auth admin API
-- (which cascades via the FK), not a direct client-side profile delete.


-- ----------------------------------------------------------------------------
-- 6. orders / order_items / order_shipping
-- ----------------------------------------------------------------------------
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.order_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.order_shipping ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS orders_select_provider ON public.orders;
CREATE POLICY orders_select_provider ON public.orders
  FOR SELECT TO authenticated
  USING (id IN (SELECT public.provider_visible_order_ids()));

DROP POLICY IF EXISTS orders_select_own_customer ON public.orders;
CREATE POLICY orders_select_own_customer ON public.orders
  FOR SELECT TO authenticated
  USING (user_id = auth.uid());

DROP POLICY IF EXISTS orders_insert_own_customer ON public.orders;
CREATE POLICY orders_insert_own_customer ON public.orders
  FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid());
-- WITH CHECK only confirms the order is being created for yourself. It does
-- NOT validate subtotal/discount_amount/coupon_pct/total_amount — those are
-- still whatever the client sends on this INSERT. The recalc trigger below
-- overwrites subtotal/total_amount from the real order_items once they
-- exist, which closes the "insert an order with a fake total" hole, but
-- discount_amount/coupon_pct/shipping_cost/gift_wrap_cost are NOT
-- independently validated against a real coupon/shipping-rate table here —
-- that table doesn't exist in this schema. Flagged in CUSTOMER_AUTH_TODO.md
-- rather than solving it with an invented coupon-validation scheme.

DROP POLICY IF EXISTS order_items_select_provider ON public.order_items;
CREATE POLICY order_items_select_provider ON public.order_items
  FOR SELECT TO authenticated
  USING (product_id IN (SELECT public.provider_visible_product_ids()));

DROP POLICY IF EXISTS order_items_select_own_customer ON public.order_items;
CREATE POLICY order_items_select_own_customer ON public.order_items
  FOR SELECT TO authenticated
  USING (order_id IN (SELECT public.customer_own_order_ids()));

DROP POLICY IF EXISTS order_items_insert_own_customer ON public.order_items;
CREATE POLICY order_items_insert_own_customer ON public.order_items
  FOR INSERT TO authenticated
  WITH CHECK (
    order_id IN (SELECT public.customer_own_order_ids())
    -- unit_price must match the product's real, current price — this is
    -- the concrete mitigation for "trusting client-supplied unit_price on
    -- INSERT is risky": it isn't trusted, it's checked against the live
    -- products_box row at insert time. (products_box's own SELECT policy
    -- is an unconditional USING (true), so this subquery can't recurse.)
    AND unit_price = (SELECT price_in_rupees FROM public.products_box WHERE id::text = product_id)
  );

DROP POLICY IF EXISTS order_shipping_select_provider ON public.order_shipping;
CREATE POLICY order_shipping_select_provider ON public.order_shipping
  FOR SELECT TO authenticated
  USING (order_id IN (SELECT public.provider_visible_order_ids()));

DROP POLICY IF EXISTS order_shipping_select_own_customer ON public.order_shipping;
CREATE POLICY order_shipping_select_own_customer ON public.order_shipping
  FOR SELECT TO authenticated
  USING (order_id IN (SELECT public.customer_own_order_ids()));

DROP POLICY IF EXISTS order_shipping_insert_own_customer ON public.order_shipping;
CREATE POLICY order_shipping_insert_own_customer ON public.order_shipping
  FOR INSERT TO authenticated
  WITH CHECK (order_id IN (SELECT public.customer_own_order_ids()));

-- No UPDATE/DELETE policies for customers on any of these three tables —
-- an order isn't editable client-side once placed. orders.status
-- specifically still has NO update policy for anyone but service_role; see
-- order_item_fulfillment below for how providers report status instead.

-- Recompute orders.subtotal/total_amount from the real order_items every
-- time they change, instead of trusting whatever the client last wrote to
-- those columns directly. This runs regardless of caller (including
-- service_role) since it's a plain trigger, not an RLS policy — if you ever
-- need an admin backfill that sets historical totals directly without
-- recalculation, do it via order_items to keep them consistent, not by
-- writing to orders.subtotal/total_amount directly.
CREATE OR REPLACE FUNCTION public.recalc_order_totals()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_order_id uuid := COALESCE(NEW.order_id, OLD.order_id);
  v_subtotal numeric;
BEGIN
  SELECT COALESCE(SUM(line_total), 0) INTO v_subtotal
  FROM public.order_items WHERE order_id = v_order_id;

  UPDATE public.orders
  SET subtotal = v_subtotal,
      total_amount = GREATEST(v_subtotal - discount_amount + shipping_cost + gift_wrap_cost, 0)
  WHERE id = v_order_id;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_recalc_order_totals ON public.order_items;
CREATE TRIGGER trg_recalc_order_totals
  AFTER INSERT OR UPDATE OR DELETE ON public.order_items
  FOR EACH ROW EXECUTE FUNCTION public.recalc_order_totals();


-- ----------------------------------------------------------------------------
-- 7. order_item_fulfillment (replaces writing orders.status directly)
-- ----------------------------------------------------------------------------
ALTER TABLE public.order_item_fulfillment ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fulfillment_select_own ON public.order_item_fulfillment;
CREATE POLICY fulfillment_select_own ON public.order_item_fulfillment
  FOR SELECT TO authenticated
  USING (provider_id = public.current_provider_id());

DROP POLICY IF EXISTS fulfillment_insert_own ON public.order_item_fulfillment;
CREATE POLICY fulfillment_insert_own ON public.order_item_fulfillment
  FOR INSERT TO authenticated
  WITH CHECK (
    provider_id = public.current_provider_id()
    AND EXISTS (
      SELECT 1 FROM public.order_items oi
      WHERE oi.id = order_item_id
        AND oi.product_id IN (SELECT public.provider_visible_product_ids())
    )
  );

DROP POLICY IF EXISTS fulfillment_update_own ON public.order_item_fulfillment;
CREATE POLICY fulfillment_update_own ON public.order_item_fulfillment
  FOR UPDATE TO authenticated
  USING (provider_id = public.current_provider_id())
  WITH CHECK (provider_id = public.current_provider_id());

-- No DELETE policy: fulfillment history shouldn't disappear.


-- ----------------------------------------------------------------------------
-- 8. signin_main
-- ----------------------------------------------------------------------------
ALTER TABLE public.signin_main ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS signin_main_select_own ON public.signin_main;
CREATE POLICY signin_main_select_own ON public.signin_main
  FOR SELECT TO authenticated
  USING (id = auth.uid());

DROP POLICY IF EXISTS signin_main_select_admin ON public.signin_main;
CREATE POLICY signin_main_select_admin ON public.signin_main
  FOR SELECT TO authenticated
  USING (public.is_admin());

-- Intentionally NO INSERT/UPDATE/DELETE policy for anon or authenticated.
-- The only writers are: trigger 2a/0e (AFTER INSERT ON auth.users), trigger
-- 2c (AFTER INSERT ON providers), and the service_role key from a trusted
-- backend context if you ever need to hand-fix a row. Triggers run as the
-- function owner and bypass RLS, so this is enforced correctly even though
-- there's no explicit "allow the trigger" policy — there doesn't need to be
-- one.


-- ----------------------------------------------------------------------------
-- 9. reviews
-- ----------------------------------------------------------------------------
ALTER TABLE public.reviews ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS reviews_select_public ON public.reviews;
CREATE POLICY reviews_select_public ON public.reviews
  FOR SELECT
  USING (true);  -- storefront reviews are public read

DROP POLICY IF EXISTS reviews_insert_own_customer ON public.reviews;
CREATE POLICY reviews_insert_own_customer ON public.reviews
  FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid());
-- Not enforced: that the reviewer actually bought/received this product
-- (there's no "verified purchase" check against order_items here). Anyone
-- authenticated can review anything. Flagged in CUSTOMER_AUTH_TODO.md as a
-- follow-up (WITH CHECK EXISTS (... order_items/order_item_fulfillment
-- status = 'delivered' ...)) rather than added silently, since it changes
-- product behavior (blocks reviews from people who haven't ordered yet).

DROP POLICY IF EXISTS reviews_update_own_customer ON public.reviews;
CREATE POLICY reviews_update_own_customer ON public.reviews
  FOR UPDATE TO authenticated
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());

DROP POLICY IF EXISTS reviews_delete_own_customer ON public.reviews;
CREATE POLICY reviews_delete_own_customer ON public.reviews
  FOR DELETE TO authenticated
  USING (user_id = auth.uid());


-- ----------------------------------------------------------------------------
-- 10. Legacy tables (signin, provider_signin) — locked down, not just flagged
-- ----------------------------------------------------------------------------
-- These predate Supabase Auth and, until now, had RLS disabled entirely —
-- meaning `password_hash` on both tables was readable by anyone with the
-- anon key. schema.sql already flags them for removal pending a check of
-- other consumers; regardless of whether they get dropped, there's no
-- reason to leave them openly readable in the meantime. Enabling RLS with
-- zero policies denies all access to anon/authenticated outright
-- (service_role still has BYPASSRLS for any migration/cleanup work).
ALTER TABLE public.signin ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.provider_signin ENABLE ROW LEVEL SECURITY;
-- No policies defined for either table — this is intentional, not an
-- oversight. Do not add a permissive policy here; migrate any remaining
-- reads/writes to the auth.users + signin_main / profile model instead.

-- ----------------------------------------------------------------------------
-- 11. Remaining out-of-scope items — see CUSTOMER_AUTH_TODO.md
-- ----------------------------------------------------------------------------
-- The customer identity gap this section used to flag is now resolved (see
-- 0e above). What's left unresolved is documented in CUSTOMER_AUTH_TODO.md
-- rather than guessed at here: coupon/discount validation on orders,
-- atomic stock decrement + payment confirmation for checkout, verified-
-- purchase gating on reviews, and the profile-oversharing-to-providers
-- tradeoff noted in section 5b.


-- ============================================================================
-- 12. POLICY TEST CHECKLIST (manual QA — run these as each role/user)
-- ============================================================================
-- This checklist has been executed as literal SQL against schema.sql +
-- this file, loaded into a real Postgres 16 instance with a Supabase-auth
-- shim (roles anon/authenticated/service_role, an auth.users table, and an
-- auth.uid() reading a simulated JWT claim). Every line below is annotated
-- [VERIFIED] and reflects the ACTUAL result observed on the FINAL version
-- of this file, not the intended one — where the two differed during
-- development, the policy was fixed and the whole suite re-run from a
-- clean database, not just the one failing line.
--
-- Bugs this process actually caught (would not have been visible from
-- re-reading the policies):
--   1. schema.sql: order_items.line_total used a DEFAULT expression that
--      referenced another column, which Postgres rejects outside a
--      GENERATED column — schema.sql failed to load at all until fixed.
--   2. rls_policies.sql: "infinite recursion detected in policy" on
--      profile (via follows) and on orders/order_items/order_shipping (via
--      each other) — each table's policy directly subqueried a table whose
--      own policy subqueried back. Fixed with SECURITY DEFINER helper
--      functions (provider_follower_ids, provider_visible_order_ids,
--      provider_visible_product_ids, customer_own_order_ids) that break
--      the cycle. Re-run confirmed zero recursion errors across both the
--      original checklist and every new customer/PII scenario below.
-- Both are fixed in the version of schema.sql/rls_policies.sql shipped
-- alongside this checklist.
--
-- Legend: [anon] = no Authorization header / anon key only.
--         [A] = authenticated as Provider A. [B] = authenticated as Provider B.
--         [C] = authenticated as Customer C. [admin] = authenticated, role=admin.
--         [pending] = authenticated, signin_main.role='provider' but
--                     provider_id IS NULL (registration interrupted).
--         [ghost] = authenticated with a syntactically valid JWT sub claim
--                   that does not correspond to any row in auth.users
--                   (simulates a forged/stale token).
--
-- providers
--   [anon]    SELECT * FROM providers                        -> 0 rows [VERIFIED]
--   [anon]    SELECT * FROM providers_storefront              -> all providers, no aadhaar/pan/hash columns [VERIFIED]
--   [A]       SELECT * FROM providers WHERE id = A.id         -> A's own row; aadhaar_number/pan_card always NULL (write-only now); aadhaar_hash/last4 present [VERIFIED]
--   [A]       SELECT * FROM providers WHERE id = B.id         -> 0 rows [VERIFIED]
--   [A]       UPDATE providers SET name=... WHERE id = B.id   -> 0 rows affected [VERIFIED]
--   [anon]    INSERT INTO providers (...)                      -> rejected, no policy for anon [VERIFIED]
--   [A]       INSERT providers (..., owner_user_id: B.id)       -> succeeds; owner_user_id silently forced to A, NOT B, by trigger [VERIFIED]
--   [A]       INSERT providers (..., aadhaar_number: '111122223333') -> row stores aadhaar_hash + aadhaar_last4='3333'; aadhaar_number reads back NULL [VERIFIED]
--   [ghost]   INSERT providers (...)                            -> rejected by FK (owner_user_id references auth.users, ghost uid doesn't exist there) — defense-in-depth beyond RLS [VERIFIED]
--
-- products_box
--   [anon]  SELECT * FROM products_box                       -> all products (storefront) [VERIFIED]
--   [A]     INSERT INTO products_box (provider_id: B.id, ...) -> rejected [VERIFIED]
--   [A]     UPDATE products_box SET ... WHERE provider_id=B.id -> 0 rows affected [VERIFIED]
--   [A]     DELETE FROM products_box WHERE provider_id=A.id   -> succeeds for A's own products only [VERIFIED]
--   [pending] INSERT products_box (provider_id: NULL)          -> rejected (current_provider_id() is NULL; NULL = NULL is not TRUE in SQL, so this does NOT accidentally pass) [VERIFIED]
--   [ghost]   SELECT * FROM products_box                       -> all products, unaffected — storefront read is intentionally public regardless of identity [VERIFIED]
--
-- follows
--   [A]     SELECT * FROM follows WHERE provider_id = A.id    -> A's followers [VERIFIED]
--   [A]     SELECT * FROM follows WHERE provider_id = B.id    -> 0 rows [VERIFIED]
--
-- profile (new)
--   [C]     SELECT * FROM profile WHERE user_id = auth.uid()  -> C's own row, all columns [VERIFIED]
--   [C]     SELECT * FROM profile WHERE id = <other customer>  -> 0 rows, UNLESS that customer follows a provider C also happens to be [VERIFIED]
--   [A]     SELECT profile row of a customer who follows A     -> full row returned (see 5b tradeoff note — more than name/avatar, flagged in CUSTOMER_AUTH_TODO.md) [VERIFIED]
--   [A]     SELECT profile row of a customer who does NOT follow A -> 0 rows [VERIFIED]
--   [C]     UPDATE own profile                                 -> succeeds [VERIFIED]
--   [C]     INSERT INTO profile (...)                           -> rejected, no client INSERT policy (trigger-only) [VERIFIED]
--
-- orders / order_items / order_shipping
--   [A]     SELECT * FROM orders                              -> only orders containing >=1 of A's products [VERIFIED]
--   [A]     SELECT * FROM order_items                         -> only line items whose product_id belongs to A, even within an order shared with B [VERIFIED]
--   [A]     SELECT * FROM order_shipping                      -> only shipping rows for orders containing A's products [VERIFIED]
--   [A]     UPDATE orders SET status=... WHERE id = <any>      -> rejected, no UPDATE policy exists at all [VERIFIED]
--   [C]     INSERT orders (user_id: C.uid)                     -> succeeds, subtotal/total_amount start at whatever client sent [VERIFIED]
--   [C]     INSERT order_items (order_id: own order, unit_price: tampered/too-low) -> rejected (must equal live products_box.price_in_rupees) [VERIFIED]
--   [C]     INSERT order_items (order_id: own order, unit_price: correct)          -> succeeds; orders.subtotal/total_amount auto-recalculated to match afterward [VERIFIED]
--   [C]     INSERT order_items (order_id: SOMEONE ELSE's order)  -> rejected [VERIFIED]
--   [C]     SELECT another customer's orders/order_items/order_shipping -> 0 rows [VERIFIED]
--
-- order_item_fulfillment
--   [A]     INSERT for an order_item belonging to A's product  -> succeeds, provider_id checked = A [VERIFIED]
--   [A]     INSERT for an order_item belonging to B's product  -> rejected [VERIFIED]
--   [A]     INSERT with provider_id spoofed to B for A's OWN item -> rejected (provider_id must equal current_provider_id() too, not just reference a real item of A's) [VERIFIED]
--   [A]     UPDATE status WHERE provider_id = A.id             -> succeeds [VERIFIED]
--   [A]     UPDATE status WHERE provider_id = B.id             -> 0 rows affected [VERIFIED]
--   [A]     INSERT for a non-existent order_item_id (dangling FK) -> rejected by RLS (EXISTS check fails before the FK constraint is even reached) [VERIFIED — adversarial case]
--   [A]     INSERT for an order_item whose product_id matches no products_box row (orphaned reference) -> rejected [VERIFIED — adversarial case]
--
-- signin_main
--   [anon]    SELECT * FROM signin_main                          -> 0 rows [VERIFIED]
--   [A]       SELECT * FROM signin_main WHERE id = A.auth_uid     -> A's own row only [VERIFIED]
--   [A]       SELECT * FROM signin_main WHERE id = B.auth_uid     -> 0 rows (A is not admin) [VERIFIED]
--   [A]       INSERT/UPDATE/DELETE signin_main (any row)          -> rejected, no policy exists for these [VERIFIED]
--   [admin]   SELECT * FROM signin_main                           -> all rows, including providers/other admins [VERIFIED]
--   [pending] SELECT own signin_main row                          -> 1 row, provider_id NULL, no error, no escalation [VERIFIED — adversarial case]
--
-- reviews
--   [anon]  SELECT * FROM reviews                               -> all reviews (public) [VERIFIED]
--   [anon]  INSERT INTO reviews (...)                            -> rejected [VERIFIED]
--   [C]     INSERT reviews (user_id: C.uid)                      -> succeeds (NOTE: no verified-purchase check — see CUSTOMER_AUTH_TODO.md) [VERIFIED]
--   [C]     UPDATE/DELETE another customer's review               -> 0 rows affected [VERIFIED]
--
-- legacy tables (signin, provider_signin)
--   [anon]  SELECT password_hash FROM signin                     -> 0 rows (previously: all rows, unrestricted — this was a live hole, now closed) [VERIFIED]
--   [anon]  SELECT password_hash FROM provider_signin            -> 0 rows [VERIFIED]
--
-- current_provider_id() / current_customer_profile_id() edge cases
--   [ghost] SELECT current_provider_id()                         -> NULL, no error [VERIFIED — adversarial case]
--   [ghost] SELECT current_customer_profile_id()                 -> NULL, no error [VERIFIED — adversarial case]
--
-- private schema (Aadhaar/PAN secret isolation)
--   [A]     SELECT * FROM private.pii_secrets                    -> "permission denied for schema private" [VERIFIED]
--   [A]     SELECT private.pii_hmac('123412341234')               -> "permission denied for schema private" [VERIFIED]
-- ============================================================================
