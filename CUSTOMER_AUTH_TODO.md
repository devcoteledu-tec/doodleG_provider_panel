# Customer identity model — decision record & open items

## Decision made

No checkout, review-submission, or other customer-facing code exists
anywhere in this project — only the `orders`/`order_items`/`order_shipping`/
`reviews`/`profile`/`signin` table definitions in `schema.sql`, with
`orders.user_id` and `reviews.user_id` pointing at the legacy `signin`
table (a hand-rolled `password_hash` table, the same shape `provider_signin`
was before providers were migrated to Supabase Auth).

I found no evidence anywhere in the codebase of an intentional, separate
customer auth system. Running two parallel auth systems in one product —
Supabase Auth for providers, a hand-rolled password table for customers —
is itself a red flag (twice the surface area to keep secure, and it's
exactly how `signin`/`provider_signin` ended up as an open hole: RLS was
never enabled on either, so the anon key could read every stored password
hash directly, for both providers and customers, until this pass). So:
customers are migrated onto Supabase Auth the same way providers were,
using `profile` as the customer-side equivalent of `signin_main`.

**What changed** (see `rls_policies.sql` sections 0d/0e/5b/6/9 for the SQL,
and the updated POLICY TEST CHECKLIST at the bottom of that file for what
was actually verified against a live database):

- `profile.user_id`, `orders.user_id`, `reviews.user_id` now reference
  `auth.users(id)` instead of the legacy `signin` table.
- A new Supabase Auth signup defaults to a `profile` row (role `customer`)
  unless `role: 'provider'` or `role: 'admin'` is explicitly passed in
  signup metadata — this is a behavior change from the previous version of
  this file, which defaulted every new signup to a `signin_main` provider
  row regardless of intent. That was fine while this provider panel was the
  only thing creating Supabase Auth users in the project; it stops being
  safe the moment a customer-facing app shares the same project.
- `orders`/`order_items`/`order_shipping` gained customer-facing SELECT and
  INSERT policies (a customer can create and read their own orders).
- `order_items` INSERT validates `unit_price` against the live
  `products_box.price_in_rupees` at insert time — a client can't submit an
  arbitrary price.
- A trigger recalculates `orders.subtotal`/`total_amount` from the real
  `order_items` after every insert/update/delete, instead of trusting
  whatever the client last wrote to those columns.
- `reviews` gained customer-facing INSERT/UPDATE/DELETE policies scoped to
  `user_id = auth.uid()`.
- `signin`/`provider_signin` had RLS enabled with zero policies — fully
  locked down rather than just flagged, since the open read was a real,
  live hole regardless of what happens to these tables long-term.

## What's still open — needs a decision before a real storefront ships

These were flagged rather than silently solved, because solving them
requires either a product decision or actual checkout code this project
doesn't have:

1. **Coupon/discount validation.** `orders.discount_amount`/`coupon_pct` are
   still whatever the client sends on INSERT — there's no coupon table to
   validate against, so nothing here checks a discount is legitimate. The
   totals-recalculation trigger fixes the *subtotal* (computed from real
   line items), but a customer could still set `discount_amount` to
   anything. Needs either a real coupons table + validation, or moving
   discount application server-side entirely.

2. **Checkout should probably be an Edge Function, not raw client inserts.**
   What's implemented here (RLS + price-check + totals-recalc trigger)
   meaningfully reduces the risk of a raw `.insert()` into `orders`/
   `order_items` from the client, but it doesn't solve everything a real
   checkout needs: atomic stock decrement (two customers buying the last
   unit at once), payment confirmation before an order is considered
   placed, or retrying a failed multi-table insert cleanly. A
   `service_role`-backed Edge Function that does all of this in one
   transaction is the more robust long-term answer. Not built here — this
   project has no payment integration to hang it off of.

3. **Reviews have no verified-purchase check.** Any authenticated customer
   can review any product, whether or not they've ordered it. Adding
   `WITH CHECK (EXISTS (... order_items/order_item_fulfillment
   status='delivered' ...))` to `reviews_insert_own_customer` is
   straightforward once that's a wanted behavior — not added here since it
   changes product behavior (blocks reviews from people who haven't
   ordered) rather than just closing a security gap, so it seemed like a
   product call rather than something to decide unilaterally.

4. **`profile` visibility to providers is broader than the UI needs.**
   `profile_select_by_followed_provider` (rls_policies.sql, section 5b)
   lets a provider read the *full* profile row of anyone who follows them —
   including `age`, `date_of_birth`, `topic_interested`, `subscription_type`
   — to support the Followers tab, which only actually displays name and
   avatar. Postgres RLS can't restrict individual columns within one row
   policy (the same limitation that's why `providers`' public reads go
   through the `providers_storefront` view instead of a table policy). The
   clean fix is a `profile_public` view (id, name, avatar_url only) with
   the Followers query in `app.js` re-pointed at it. Not implemented here
   to keep this change set focused on the three tasks asked for — worth
   doing before this is treated as fully privacy-hardened.

5. **Account deletion / GDPR-style requests.** No DELETE policy exists on
   `profile` for customers — deletion is expected to go through the
   Supabase Auth admin API (which cascades via the FK to `auth.users`), not
   a direct client-side delete. If there's a self-service "delete my
   account" requirement, that flow doesn't exist yet.

## What I did NOT do

I did not invent a coupon-validation scheme, a payment integration, or a
verified-purchase rule for reviews — each of those is a product decision
with real tradeoffs (e.g., should a customer be able to review a product
before delivery? should discount codes stack?) that isn't mine to make
silently. The RLS/schema changes in this pass close the access-control gaps
that existed regardless of those decisions (arbitrary price injection,
unrestricted table access, the open `signin`/`provider_signin` read hole);
the items above are the ones that need a person, not just a policy fix.
