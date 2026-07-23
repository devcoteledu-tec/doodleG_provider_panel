-- Doodle G Database Setup Schema
-- Run these scripts in your Supabase SQL Editor to prepare the tables.
--
-- FLAGGED FOR REVIEW (see rls_policies.sql item 6 / cleanup notes at the end
-- of this file): `signin`, `profile`, and `provider_signin` below all
-- predate the current Supabase-Auth-based login (see app.js — providers now
-- authenticate via supabaseClient.auth + signin_main, not these tables).
-- `signin` and `provider_signin` still carry `password_hash` columns, which
-- is unused/dead auth surface if nothing in the current codebase reads or
-- writes them anymore. I did not confirm whether any other project
-- (the customer-facing storefront app, an admin tool, etc.) still depends
-- on them, so I'm flagging rather than dropping them here — grep every
-- consumer of this database for `.from('signin')`, `.from('profile')`, and
-- `.from('provider_signin')` before removing/migrating.

CREATE TABLE public.signin (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_name text NOT NULL,
  mobile_number text,
  email text NOT NULL UNIQUE,
  password_hash text,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  is_blocked boolean DEFAULT false,
  CONSTRAINT signin_pkey PRIMARY KEY (id)
);

CREATE TABLE public.profile (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid UNIQUE,
  subscription_type text NOT NULL DEFAULT 'prime'::text CHECK (subscription_type = ANY (ARRAY['urgent'::text, 'major'::text, 'prime'::text])),
  name text NOT NULL,
  age integer,
  date_of_birth date,
  topic_interested text[] NOT NULL DEFAULT '{}'::text[],
  like_products_id uuid[] NOT NULL DEFAULT '{}'::uuid[],
  avatar_url text DEFAULT 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=150&q=80'::text,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT profile_pkey PRIMARY KEY (id),
  CONSTRAINT profile_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.signin(id)
);

CREATE TABLE public.providers (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  name text NOT NULL,
  bio text DEFAULT ''::text,
  description text DEFAULT ''::text,
  avatar_url text DEFAULT 'https://images.unsplash.com/photo-1522075469751-3a6694fb2f61?auto=format&fit=crop&w=150&q=80'::text,
  specialty text[] NOT NULL DEFAULT '{}'::text[],
  instagram_handle text,
  internal_links jsonb NOT NULL DEFAULT '[]'::jsonb,
  rating numeric DEFAULT 5.0 CHECK (rating >= 1::numeric AND rating <= 5::numeric),
  is_verified boolean DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  score numeric CHECK (score > 5::numeric),
  aadhaar_number character varying,
  pan_card character varying,
  CONSTRAINT providers_pkey PRIMARY KEY (id)
);

CREATE TABLE public.follows (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  follower_id uuid,
  following_id uuid,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  provider_id uuid,
  CONSTRAINT follows_pkey PRIMARY KEY (id),
  CONSTRAINT follows_follower_id_fkey FOREIGN KEY (follower_id) REFERENCES public.profile(id),
  CONSTRAINT follows_following_id_fkey FOREIGN KEY (following_id) REFERENCES public.profile(id),
  CONSTRAINT follows_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.providers(id)
);

CREATE TABLE public.products_box (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  star_count numeric DEFAULT 5.0 CHECK (star_count >= 1::numeric AND star_count <= 5::numeric),
  product_name text NOT NULL,
  product_images text[] NOT NULL CHECK (cardinality(product_images) >= 3 AND cardinality(product_images) <= 5),
  price_in_rupees numeric NOT NULL,
  product_description text,
  likes integer DEFAULT 0,
  shipping_and_products text,
  saving_percentage numeric DEFAULT 0,
  total_reviews integer DEFAULT 0,
  category text NOT NULL,
  status text DEFAULT 'NEW'::text CHECK (status = ANY (ARRAY['NEW'::text, 'SALE'::text, 'HOT'::text, 'LIMITED'::text])),
  available_qty integer DEFAULT 0,
  total_likes integer DEFAULT 0,
  date_of_listed timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  sales_count integer DEFAULT 0,
  gradient text DEFAULT 'from-gray-500 to-gray-700'::text,
  emoji text DEFAULT '🎁'::text,
  provider_id uuid,
  CONSTRAINT products_box_pkey PRIMARY KEY (id),
  CONSTRAINT products_box_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.providers(id)
);

CREATE TABLE public.reviews (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_name text NOT NULL,
  user_id uuid,
  date_of_posted timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  description_of_product text NOT NULL,
  rating integer NOT NULL CHECK (rating >= 1 AND rating <= 5),
  product_id uuid NOT NULL,
  CONSTRAINT reviews_pkey PRIMARY KEY (id),
  CONSTRAINT reviews_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.signin(id),
  CONSTRAINT reviews_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products_box(id)
);

CREATE TABLE public.orders (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid,
  order_number text NOT NULL DEFAULT ((('DG-'::text || to_char(timezone('utc'::text, now()), 'YYYYMMDD'::text)) || '-'::text) || substr(md5((random())::text), 1, 6)) UNIQUE,
  subtotal numeric NOT NULL DEFAULT 0,
  discount_amount numeric NOT NULL DEFAULT 0,
  coupon_code text,
  coupon_pct numeric NOT NULL DEFAULT 0,
  shipping_cost numeric NOT NULL DEFAULT 0,
  gift_wrap_cost numeric NOT NULL DEFAULT 0,
  total_amount numeric NOT NULL DEFAULT 0,
  gift_wrap boolean NOT NULL DEFAULT false,
  payment_method text DEFAULT 'Credit Card'::text,
  status text NOT NULL DEFAULT 'confirmed'::text CHECK (status = ANY (ARRAY['confirmed'::text, 'processing'::text, 'shipped'::text, 'delivered'::text, 'cancelled'::text])),
  placed_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT orders_pkey PRIMARY KEY (id),
  CONSTRAINT orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.signin(id)
);

CREATE TABLE public.order_items (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL,
  product_id text NOT NULL,
  product_name text NOT NULL,
  product_emoji text DEFAULT '🎁'::text,
  selected_color text,
  quantity integer NOT NULL CHECK (quantity > 0),
  unit_price numeric NOT NULL CHECK (unit_price >= 0::numeric),
  line_total numeric GENERATED ALWAYS AS ((quantity)::numeric * unit_price) STORED,
  CONSTRAINT order_items_pkey PRIMARY KEY (id),
  CONSTRAINT order_items_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(id)
);

CREATE TABLE public.order_shipping (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL UNIQUE,
  full_name text NOT NULL,
  email text NOT NULL,
  phone text,
  street_address text NOT NULL,
  city text NOT NULL,
  zip_code text,
  country text DEFAULT 'India'::text,
  tracking_number text,
  estimated_delivery date,
  CONSTRAINT order_shipping_pkey PRIMARY KEY (id),
  CONSTRAINT order_shipping_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(id)
);

CREATE TABLE public.provider_signin (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  provider_id uuid UNIQUE,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT provider_signin_pkey PRIMARY KEY (id),
  CONSTRAINT provider_signin_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.providers(id)
);

CREATE TABLE public.signin_main (
  id uuid NOT NULL,
  email text NOT NULL,
  role text NOT NULL CHECK (role = ANY (ARRAY['admin'::text, 'provider'::text])),
  provider_id uuid,
  created_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT signin_main_pkey PRIMARY KEY (id),
  CONSTRAINT profiles_id_fkey FOREIGN KEY (id) REFERENCES auth.users(id),
  CONSTRAINT profiles_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.providers(id)
);
