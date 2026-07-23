// Supabase configuration
//
// FILL THESE IN before deploying, then leave them as-is — every provider
// who loads this app gets these values baked into the page; there is no
// per-user setup step anymore.
//
// The anon key is DESIGNED to be public. It ships inside the compiled JS
// of every Supabase client app that exists — that's normal, not a leak.
// The actual access control is Row Level Security (see rls_policies.sql);
// the anon key on its own grants nothing RLS doesn't allow.
//
// NEVER put the service_role key here, or anywhere in this repo. That key
// bypasses RLS entirely — anyone who gets it can read/write every table,
// unrestricted. It belongs only in a server-side environment (an Edge
// Function, a backend), never in code that ships to a browser.
const SUPABASE_CONFIG = {
  url: 'https://YOUR-PROJECT-REF.supabase.co',
  anonKey: 'YOUR-ANON-PUBLIC-KEY',

  get isConfigured() {
    return Boolean(this.url) && Boolean(this.anonKey)
      && !this.url.includes('YOUR-PROJECT-REF')
      && !this.anonKey.includes('YOUR-ANON-PUBLIC-KEY');
  }
};
