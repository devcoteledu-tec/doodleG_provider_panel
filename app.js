let supabaseClient = null;
let currentProvider = null;
let currentTab = 'dashboard';
let allProducts = [];
let allFollowers = [];
let allOrders = [];

// Session state
let sessionUser = null;

// DOM Elements
const authSection = document.getElementById('auth-section');
const panelSection = document.getElementById('panel-section');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const toastContainer = document.getElementById('toast-container');
const productModal = document.getElementById('product-modal');
const productForm = document.getElementById('product-form');

// ---------------------------------------------------------------------------
// escapeHtml — every render function below runs untrusted/less-trusted
// strings (customer shipping data, product text supplied by other
// providers-as-viewed-by-admin-contexts, etc.) through this before putting
// them into innerHTML. This is defense-in-depth: it applies at render time
// regardless of what's already sitting in the database, rather than
// assuming upstream inserts were already sanitized.
// ---------------------------------------------------------------------------
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Builds a https://wa.me/<digits> link from a raw shipping phone number.
// wa.me only accepts digits (with implicit country code, no "+" or
// separators), so we strip everything else out here. Returns null when
// there's nothing usable to link to, so callers can skip rendering the
// icon entirely instead of pointing it at a dead/empty chat link.
function buildWhatsAppLink(rawPhone) {
  if (!rawPhone) return null;
  const digits = String(rawPhone).replace(/\D/g, '');
  if (!digits) return null;
  return `https://wa.me/${digits}`;
}

// Builds a tel:<digits> link from a raw shipping phone number, for the
// "Connect" column's call icon. Returns null when there's nothing usable
// to link to, so callers can skip rendering the icon entirely.
function buildCallLink(rawPhone) {
  if (!rawPhone) return null;
  const digits = String(rawPhone).replace(/[^\d+]/g, '');
  if (!digits) return null;
  return `tel:${digits}`;
}

// Toast notifications helper
function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  let iconName = 'check-circle';
  if (type === 'error') iconName = 'alert-triangle';
  if (type === 'warning') iconName = 'alert-circle';

  // message is usually a static string we wrote, but can also be a Supabase
  // error message (err.message) which we don't fully control the contents
  // of — escape it either way.
  toast.innerHTML = `<i data-lucide="${iconName}"></i> <span>${escapeHtml(message)}</span>`;
  toastContainer.appendChild(toast);
  lucide.createIcons();

  setTimeout(() => {
    toast.remove();
  }, 4000);
}

// Initial Loading
document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

function initApp() {
  if (!SUPABASE_CONFIG.isConfigured) {
    // config.js still has placeholder values — this is a deployment
    // mistake, not something an end user (one of 500+ providers) can or
    // should fix themselves. Previously this showed a modal prompting
    // whoever loaded the page to type in a Supabase URL/anon key by hand,
    // with a "Switch DB Project" button in the topbar that let any
    // signed-in provider do the same at any time. Removed both: letting
    // users repoint the whole app's backend is a real risk (accidental
    // misconfiguration, or a phishing trick pointing it at a look-alike
    // Supabase project to harvest logins), not just a UX inconvenience.
    // Fail loudly instead so a misconfigured deploy is obvious immediately.
    document.body.innerHTML = `
      <div style="max-width: 480px; margin: 15vh auto; padding: 32px; font-family: system-ui, sans-serif; text-align: center;">
        <h2 style="margin-bottom: 12px;">Configuration missing</h2>
        <p style="color: #666;">This deployment hasn't been set up with a Supabase project yet. Set <code>SUPABASE_CONFIG.url</code> and <code>SUPABASE_CONFIG.anonKey</code> in <code>config.js</code>, then redeploy.</p>
      </div>
    `;
    return;
  }
  initializeSupabase();
}

// Initialize Supabase client
function initializeSupabase() {
  try {
    supabaseClient = supabase.createClient(SUPABASE_CONFIG.url, SUPABASE_CONFIG.anonKey);
    checkAuthSession();
  } catch (err) {
    // A hardcoded config.js value is malformed — this is a deploy-time
    // problem, not something the person loading the page can fix, so
    // there's nothing useful to prompt them for here.
    document.body.innerHTML = `
      <div style="max-width: 480px; margin: 15vh auto; padding: 32px; font-family: system-ui, sans-serif; text-align: center;">
        <h2 style="margin-bottom: 12px;">Configuration error</h2>
        <p style="color: #666;">Couldn't connect using the Supabase settings in <code>config.js</code>. Double-check the URL and anon key, then redeploy.</p>
      </div>
    `;
  }
}

// Check Session — real Supabase Auth session (not a hand-rolled localStorage
// flag). This matters: every RLS policy on orders/order_items/order_shipping
// checks auth.uid() via signin_main, so unless there is a real logged-in
// Supabase Auth session, those tables will just silently return 0 rows.
async function checkAuthSession() {
  try {
    const { data: { session } } = await supabaseClient.auth.getSession();
    if (session?.user) {
      const provider_id = await resolveProviderId(session.user);
      if (provider_id) {
        sessionUser = { provider_id, email: session.user.email };
        await loadProviderProfile(provider_id, session.user.email);
        return;
      }
    }
    authSection.classList.remove('hidden');
    panelSection.classList.add('hidden');
    lucide.createIcons();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Look up this authenticated user's role + provider_id from signin_main.
// The DB decides the role/ownership here, not anything stored client-side.
//
// A signin_main row with role='provider' but provider_id === null means
// this account finished creating its Supabase Auth login but hasn't
// created its providers row yet (see registerForm handler below — that's
// the fixed, two-step, auth-first registration flow). If registration was
// interrupted before a providers row could be created (see registerForm
// below), Aadhaar/PAN are NOT recoverable here — they were never stashed
// anywhere (see registerForm's comment on why) — so the provider is
// created without them and prompted to add verification details from
// Settings once they're in.
async function resolveProviderId(authUser) {
  const { data: row, error } = await supabaseClient
    .from('signin_main')
    .select('role, provider_id')
    .eq('id', authUser.id)
    .maybeSingle();

  if (error || !row || row.role !== 'provider') {
    showToast('This account has no provider access. Contact an administrator.', 'error');
    await supabaseClient.auth.signOut();
    return null;
  }

  if (row.provider_id) {
    return row.provider_id;
  }

  // Registration was interrupted (e.g. email confirmation was required and
  // this is the first sign-in after confirming). Finish it now that we
  // have an authenticated session. No aadhaar/pan available at this point
  // — see registerForm.
  return await completeProviderRegistration(authUser, null, null);
}

// Finish provider registration: create the providers row now that we have
// an authenticated session. owner_user_id is set server-side by a trigger
// (see rls_policies.sql) — never trust/send it from the client.
// signin_main.provider_id then gets linked automatically by another
// trigger; we never write to signin_main directly from the client.
//
// aadhaarPlain/panPlain are passed directly (in-memory), NOT read from
// auth user metadata. Earlier this project stashed them in
// options.data.aadhaar/pan at signUp time so this function could pick them
// up later on the deferred (email-confirmation-pending) path — but
// Supabase Auth metadata is stored in plaintext in auth.users AND is
// included in the session's own JWT, so that would have meant a provider's
// Aadhaar/PAN sat in plaintext outside the providers table (and briefly in
// their own browser's session token) even after this file went on to hash
// it everywhere else. Now: on the immediate-session path (registerForm,
// below) the plaintext values never leave memory before being sent
// straight to this INSERT, which the database hashes on the way in (see
// protect_provider_pii() in rls_policies.sql). On the deferred path
// (resolveProviderId, above) they're simply not available — nothing was
// stashed — so the provider is created without them, and Settings prompts
// for them once the provider is authenticated (see setupPiiField below).
async function completeProviderRegistration(authUser, aadhaarPlain, panPlain) {
  const meta = authUser.user_metadata || {};
  if (!meta.pending_provider) {
    showToast('This account has no provider access. Contact an administrator.', 'error');
    await supabaseClient.auth.signOut();
    return null;
  }

  try {
    const { data: providerData, error: providerError } = await supabaseClient
      .from('providers')
      .insert([{
        name: meta.biz_name,
        bio: meta.owner_name ? `Owned by ${meta.owner_name}` : '',
        instagram_handle: meta.instagram || null,
        aadhaar_number: aadhaarPlain || null,
        pan_card: panPlain || null
      }])
      .select()
      .single();

    if (providerError) throw providerError;
    return providerData.id;
  } catch (err) {
    showToast(`Could not finish registration: ${err.message}`, 'error');
    return null;
  }
}

// Auth Tab Switches
function switchAuthTab(tab) {
  const tabs = document.querySelectorAll('.auth-tab-btn');
  tabs.forEach(t => t.classList.remove('active'));

  if (tab === 'login') {
    tabs[0].classList.add('active');
    loginForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
  } else {
    tabs[1].classList.add('active');
    loginForm.classList.add('hidden');
    registerForm.classList.remove('hidden');
  }
}

// Login logic — real Supabase Auth (bcrypt on Supabase's server, never
// compared in the browser). Role/provider_id come from signin_main after.
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;

  try {
    const { data: authData, error: authErr } = await supabaseClient.auth.signInWithPassword({
      email, password
    });
    if (authErr || !authData?.user) {
      throw new Error('Invalid email or password. Please try again.');
    }

    const provider_id = await resolveProviderId(authData.user);
    if (!provider_id) return; // resolveProviderId already toasted (+ signed out, if applicable)

    sessionUser = { provider_id, email: authData.user.email };

    showToast('Signed in successfully!', 'success');
    await loadProviderProfile(provider_id, authData.user.email);
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// Registration logic.
//
// Fixed ordering (was: insert providers first, using the anon key, *before*
// any auth account existed — which meant an anonymous caller could create
// providers rows with no account behind them at all, regardless of what RLS
// says, because the insert never depended on being authenticated in the
// first place).
//
// Now: we create the Supabase Auth account first. The business details go
// along as auth user metadata (not written to any table yet). Only once we
// have an authenticated session — either immediately, or on next sign-in if
// "Confirm email" is turned on for this project — do we insert the
// providers row, and that insert is only reachable by an authenticated
// caller (see rls_policies.sql: providers_insert_own). owner_user_id is
// stamped server-side by a trigger, never sent by the client.
registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const bizName = document.getElementById('reg-biz-name').value;
  const ownerName = document.getElementById('reg-owner-name').value;
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;
  const instagram = document.getElementById('reg-instagram').value;
  const aadhaar = document.getElementById('reg-aadhaar').value;
  const pan = document.getElementById('reg-pan').value;

  // Clean and sanitize data to match database constraints (e.g. PAN card limit of 10 chars)
  const cleanAadhaar = (aadhaar || '').trim().replace(/[\s-]/g, ''); // strip spaces/hyphens
  const cleanPan = (pan || '').trim().replace(/[\s-]/g, '').toUpperCase().substring(0, 10); // strip spaces/hyphens & limit to 10 chars

  try {
    const { data: authData, error: authErr } = await supabaseClient.auth.signUp({
      email, password,
      options: {
        // Deliberately NOT included here: aadhaar/pan. Auth user metadata
        // is stored in plaintext in auth.users and is embedded in the
        // session's own JWT — the wrong place for a government ID number
        // to sit, even briefly. See completeProviderRegistration()'s
        // comment for the full reasoning and what happens on each path.
        data: {
          role: 'provider',
          pending_provider: true,
          biz_name: bizName,
          owner_name: ownerName,
          instagram: instagram || null
        }
      }
    });
    if (authErr || !authData?.user) throw (authErr || new Error('Could not create account.'));

    if (!authData.session) {
      // Email confirmation is required on this project — there's no active
      // session yet, so we can't create the providers row (or send
      // Aadhaar/PAN anywhere) until they confirm and sign in.
      // completeProviderRegistration() runs on their first authenticated
      // sign-in instead, without Aadhaar/PAN — they'll be prompted to add
      // verification details from Settings once logged in.
      showToast('Business Registered! Check your email to confirm your account, then sign in to finish adding your verification details.', 'success');
      switchAuthTab('login');
      return;
    }

    const provider_id = await completeProviderRegistration(authData.user, cleanAadhaar, cleanPan);
    if (!provider_id) return; // already toasted

    sessionUser = { provider_id, email };
    showToast('Business Registered Successfully!', 'success');
    await loadProviderProfile(provider_id, email);
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// Logout Handler
async function handleLogout() {
  if (confirm('Are you sure you want to log out?')) {
    await supabaseClient.auth.signOut();
    currentProvider = null;
    sessionUser = null;
    authSection.classList.remove('hidden');
    panelSection.classList.add('hidden');
    showToast('Logged out successfully.', 'info');
  }
}

// Load Provider Profile
async function loadProviderProfile(providerId, email) {
  try {
    const { data: prov, error: provErr } = await supabaseClient
      .from('providers')
      .select('*')
      .eq('id', providerId)
      .single();

    if (provErr) throw provErr;
    currentProvider = prov;

    // Update sidebar UI info
    document.getElementById('provider-display-name').textContent = currentProvider.name;
    document.getElementById('provider-display-email').textContent = email;
    if (currentProvider.avatar_url) {
      document.getElementById('provider-avatar').src = currentProvider.avatar_url;
    } else {
      document.getElementById('provider-avatar').src = `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(currentProvider.name)}`;
    }

    // Display dashboard UI
    authSection.classList.add('hidden');
    panelSection.classList.remove('hidden');

    // Set settings values
    document.getElementById('set-biz-name').value = currentProvider.name;
    document.getElementById('set-instagram').value = currentProvider.instagram_handle || '';
    document.getElementById('set-email').value = email;
    document.getElementById('set-avatar').value = currentProvider.avatar_url || '';
    document.getElementById('set-bio').value = currentProvider.bio || '';
    setupPiiField('set-aadhaar', currentProvider.aadhaar_last4 || '');
    setupPiiField('set-pan', currentProvider.pan_last4 || '');

    // Load tabs data
    await loadAllData();
    switchTab('dashboard');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ---------------------------------------------------------------------------
// Aadhaar / PAN (item 4 → real protection, not just UI masking)
//
// The database no longer stores or returns the full Aadhaar/PAN value at
// all — see protect_provider_pii() in rls_policies.sql: the plaintext
// columns are hashed (HMAC-SHA256, server-side secret) and hard-nulled on
// every insert/update, before the row is ever written to disk. What comes
// back from a SELECT is only aadhaar_hash/pan_hash (opaque, not useful to
// the UI) and aadhaar_last4/pan_last4.
//
// TRADEOFF, called out explicitly: this means Settings can no longer
// "reveal" the full number — there's nothing to reveal, by design. It can
// only show "on file, ending in 1234" and offer to replace it with a new
// number. If this business ever needs an admin to pull up the full
// original value again (e.g. a KYC dispute), a hash is the wrong tool for
// that and this needs revisiting — see the TODO in rls_policies.sql
// section 0d.
// ---------------------------------------------------------------------------
function setupPiiField(fieldId, last4) {
  const input = document.getElementById(fieldId);
  input.value = last4 ? `On file, ending in ${last4}` : 'Not yet provided';
  input.readOnly = true;
  input.dataset.editing = 'false';
  input.placeholder = '';
}

function togglePiiFieldEdit(fieldId) {
  const input = document.getElementById(fieldId);
  const editing = input.dataset.editing === 'true';
  if (editing) {
    // Cancel — settingsForm's submit handler re-runs setupPiiField from
    // currentProvider once the form is saved/reloaded; for a plain cancel,
    // just restore the on-file placeholder from what we last loaded.
    const last4 = fieldId === 'set-aadhaar' ? (currentProvider.aadhaar_last4 || '') : (currentProvider.pan_last4 || '');
    setupPiiField(fieldId, last4);
  } else {
    input.value = '';
    input.readOnly = false;
    input.dataset.editing = 'true';
    input.placeholder = fieldId === 'set-aadhaar' ? '1234-5678-9012' : 'ABCDE1234F';
    input.focus();
  }
}

// Switch tabs inside panel
function switchTab(tabId) {
  currentTab = tabId;
  const tabs = document.querySelectorAll('.tab-content');
  tabs.forEach(t => t.classList.add('hidden'));

  document.getElementById(`tab-${tabId}`).classList.remove('hidden');

  // Active states in sidebar menu
  const menuItems = document.querySelectorAll('.nav-item');
  menuItems.forEach(item => {
    if (item.getAttribute('data-tab') === tabId) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });

  // Page Title Update
  const titles = {
    dashboard: ['Dashboard Overview', 'Welcome back, get an instant health check of your business.'],
    products: ['Manage Gift Products', 'Create, update and showcase your gift items on our store.'],
    followers: ['Loyal Customers & Followers', 'See who has subscribed to your business for updates.'],
    orders: ['Incoming Customer Orders', 'Fulfill and update statuses on orders purchased from you.'],
    settings: ['Business Profile Settings', 'Update details about your brand, logos, and descriptions.']
  };

  document.getElementById('page-title').textContent = titles[tabId][0];
  document.getElementById('page-subtitle').textContent = titles[tabId][1];

  lucide.createIcons();
}

// Hook up navigation menu clicks
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    const tab = e.currentTarget.getAttribute('data-tab');
    switchTab(tab);
  });
});

// Load All Business Data from DB
async function loadAllData() {
  if (!currentProvider) return;

  // Load products first, since fetchOrders relies on allProducts being populated
  await fetchProducts();

  await Promise.all([
    fetchFollowers(),
    fetchOrders()
  ]);

  updateDashboardStats();
}

// 1. PRODUCTS MANAGEMENT
async function fetchProducts() {
  try {
    const { data, error } = await supabaseClient
      .from('products_box')
      .select('*')
      .eq('provider_id', currentProvider.id)
      .order('date_of_listed', { ascending: false });

    if (error) throw error;
    allProducts = data || [];
    renderProducts();
  } catch (err) {
    showToast(`Error products: ${err.message}`, 'error');
  }
}

function renderProducts(productsList = allProducts) {
  const grid = document.getElementById('products-grid');
  grid.innerHTML = '';

  if (productsList.length === 0) {
    grid.innerHTML = `
      <div class="col-span-full text-center py-8 text-muted">
        <i data-lucide="package-x" style="width: 48px; height: 48px; margin-bottom: 12px; display: inline-block;"></i>
        <p>No products found. Start by listing a new gift item!</p>
      </div>
    `;
    lucide.createIcons();
    return;
  }

  productsList.forEach(p => {
    const card = document.createElement('div');
    card.className = 'product-card';

    const fallbackImage = 'https://images.unsplash.com/photo-1549465220-1a8b9238cd48?w=500&auto=format&fit=crop&q=60';
    const imageUrl = (p.product_images && p.product_images.length > 0) ? p.product_images[0] : fallbackImage;

    card.innerHTML = `
      <div class="product-image">
        <img src="${escapeHtml(imageUrl)}" alt="${escapeHtml(p.product_name)}" onerror="this.onerror=null;this.src='${escapeHtml(fallbackImage)}'">
        <span class="product-status-tag active">
          ${escapeHtml(p.status || 'NEW')}
        </span>
      </div>
      <div class="product-details">
        <h3>${escapeHtml(p.product_name)}</h3>
        <p class="product-description">${escapeHtml(p.product_description || 'No description provided.')}</p>
        <div class="product-meta">
          <span class="product-price">₹${Number(p.price_in_rupees).toFixed(2)}</span>
          <span class="product-stock">${Number(p.available_qty || 0)} left</span>
        </div>
        <div class="product-actions">
          <button data-action="edit-product" data-id="${escapeHtml(p.id)}" class="btn btn-secondary">
            <i data-lucide="edit"></i> Edit
          </button>
          <button data-action="delete-product" data-id="${escapeHtml(p.id)}" class="btn btn-logout">
            <i data-lucide="trash-2"></i> Delete
          </button>
        </div>
      </div>
    `;
    grid.appendChild(card);
  });
  lucide.createIcons();
}

// Event delegation for product card buttons — avoids interpolating
// user/provider-controlled strings into inline onclick="..." JS, which
// HTML-escaping alone can't fully protect (the browser HTML-decodes
// attribute values before running them as JS).
document.getElementById('products-grid').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const id = btn.dataset.id;
  if (btn.dataset.action === 'edit-product') editProduct(id);
  if (btn.dataset.action === 'delete-product') deleteProduct(id);
});

function filterProducts() {
  const query = document.getElementById('product-search').value.toLowerCase();
  const filtered = allProducts.filter(p =>
    p.product_name.toLowerCase().includes(query) ||
    (p.product_description && p.product_description.toLowerCase().includes(query))
  );
  renderProducts(filtered);
}

// Add/Edit Product Modal triggers
function openProductModal() {
  productForm.reset();
  document.getElementById('product-id').value = '';
  document.getElementById('product-modal-title').textContent = 'Add Gift Product';
  productModal.classList.remove('hidden');
}

function closeProductModal() {
  productModal.classList.add('hidden');
}

async function editProduct(id) {
  const prod = allProducts.find(p => p.id === id);
  if (!prod) return;

  document.getElementById('product-id').value = prod.id;
  document.getElementById('prod-name').value = prod.product_name;
  document.getElementById('prod-description').value = prod.product_description || '';
  document.getElementById('prod-price').value = prod.price_in_rupees;
  document.getElementById('prod-stock').value = prod.available_qty;
  document.getElementById('prod-category').value = prod.category;
  document.getElementById('prod-status').value = prod.status || 'NEW';
  document.getElementById('prod-emoji').value = prod.emoji || '🎁';
  document.getElementById('prod-gradient').value = prod.gradient || '';
  document.getElementById('prod-images').value = (prod.product_images || []).join(', ');

  document.getElementById('product-modal-title').textContent = 'Edit Gift Product';
  productModal.classList.remove('hidden');
}

// Product save submission
productForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const id = document.getElementById('product-id').value;
  const name = document.getElementById('prod-name').value;
  const description = document.getElementById('prod-description').value;
  const price = parseFloat(document.getElementById('prod-price').value);
  const stock = parseInt(document.getElementById('prod-stock').value);
  const category = document.getElementById('prod-category').value;
  const status = document.getElementById('prod-status').value;
  const emoji = document.getElementById('prod-emoji').value;
  const gradient = document.getElementById('prod-gradient').value;

  // Format images array
  const rawImages = document.getElementById('prod-images').value;
  let imagesArray = rawImages.split(',').map(u => u.trim()).filter(u => u.length > 0);

  // Enforce schema checks (between 3 and 5 images)
  const defaultImgs = [
    'https://images.unsplash.com/photo-1549465220-1a8b9238cd48?w=500',
    'https://images.unsplash.com/photo-1513201099705-a9746e1e201f?w=500',
    'https://images.unsplash.com/photo-1484712401471-05c7215e66eb?w=500'
  ];
  while (imagesArray.length < 3) {
    imagesArray.push(defaultImgs[imagesArray.length]);
  }
  if (imagesArray.length > 5) {
    imagesArray = imagesArray.slice(0, 5);
  }

  const productData = {
    provider_id: currentProvider.id,
    product_name: name,
    product_description: description,
    price_in_rupees: price,
    available_qty: stock,
    category,
    status,
    emoji,
    gradient,
    product_images: imagesArray
  };

  try {
    if (id) {
      const { error } = await supabaseClient
        .from('products_box')
        .update(productData)
        .eq('id', id);

      if (error) throw error;
      showToast('Product updated successfully!');
    } else {
      const { error } = await supabaseClient
        .from('products_box')
        .insert([productData]);

      if (error) throw error;
      showToast('Product added successfully!');
    }

    closeProductModal();
    await fetchProducts();
    updateDashboardStats();
  } catch (err) {
    showToast(err.message, 'error');
  }
});

async function deleteProduct(id) {
  if (confirm('Are you sure you want to permanently delete this product?')) {
    try {
      const { error } = await supabaseClient
        .from('products_box')
        .delete()
        .eq('id', id);

      if (error) throw error;
      showToast('Product deleted.');
      await fetchProducts();
      updateDashboardStats();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }
}

// 2. FOLLOWERS MANAGEMENT
async function fetchFollowers() {
  try {
    // Query followers joining profiles
    const { data, error } = await supabaseClient
      .from('follows')
      .select(`
        id,
        created_at,
        profile:follower_id ( name, avatar_url )
      `)
      .eq('provider_id', currentProvider.id);

    if (error) throw error;
    allFollowers = data || [];
    renderFollowers();
  } catch (err) {
    showToast(`Error followers: ${err.message}`, 'error');
  }
}

function renderFollowers(followersList = allFollowers) {
  const tbody = document.getElementById('followers-list');
  tbody.innerHTML = '';

  if (followersList.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="3" class="text-center py-4 text-muted">You don't have any followers yet. Promote your store on Doodle G!</td>
      </tr>
    `;
    return;
  }

  followersList.forEach(f => {
    const tr = document.createElement('tr');
    const profile = f.profile || { name: 'Anonymous Customer', avatar_url: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150' };

    tr.innerHTML = `
      <td>
        <img src="${escapeHtml(profile.avatar_url)}" alt="${escapeHtml(profile.name)}" class="avatar-sm" style="width: 32px; height: 32px; border-radius: 50%; object-fit: cover;">
      </td>
      <td><strong>${escapeHtml(profile.name)}</strong></td>
      <td>${escapeHtml(new Date(f.created_at).toLocaleDateString(undefined, { dateStyle: 'medium' }))}</td>
    `;
    tbody.appendChild(tr);
  });
}

function filterFollowers() {
  const query = document.getElementById('follower-search').value.toLowerCase();
  const filtered = allFollowers.filter(f => f.profile && f.profile.name.toLowerCase().includes(query));
  renderFollowers(filtered);
}

// 3. ORDERS MANAGEMENT
// Same pattern as the main admin panel's fetchOrders(): one query that pulls
// orders with their order_items and order_shipping embedded via Supabase's
// FK-based nested select, then flatten + filter client-side down to just
// this provider's own products (order_items.product_id is TEXT, so we
// compare against provider product IDs as plain strings).
//
// Status now comes from order_item_fulfillment, one row per (order_item,
// provider) — NOT from orders.status. orders.status was a single column
// shared by every provider on that order; updating it from one provider's
// panel could silently change the status seen by every other provider on
// the same order (and RLS can't safely allow that as a blanket policy —
// see rls_policies.sql item 2). Each provider now tracks their own line
// items' fulfillment independently. Fulfillment rows are created lazily
// (upserted) the first time a provider views an order that doesn't have one
// yet, seeded from the legacy orders.status as a reasonable starting point.
async function fetchOrders() {
  try {
    if (allProducts.length === 0) {
      allOrders = [];
      renderOrders();
      renderRecentOrders();
      return;
    }

    const productIds = new Set(allProducts.map(p => String(p.id)));

    const { data, error } = await supabaseClient
      .from('orders')
      .select(`
        id, order_number, user_id, status, placed_at,
        order_items ( id, order_id, product_id, product_name, product_emoji, selected_color, quantity, unit_price, line_total ),
        order_shipping ( id, order_id, full_name, email, phone, street_address, city, zip_code, country, tracking_number, estimated_delivery )
      `)
      .order('placed_at', { ascending: false });

    if (error) throw error;

    // Debug helper: if this stays empty while real orders exist in the DB,
    // it's almost always a Row Level Security policy blocking read access
    // to orders/order_items/order_shipping — see rls_policies.sql.
    console.debug('[fetchOrders] orders visible to this session:', data?.length ?? 0);

    const rows = [];
    (data || []).forEach(order => {
      const items = order.order_items || [];
      // order_shipping.order_id is UNIQUE in the schema, so Supabase embeds
      // it as a single object here, NOT an array — handle both shapes just
      // in case, since PostgREST's behavior here has been version-dependent.
      const shipping = Array.isArray(order.order_shipping)
        ? (order.order_shipping[0] || {})
        : (order.order_shipping || {});
      // Only this provider's own line items out of the order — an order can
      // legitimately contain products from several different providers.
      const providerItems = items.filter(i => productIds.has(String(i.product_id)));

      providerItems.forEach(item => {
        rows.push({
          ...item,
          order_id: order.id,
          order_number: order.order_number || 'DG-PENDING',
          placed_at: order.placed_at,
          legacy_status: order.status || 'confirmed', // seed value only, never written back to orders
          fulfillment_status: null, // filled in below once we've synced order_item_fulfillment
          customer_name: shipping.full_name || 'Customer',
          customer_email: shipping.email || 'N/A',
          customer_phone: shipping.phone || '',
          shipping_address: `${shipping.street_address || ''}, ${shipping.city || ''} (${shipping.zip_code || ''})`
        });
      });
    });

    await syncFulfillmentStatuses(rows);

    allOrders = rows.sort((a, b) => new Date(b.placed_at) - new Date(a.placed_at));

    renderOrders();
    renderRecentOrders();
  } catch (err) {
    showToast(`Error orders: ${err.message}`, 'error');
  }
}

// Fetches this provider's existing order_item_fulfillment rows for the
// given line items, and lazily creates any that are missing (RLS enforces
// provider_id = current_provider_id() on both read and insert — see
// rls_policies.sql item 7).
async function syncFulfillmentStatuses(rows) {
  if (rows.length === 0) return;
  const itemIds = rows.map(r => r.id);

  const { data: existing, error } = await supabaseClient
    .from('order_item_fulfillment')
    .select('order_item_id, status')
    .in('order_item_id', itemIds);

  if (error) {
    // Non-fatal: fall back to the legacy status so the panel still renders.
    rows.forEach(r => { r.fulfillment_status = r.legacy_status; });
    return;
  }

  const statusByItemId = new Map((existing || []).map(row => [row.order_item_id, row.status]));

  const missing = rows.filter(r => !statusByItemId.has(r.id));
  if (missing.length > 0) {
    const toInsert = missing.map(r => ({
      order_item_id: r.id,
      provider_id: currentProvider.id,
      status: r.legacy_status
    }));
    const { data: inserted, error: insertErr } = await supabaseClient
      .from('order_item_fulfillment')
      .upsert(toInsert, { onConflict: 'order_item_id' })
      .select('order_item_id, status');

    if (!insertErr) {
      (inserted || []).forEach(row => statusByItemId.set(row.order_item_id, row.status));
    }
  }

  rows.forEach(r => {
    r.fulfillment_status = statusByItemId.get(r.id) || r.legacy_status;
  });
}

function renderOrders(ordersList = allOrders) {
  const tbody = document.getElementById('orders-list');
  tbody.innerHTML = '';

  if (ordersList.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="10" class="text-center py-4 text-muted">No orders received yet.</td>
      </tr>
    `;
    return;
  }

  ordersList.forEach(o => {
    const tr = document.createElement('tr');
    tr.className = 'order-row';
    tr.dataset.orderRowId = o.id;
    const status = o.fulfillment_status || o.legacy_status;
    const waLink = buildWhatsAppLink(o.customer_phone);
    const callLink = buildCallLink(o.customer_phone);
    const callIcon = callLink
      ? `<a href="${escapeHtml(callLink)}" title="Call customer" style="display:inline-flex; vertical-align:middle; margin-right:8px;">
           <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRxz80Nlo85SdDHUxBrSp69uQi5tzk0dmZu4XIk8IGVHw&s=10" alt="Call" width="18" height="18" style="border-radius:3px;">
         </a>`
      : '';
    const waIcon = waLink
      ? `<a href="${escapeHtml(waLink)}" target="_blank" rel="noopener noreferrer" title="Chat on WhatsApp" style="display:inline-flex; vertical-align:middle;">
           <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTvg2MbImmMcal8qKmgenlQd_How3sCXGLHVEDbqA1Lwg&s=10" alt="WhatsApp" width="18" height="18" style="border-radius:3px;">
         </a>`
      : '';
    const connectCell = (callIcon || waIcon)
      ? `${callIcon}${waIcon}`
      : '<small class="text-muted">—</small>';
    tr.innerHTML = `
      <td><small class="text-muted">${escapeHtml(o.order_number)}</small></td>
      <td>
        <strong>${escapeHtml(o.customer_name)}</strong><br>
        <small class="text-muted">${escapeHtml(o.customer_email)}</small>
      </td>
      <td>${escapeHtml(o.product_emoji || '🎁')} ${escapeHtml(o.product_name)}</td>
      <td>${Number(o.quantity)}</td>
      <td>₹${Number(o.unit_price || 0).toFixed(2)}</td>
      <td><strong>₹${Number(o.line_total || 0).toFixed(2)}</strong></td>
      <td><small>${escapeHtml(o.shipping_address)}</small></td>
      <td>
        <span class="badge-status ${escapeHtml(status)}">${escapeHtml(status)}</span>
      </td>
      <td>${connectCell}</td>
      <td>
        <select data-order-item-id="${escapeHtml(o.id)}" class="table-select order-status-select" style="background-color: var(--bg-surface-elevated); color: var(--text-primary); border-radius: var(--radius-sm); border: 1px solid var(--border-color); padding: 4px;">
          <option value="confirmed" ${status === 'confirmed' ? 'selected' : ''}>Confirmed</option>
          <option value="processing" ${status === 'processing' ? 'selected' : ''}>Processing</option>
          <option value="shipped" ${status === 'shipped' ? 'selected' : ''}>Shipped</option>
          <option value="delivered" ${status === 'delivered' ? 'selected' : ''}>Delivered</option>
          <option value="cancelled" ${status === 'cancelled' ? 'selected' : ''}>Cancelled</option>
        </select>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Event delegation for the per-line-item status dropdown — avoids
// interpolating order_item_id into an inline onchange="..." string.
document.getElementById('orders-list').addEventListener('change', (e) => {
  const select = e.target.closest('.order-status-select');
  if (!select) return;
  updateOrderStatus(select.dataset.orderItemId, select.value);
});

// Clicking anywhere on an order row opens its overview modal — except
// clicks on the status dropdown or the call/WhatsApp connect icons,
// which have their own behavior and shouldn't also pop the modal.
document.getElementById('orders-list').addEventListener('click', (e) => {
  if (e.target.closest('select, a')) return;
  const row = e.target.closest('.order-row');
  if (!row) return;
  openOrderOverview(row.dataset.orderRowId);
});

// Builds a Google Maps search link for a shipping address so clicking the
// map preview in the order overview takes the provider straight to it.
function buildMapsLink(address) {
  if (!address) return null;
  return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(address)}`;
}

function openOrderOverview(orderItemId) {
  const o = allOrders.find(order => String(order.id) === String(orderItemId));
  if (!o) return;

  const status = o.fulfillment_status || o.legacy_status;
  const waLink = buildWhatsAppLink(o.customer_phone);
  const callLink = buildCallLink(o.customer_phone);

  document.getElementById('ov-order-number').textContent = o.order_number;
  document.getElementById('ov-status').innerHTML =
    `<span class="badge-status ${escapeHtml(status)}">${escapeHtml(status)}</span>`;
  document.getElementById('ov-customer-name').textContent = o.customer_name;
  document.getElementById('ov-customer-email').textContent = o.customer_email;
  document.getElementById('ov-product').textContent =
    `${o.product_emoji || '🎁'} ${o.product_name}`;
  document.getElementById('ov-quantity').textContent = Number(o.quantity);
  document.getElementById('ov-unit-price').textContent = `₹${Number(o.unit_price || 0).toFixed(2)}`;
  document.getElementById('ov-total').textContent = `₹${Number(o.line_total || 0).toFixed(2)}`;
  document.getElementById('ov-address').textContent = o.shipping_address || 'No address on file';

  const connectEl = document.getElementById('ov-connect');
  const parts = [];
  if (callLink) {
    parts.push(`<a href="${escapeHtml(callLink)}" title="Call customer" style="display:inline-flex; align-items:center; gap:6px;">
      <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRxz80Nlo85SdDHUxBrSp69uQi5tzk0dmZu4XIk8IGVHw&s=10" alt="Call" width="18" height="18" style="border-radius:3px;">
    </a>`);
  }
  if (waLink) {
    parts.push(`<a href="${escapeHtml(waLink)}" target="_blank" rel="noopener noreferrer" title="Chat on WhatsApp" style="display:inline-flex; align-items:center; gap:6px;">
      <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTvg2MbImmMcal8qKmgenlQd_How3sCXGLHVEDbqA1Lwg&s=10" alt="WhatsApp" width="18" height="18" style="border-radius:3px;">
    </a>`);
  }
  connectEl.innerHTML = parts.length
    ? `<span class="overview-label">Connect</span><span style="display:flex; gap:10px;">${parts.join('')}</span>`
    : '';

  const mapLink = buildMapsLink(o.shipping_address);
  const mapAnchor = document.getElementById('ov-map-link');
  if (mapLink) {
    mapAnchor.href = mapLink;
    mapAnchor.style.display = 'flex';
  } else {
    mapAnchor.removeAttribute('href');
    mapAnchor.style.display = 'none';
  }

  document.getElementById('order-overview-modal').classList.remove('hidden');
  if (window.lucide) lucide.createIcons();
}

function closeOrderOverviewModal() {
  document.getElementById('order-overview-modal').classList.add('hidden');
}

function renderRecentOrders() {
  const list = document.getElementById('recent-orders-list');
  list.innerHTML = '';

  const recent = allOrders.slice(0, 5);
  if (recent.length === 0) {
    list.innerHTML = `
      <tr>
        <td colspan="5" class="text-center py-4 text-muted">No orders yet.</td>
      </tr>
    `;
    return;
  }

  recent.forEach(o => {
    const tr = document.createElement('tr');
    const status = o.fulfillment_status || o.legacy_status;
    tr.innerHTML = `
      <td><small class="text-muted">${escapeHtml(o.order_number.substring(0, 12))}...</small></td>
      <td>${escapeHtml(o.product_name)}</td>
      <td>${Number(o.quantity)}</td>
      <td>₹${Number(o.line_total).toFixed(2)}</td>
      <td><span class="badge-status ${escapeHtml(status)}">${escapeHtml(status)}</span></td>
    `;
    list.appendChild(tr);
  });
}

function filterOrders() {
  const val = document.getElementById('order-status-filter').value;
  if (val === 'all') {
    renderOrders(allOrders);
  } else {
    const filtered = allOrders.filter(o => (o.fulfillment_status || o.legacy_status) === val);
    renderOrders(filtered);
  }
}

// Updates fulfillment status for ONE order line item, scoped to this
// provider. RLS (order_item_fulfillment: fulfillment_update_own) enforces
// provider_id = current_provider_id() server-side regardless of what's
// passed here, so this can never touch another provider's line item, let
// alone the whole order.
async function updateOrderStatus(orderItemId, status) {
  try {
    const { error } = await supabaseClient
      .from('order_item_fulfillment')
      .update({ status, updated_at: new Date().toISOString() })
      .eq('order_item_id', orderItemId)
      .eq('provider_id', currentProvider.id);

    if (error) throw error;
    showToast('Order status updated successfully!');
    await fetchOrders();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// 4. SETTINGS FORM SUBMISSION
const settingsForm = document.getElementById('settings-form');
settingsForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const bizName = document.getElementById('set-biz-name').value;
  const instagram = document.getElementById('set-instagram').value;
  const avatar = document.getElementById('set-avatar').value;
  const bio = document.getElementById('set-bio').value;

  // Aadhaar/PAN: the DB never gives us the full value back (see
  // setupPiiField above), so there's nothing to silently resend on every
  // save. Only include these keys in the update at all if the provider
  // actively clicked "Update"/"Add" and typed a new value — omitting the
  // key entirely (not sending an empty string) is what makes
  // protect_provider_pii() leave the existing hash untouched.
  const aadhaarInput = document.getElementById('set-aadhaar');
  const panInput = document.getElementById('set-pan');
  const updates = {
    name: bizName,
    instagram_handle: instagram || null,
    avatar_url: avatar || null,
    bio: bio || null
  };
  if (aadhaarInput.dataset.editing === 'true' && aadhaarInput.value.trim()) {
    updates.aadhaar_number = aadhaarInput.value.trim().replace(/[\s-]/g, '');
  }
  if (panInput.dataset.editing === 'true' && panInput.value.trim()) {
    updates.pan_card = panInput.value.trim().replace(/[\s-]/g, '').toUpperCase().substring(0, 10);
  }

  try {
    const { error } = await supabaseClient
      .from('providers')
      .update(updates)
      .eq('id', currentProvider.id);

    if (error) throw error;
    showToast('Store profile updated successfully!');

    // Refresh state
    await loadProviderProfile(currentProvider.id, sessionUser.email);
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// Update Statistics Cards & Top Products
function updateDashboardStats() {
  document.getElementById('stat-products').textContent = allProducts.length;
  document.getElementById('stat-followers').textContent = allFollowers.length;

  let totalRevenue = 0;
  allOrders.forEach(o => {
    totalRevenue += Number(o.line_total || 0);
  });

  document.getElementById('stat-revenue').textContent = `₹${totalRevenue.toFixed(2)}`;
  document.getElementById('stat-orders').textContent = allOrders.length;

  // Render Top Products List
  const topProductsList = document.getElementById('top-products-list');
  topProductsList.innerHTML = '';

  const topItems = allProducts.slice(0, 3);
  if (topItems.length === 0) {
    topProductsList.innerHTML = `<li class="text-muted text-center py-4">No products listed.</li>`;
    return;
  }

  topItems.forEach(p => {
    const li = document.createElement('li');
    const fallbackImage = 'https://images.unsplash.com/photo-1549465220-1a8b9238cd48?w=500&auto=format&fit=crop&q=60';
    const imgUrl = (p.product_images && p.product_images.length > 0) ? p.product_images[0] : fallbackImage;

    li.innerHTML = `
      <img src="${escapeHtml(imgUrl)}" alt="${escapeHtml(p.product_name)}" onerror="this.onerror=null;this.src='${escapeHtml(fallbackImage)}'">
      <div class="top-prod-info">
        <h4>${escapeHtml(p.product_name)}</h4>
        <p>${Number(p.available_qty || 0)} left in stock</p>
      </div>
      <div class="top-prod-price">₹${Number(p.price_in_rupees).toFixed(2)}</div>
    `;
    topProductsList.appendChild(li);
  });
}
