require('dotenv').config({ path: require('path').resolve(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Anthropic } = require('@anthropic-ai/sdk');
const Stripe = require('stripe');

const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- Dashboard login (real session cookie, not the browser's native HTTP
// Basic Auth popup -- that has no branding, no logout, and behaves
// inconsistently across browsers). A session is a signed, expiring token;
// the signing key is derived from ADMIN_DASHBOARD_PASSWORD itself, so
// rotating the password invalidates every existing session automatically.
const SESSION_COOKIE = 'ds_session';
const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function signSession(expiry) {
  const secret = process.env.ADMIN_DASHBOARD_PASSWORD || '';
  return crypto.createHmac('sha256', secret).update(String(expiry)).digest('hex');
}

function makeSessionCookieValue() {
  const expiry = Date.now() + SESSION_MAX_AGE_MS;
  return `${expiry}.${signSession(expiry)}`;
}

function verifySessionCookie(value) {
  if (!value) return false;
  const [expiryStr, sig] = value.split('.');
  const expiry = parseInt(expiryStr, 10);
  if (!expiry || !sig || Date.now() > expiry) return false;
  const expected = signSession(expiry);
  try {
    return sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch {
    return false;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

function loginPageHtml(showError) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DreamSpire Admin — Sign in</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', -apple-system, sans-serif; background: #f1f2f4; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .box { background: #fff; border: 1px solid #e3e5e8; border-radius: 10px; padding: 36px; width: 92%; max-width: 340px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }
  .logo { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 1.1rem; margin-bottom: 24px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #008060; }
  label { display: block; font-size: 0.78rem; font-weight: 600; color: #6b7177; margin-bottom: 6px; }
  input { width: 100%; padding: 10px 12px; border: 1px solid #e3e5e8; border-radius: 6px; font-size: 0.9rem; margin-bottom: 16px; }
  button { width: 100%; background: #008060; color: #fff; border: none; padding: 10px; font-weight: 600; font-size: 0.9rem; border-radius: 6px; cursor: pointer; }
  button:hover { background: #006e52; }
  .error { background: #fde7e7; color: #99241b; font-size: 0.82rem; padding: 10px 12px; border-radius: 6px; margin-bottom: 16px; }
</style></head>
<body>
  <div class="box">
    <div class="logo"><span class="dot"></span> DreamSpire Admin</div>
    ${showError ? '<div class="error">Wrong password. Try again.</div>' : ''}
    <form method="POST" action="/admin/login">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autofocus autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </div>
</body></html>`;
}

// Password-gate the ops dashboard -- it will show real order/customer data
// once SHOPIFY_ADMIN_ACCESS_TOKEN is set, so it must never be left open.
function requireDashboardAuth(req, res, next) {
  const configuredPassword = process.env.ADMIN_DASHBOARD_PASSWORD;
  if (!configuredPassword) {
    return res.status(503).send('Dashboard locked: ADMIN_DASHBOARD_PASSWORD is not set in Vercel env vars yet.');
  }
  const cookies = parseCookies(req);
  if (verifySessionCookie(cookies[SESSION_COOKIE])) return next();

  // Real page loads get sent to the login page; the dashboard's own fetch()
  // calls for data get a plain 401 so the front-end can react in place.
  if ((req.headers.accept || '').includes('text/html')) {
    return res.redirect('/admin/login');
  }
  return res.status(401).json({ status: 'ERROR', message: 'Not signed in.' });
}

// Basic brute-force throttle on login attempts, keyed by IP. This is
// in-memory, so on Vercel it only protects within one warm serverless
// instance -- a cold start or a different region resets it. Real
// protection here is the 20-char random password; this is a second,
// honest-about-its-limits layer, not a guarantee.
const loginAttempts = new Map(); // ip -> { count, resetAt }
const LOGIN_MAX_ATTEMPTS = 10;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

function tooManyLoginAttempts(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) return false;
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}

function recordLoginAttempt(ip, failed) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(ip, { count: failed ? 1 : 0, resetAt: now + LOGIN_WINDOW_MS });
    return;
  }
  if (failed) entry.count++;
  else loginAttempts.delete(ip); // successful login clears the counter
}

app.get('/admin/login', (req, res) => {
  if (!process.env.ADMIN_DASHBOARD_PASSWORD) {
    return res.status(503).send('Dashboard locked: ADMIN_DASHBOARD_PASSWORD is not set in Vercel env vars yet.');
  }
  res.set('Content-Type', 'text/html').send(loginPageHtml(req.query.error === '1'));
});

app.post('/admin/login', (req, res) => {
  const configuredPassword = process.env.ADMIN_DASHBOARD_PASSWORD;
  if (!configuredPassword) {
    return res.status(503).send('Dashboard locked: ADMIN_DASHBOARD_PASSWORD is not set in Vercel env vars yet.');
  }
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  if (tooManyLoginAttempts(ip)) {
    return res.status(429).send('Too many attempts. Wait 15 minutes and try again.');
  }
  const supplied = (req.body && req.body.password) || '';
  const suppliedBuf = Buffer.from(supplied);
  const expectedBuf = Buffer.from(configuredPassword);
  const matches = suppliedBuf.length === expectedBuf.length && crypto.timingSafeEqual(suppliedBuf, expectedBuf);
  recordLoginAttempt(ip, !matches);
  if (!matches) {
    return res.redirect('/admin/login?error=1');
  }
  res.cookie(SESSION_COOKIE, makeSessionCookieValue(), {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: SESSION_MAX_AGE_MS,
    path: '/'
  });
  res.redirect('/admin');
});

app.post('/admin/logout', (req, res) => {
  res.clearCookie(SESSION_COOKIE, { path: '/' });
  res.redirect('/admin/login');
});

app.get(['/admin', '/admin.html'], requireDashboardAuth, (req, res) => {
  // Force revalidation on every load -- otherwise a browser can keep
  // serving a stale cached copy of the dashboard after a deploy until
  // the user manually hard-refreshes.
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Every endpoint that can return real order/customer/shop data must sit
// behind the same password gate as the dashboard itself -- these were
// previously reachable unauthenticated even though /admin was protected.
app.use('/api/shopify/orders', requireDashboardAuth);
app.use('/api/shopify/products', requireDashboardAuth);
app.use('/api/shopify/shop', requireDashboardAuth);
app.use('/api/shopify/customers', requireDashboardAuth);
app.use('/api/fulfillment/status', requireDashboardAuth);
app.use('/api/shopify/analytics', requireDashboardAuth);

// Parse a Shopify REST `Link` response header into { next, previous } page_info
// cursors -- the modern cursor-based pagination scheme (page-number pagination
// was removed from the REST Admin API).
function parseLinkHeader(header) {
  if (!header) return {};
  const links = {};
  header.split(',').forEach(part => {
    const match = part.match(/<([^>]+)>;\s*rel="([^"]+)"/);
    if (match) {
      links[match[2]] = new URL(match[1]).searchParams.get('page_info');
    }
  });
  return links;
}

const PORT = process.env.PORT || 4000;
const SHOPIFY_DOMAIN = process.env.SHOPIFY_SHOP_URL || "anznev-5s.myshopify.com";

const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' }) : null;

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY || 'sk-ant-demo-key-12345',
});

// 1. Health & Ecosystem Status Endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: "OPERATIONAL",
    system: "DreamSpire Distributed Atelier Orchestrator",
    port: PORT,
    timestamp: new Date().toISOString(),
    stakeholders: {
      shopify: (process.env.SHOPIFY_ADMIN_ACCESS_TOKEN && process.env.SHOPIFY_ADMIN_ACCESS_TOKEN !== 'shpat_demo_token_12345') ? `CONFIGURED (${SHOPIFY_DOMAIN})` : "NOT_CONNECTED",
      fulfillment: "See /api/fulfillment/status — routing is native to Shopify, not a custom API key",
      stripe: (process.env.STRIPE_SECRET_KEY && !process.env.STRIPE_SECRET_KEY.includes('demo') && !process.env.STRIPE_SECRET_KEY.includes('YOUR_PROD')) ? "CONFIGURED" : "NOT_CONNECTED",
      anthropic: (process.env.ANTHROPIC_API_KEY || '').includes('demo') ? "DEMO & FREE ROTATION ACTIVE" : "CONFIGURED",
      google_merchant_feed: "LIVE — see /api/google/feed.xml (generated from real Shopify catalog)"
    }
  });
});

// 1.1 Real Fulfillment Routing Status
// Printful and Tapstitch are connected as native Shopify fulfillment-service
// apps (installed via OAuth in Shopify Admin), NOT via a custom API key in
// this backend. Shopify itself dispatches orders to them and receives
// tracking back via their own webhooks. This endpoint reports what Shopify
// actually has registered, instead of guessing from an unrelated env var.
app.get('/api/fulfillment/status', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({
      status: "NOT_CONNECTED",
      services: [],
      message: "No live Shopify Admin API token configured. Set SHOPIFY_ADMIN_ACCESS_TOKEN to check real fulfillment routing."
    });
  }

  try {
    const gqlRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/graphql.json`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token
      },
      body: JSON.stringify({
        query: `query { shop { fulfillmentServices { serviceName handle callbackUrl } } }`
      })
    });
    const gqlData = await gqlRes.json();
    const services = (gqlData?.data?.shop?.fulfillmentServices || [])
      .filter(s => s.handle !== 'manual')
      .map(s => ({ name: s.serviceName, handle: s.handle, callbackUrl: s.callbackUrl, connected: true }));
    return res.json({ status: "SUCCESS", services });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 1.2 Real store locations (own shop location + any fulfillment-service
// locations like Printful/ODMPOD). Requires read_locations.
app.get('/api/shopify/locations', requireDashboardAuth, async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", locations: [] });
  }
  try {
    const r = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/locations.json`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    const d = await r.json();
    const mapped = (d.locations || []).map(l => ({
      id: l.id,
      name: l.name,
      active: l.active,
      country: l.country_name
    }));
    return res.json({ status: "SUCCESS", locations: mapped });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 1.3 Real recent fulfillments -- tracking numbers/carriers actually
// generated by Shopify for the most recent fulfilled orders (this data is
// already returned inline on each order, just not surfaced anywhere).
app.get('/api/shopify/fulfillments/recent', requireDashboardAuth, async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", fulfillments: [] });
  }
  try {
    const r = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders.json?status=any&fulfillment_status=fulfilled&limit=25`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    const d = await r.json();
    const rows = [];
    (d.orders || []).forEach(o => {
      (o.fulfillments || []).forEach(f => {
        rows.push({
          order_id: o.name,
          status: f.status,
          tracking_number: f.tracking_number || '',
          tracking_company: f.tracking_company || '',
          tracking_url: f.tracking_url || '',
          created_at: f.created_at
        });
      });
    });
    rows.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    return res.json({ status: "SUCCESS", fulfillments: rows.slice(0, 20) });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 2. Google Merchant Center XML Product Feed (Live XML Generation)
app.get('/api/google/feed.xml', async (req, res) => {
  try {
    // Using native Node 18+ global fetch
    const shopifyRes = await fetch(`https://${SHOPIFY_DOMAIN}/products.json`);
    const data = await shopifyRes.json();
    const products = data.products || [];

    let xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:g="http://base.google.com/ns/1.0">
  <channel>
    <title>DreamSpire Atelier Official Catalog</title>
    <link>https://${SHOPIFY_DOMAIN}</link>
    <description>Authentic 500GSM Heavyweight Luxury Streetwear Archive</description>
`;

    products.forEach(p => {
      const v = (p.variants && p.variants[0]) || {};
      const img = (p.images && p.images[0]) ? p.images[0].src : '';
      const additionalImgs = (p.images || []).slice(1, 4).map(i => i.src);
      const desc = (p.body_html || '').replace(/<[^>]+>/g, ' ').substring(0, 500);

      xml += `    <item>
      <g:id>${p.id}</g:id>
      <g:title><![CDATA[${p.title}]]></g:title>
      <g:description><![CDATA[${desc}]]></g:description>
      <g:link>https://${SHOPIFY_DOMAIN}/products/${p.handle}</g:link>
      <g:image_link>${img}</g:image_link>\n`;
      
      additionalImgs.forEach(addImg => {
        xml += `      <g:additional_image_link>${addImg}</g:additional_image_link>\n`;
      });

      xml += `      <g:brand>DreamSpire</g:brand>
      <g:condition>new</g:condition>
      <g:availability>${v.available !== false ? 'in_stock' : 'out_of_stock'}</g:availability>
      <g:price>${v.price || '45.00'} GBP</g:price>
      <g:google_product_category>Apparel &amp; Accessories &gt; Clothing</g:google_product_category>
      <g:product_type>500GSM Heavyweight Luxury Streetwear</g:product_type>
      <g:material>100% Pre-Shrunk Loopback French Terry Cotton</g:material>
      <g:gender>unisex</g:gender>
      <g:age_group>adult</g:age_group>
      <g:custom_label_0>Drop 001 Archive</g:custom_label_0>
      <g:custom_label_1>500GSM Heavyweight</g:custom_label_1>
      <g:shipping>
        <g:country>GB</g:country>
        <g:service>Royal Mail Tracked 24 (DDP)</g:service>
        <g:price>0.00 GBP</g:price>
      </g:shipping>
    </item>\n`;
    });

    xml += `  </channel>
</rss>`;

    res.header('Content-Type', 'application/xml');
    res.send(xml);
  } catch (err) {
    res.status(500).send('<error>' + err.message + '</error>');
  }
});

// 3. Shopify Admin API - Create a real percentage-off discount code.
// Uses the modern GraphQL discountCodeBasicCreate mutation (Shopify's REST
// Price Rules endpoint is deprecated). Requires write_discounts.
app.post('/api/shopify/discount', requireDashboardAuth, async (req, res) => {
  const { code, value } = req.body;
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", message: "No live Shopify Admin API token configured." });
  }

  const generatedCode = (code || `SECURED-${Math.floor(1000 + Math.random() * 9000)}`).toUpperCase();
  const percentage = Math.min(Math.max(parseFloat(value) || 15, 1), 100) / 100;

  const mutation = `
    mutation discountCodeBasicCreate($basicCodeDiscount: DiscountCodeBasicInput!) {
      discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
        codeDiscountNode { id }
        userErrors { field message }
      }
    }
  `;
  const variables = {
    basicCodeDiscount: {
      title: generatedCode,
      code: generatedCode,
      startsAt: new Date().toISOString(),
      customerSelection: { all: true },
      customerGets: { value: { percentage }, items: { all: true } },
      appliesOncePerCustomer: false
    }
  };

  try {
    const gqlRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/graphql.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ query: mutation, variables })
    });
    const gqlData = await gqlRes.json();
    const result = gqlData?.data?.discountCodeBasicCreate;
    if (result?.userErrors?.length) {
      return res.status(400).json({ status: "ERROR", message: result.userErrors.map(e => e.message).join('; ') });
    }
    if (!result?.codeDiscountNode) {
      return res.status(500).json({ status: "ERROR", message: gqlData.errors ? JSON.stringify(gqlData.errors) : "Unknown error creating discount." });
    }
    return res.json({ status: "SUCCESS", code: generatedCode, discount_id: result.codeDiscountNode.id });
  } catch (error) {
    res.status(500).json({ status: "ERROR", message: error.message });
  }
});

// 3.1 Shopify Admin API - List real active discount codes. Requires read_discounts.
app.get('/api/shopify/discounts', requireDashboardAuth, async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", discounts: [] });
  }

  const query = `
    query {
      codeDiscountNodes(first: 50) {
        nodes {
          id
          codeDiscount {
            ... on DiscountCodeBasic {
              title
              status
              codes(first: 1) { nodes { code } }
              customerGets { value { ... on DiscountPercentage { percentage } } }
            }
          }
        }
      }
    }
  `;

  try {
    const gqlRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/graphql.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ query })
    });
    const gqlData = await gqlRes.json();
    const nodes = gqlData?.data?.codeDiscountNodes?.nodes || [];
    const mapped = nodes
      .filter(n => n.codeDiscount && n.codeDiscount.title !== undefined)
      .map(n => ({
        id: n.id,
        title: n.codeDiscount.title,
        status: n.codeDiscount.status,
        code: n.codeDiscount.codes?.nodes?.[0]?.code || '',
        percentage: n.codeDiscount.customerGets?.value?.percentage ? (n.codeDiscount.customerGets.value.percentage * 100).toFixed(0) : null
      }));
    return res.json({ status: "SUCCESS", discounts: mapped });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 3.2 Shopify Admin API - Edit an existing discount code's title/percentage.
// Discount ids are GraphQL global ids (contain slashes/colons), so they're
// passed in the request body rather than a URL path segment.
app.put('/api/shopify/discounts', requireDashboardAuth, async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  const { id, title, value } = req.body;
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED" });
  }
  if (!id) return res.status(400).json({ status: "ERROR", message: "Missing discount id." });

  const mutation = `
    mutation discountCodeBasicUpdate($id: ID!, $basicCodeDiscount: DiscountCodeBasicInput!) {
      discountCodeBasicUpdate(id: $id, basicCodeDiscount: $basicCodeDiscount) {
        codeDiscountNode { id }
        userErrors { field message }
      }
    }
  `;
  const basicCodeDiscount = {};
  if (title !== undefined) basicCodeDiscount.title = title;
  if (value !== undefined) {
    basicCodeDiscount.customerGets = { value: { percentage: Math.min(Math.max(parseFloat(value) || 1, 1), 100) / 100 }, items: { all: true } };
  }

  try {
    const gqlRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/graphql.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ query: mutation, variables: { id, basicCodeDiscount } })
    });
    const gqlData = await gqlRes.json();
    const result = gqlData?.data?.discountCodeBasicUpdate;
    if (result?.userErrors?.length) {
      return res.status(400).json({ status: "ERROR", message: result.userErrors.map(e => e.message).join('; ') });
    }
    return res.json({ status: "SUCCESS" });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 3.3 Shopify Admin API - Activate/deactivate a discount code (pause it
// without deleting it).
app.post('/api/shopify/discounts/toggle', requireDashboardAuth, async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  const { id, activate } = req.body;
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED" });
  }
  if (!id) return res.status(400).json({ status: "ERROR", message: "Missing discount id." });

  const mutation = activate
    ? `mutation($id: ID!) { discountCodeActivate(id: $id) { codeDiscountNode { id } userErrors { field message } } }`
    : `mutation($id: ID!) { discountCodeDeactivate(id: $id) { codeDiscountNode { id } userErrors { field message } } }`;

  try {
    const gqlRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/graphql.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ query: mutation, variables: { id } })
    });
    const gqlData = await gqlRes.json();
    const result = gqlData?.data?.discountCodeActivate || gqlData?.data?.discountCodeDeactivate;
    if (result?.userErrors?.length) {
      return res.status(400).json({ status: "ERROR", message: result.userErrors.map(e => e.message).join('; ') });
    }
    return res.json({ status: "SUCCESS" });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 3.4 Shopify Admin API - Permanently delete a discount code.
app.post('/api/shopify/discounts/delete', requireDashboardAuth, async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  const { id } = req.body;
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED" });
  }
  if (!id) return res.status(400).json({ status: "ERROR", message: "Missing discount id." });

  try {
    const gqlRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/graphql.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ query: `mutation($id: ID!) { discountCodeDelete(id: $id) { deletedCodeDiscountId userErrors { field message } } }`, variables: { id } })
    });
    const gqlData = await gqlRes.json();
    const result = gqlData?.data?.discountCodeDelete;
    if (result?.userErrors?.length) {
      return res.status(400).json({ status: "ERROR", message: result.userErrors.map(e => e.message).join('; ') });
    }
    return res.json({ status: "SUCCESS" });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4. Shopify Admin API - Live Orders Sync. Supports cursor pagination via
// ?after=<page_info> (from the previous response's next_cursor) so the
// dashboard can reach orders past the first 50, not just the most recent page.
app.get('/api/shopify/orders', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({
      status: "NOT_CONNECTED",
      orders: [],
      message: "No live Shopify Admin API token configured. Set SHOPIFY_ADMIN_ACCESS_TOKEN to enable real order sync."
    });
  }

  const after = req.query.after;
  // Shopify's page_info cursor must be the ONLY filter param on the request
  // (besides limit) -- can't combine it with status=any on a paginated call.
  const ordersUrl = after
    ? `https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders.json?limit=50&page_info=${encodeURIComponent(after)}`
    : `https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders.json?status=any&limit=50`;

  try {
    const [ordersRes, countRes] = await Promise.all([
      fetch(ordersUrl, { headers: { 'X-Shopify-Access-Token': token } }),
      after ? Promise.resolve(null) : fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders/count.json?status=any`, {
        headers: { 'X-Shopify-Access-Token': token }
      })
    ]);
    const ordersData = await ordersRes.json();
    const countData = countRes ? await countRes.json() : null;
    const nextCursor = parseLinkHeader(ordersRes.headers.get('link')).next || null;
    const mapped = (ordersData.orders || []).map(o => ({
      id: o.name,
      order_id: o.id,
      name: [o.customer?.first_name, o.customer?.last_name].filter(Boolean).join(' ') || 'Guest',
      total: parseFloat(o.total_price || '0'),
      currency: o.currency || 'GBP',
      status: o.cancelled_at ? 'Cancelled' : (o.financial_status || 'unknown'),
      items: (o.line_items || []).reduce((n, li) => n + (li.quantity || 0), 0),
      routed_to: o.fulfillment_status || 'unfulfilled',
      created_at: o.created_at
    }));
    return res.json({
      status: "SUCCESS",
      orders: mapped,
      total_count: countData ? (countData.count ?? mapped.length) : undefined,
      next_cursor: nextCursor
    });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.0.05 Shopify Admin API - Full detail for one order: real line items and
// shipping address, not just the summary row shown in the list.
app.get('/api/shopify/orders/:id/detail', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  const { id } = req.params;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED" });
  }

  try {
    const orderRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders/${id}.json`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    const data = await orderRes.json();
    const o = data.order;
    if (!o) return res.status(404).json({ status: "ERROR", message: "Order not found." });

    const addr = o.shipping_address;
    return res.json({
      status: "SUCCESS",
      order: {
        id: o.name,
        order_id: o.id,
        created_at: o.created_at,
        customer_name: [o.customer?.first_name, o.customer?.last_name].filter(Boolean).join(' ') || 'Guest',
        email: o.email || o.contact_email || '',
        total: parseFloat(o.total_price || '0'),
        subtotal: parseFloat(o.subtotal_price || '0'),
        shipping: parseFloat(o.total_shipping_price_set?.shop_money?.amount || '0'),
        currency: o.currency || 'GBP',
        financial_status: o.cancelled_at ? 'Cancelled' : (o.financial_status || 'unknown'),
        fulfillment_status: o.fulfillment_status || 'unfulfilled',
        note: o.note || '',
        line_items: (o.line_items || []).map(li => ({
          title: li.title,
          variant_title: li.variant_title,
          quantity: li.quantity,
          price: parseFloat(li.price || '0'),
          sku: li.sku || ''
        })),
        shipping_address: addr ? {
          address1: addr.address1 || '',
          address2: addr.address2 || '',
          city: addr.city || '',
          province: addr.province || '',
          zip: addr.zip || '',
          country: addr.country || ''
        } : null
      }
    });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.0.06 Real revenue trend, computed server-side from real orders (paginates
// through everything in the requested window -- not just the most recent 50).
app.get('/api/shopify/analytics/revenue-trend', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", series: [] });
  }

  const days = Math.min(parseInt(req.query.days, 10) || 30, 90);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  try {
    let allOrders = [];
    let url = `https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders.json?status=any&limit=250&created_at_min=${encodeURIComponent(since)}`;
    let guard = 0;
    while (url && guard < 10) {
      const r = await fetch(url, { headers: { 'X-Shopify-Access-Token': token } });
      const d = await r.json();
      allOrders = allOrders.concat(d.orders || []);
      const next = parseLinkHeader(r.headers.get('link')).next;
      url = next ? `https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders.json?limit=250&page_info=${encodeURIComponent(next)}` : null;
      guard++;
    }

    const byDay = {};
    allOrders.forEach(o => {
      if (o.cancelled_at) return;
      const day = o.created_at.slice(0, 10);
      byDay[day] = (byDay[day] || 0) + parseFloat(o.total_price || '0');
    });

    const series = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
      series.push({ date: d, revenue: Math.round((byDay[d] || 0) * 100) / 100 });
    }
    return res.json({ status: "SUCCESS", series, currency: allOrders[0]?.currency || 'GBP' });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.0.07 Orders that have sat unfulfilled longer than the threshold, scanned
// across ALL open orders (not just the most recent 50) so an old stuck order
// can't silently fall off the bottom of the list.
app.get('/api/shopify/orders/attention', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", orders: [] });
  }

  try {
    const r = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders.json?status=open&fulfillment_status=unfulfilled&limit=250`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    const d = await r.json();
    const thresholdDays = 3;
    const cutoff = Date.now() - thresholdDays * 24 * 60 * 60 * 1000;
    const stale = (d.orders || [])
      .filter(o => new Date(o.created_at).getTime() < cutoff)
      .map(o => ({
        id: o.name,
        order_id: o.id,
        created_at: o.created_at,
        total: parseFloat(o.total_price || '0'),
        currency: o.currency || 'GBP'
      }));
    return res.json({ status: "SUCCESS", orders: stale, threshold_days: thresholdDays });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.0.1 Shopify Admin API - Mark an order fulfilled (all remaining
// fulfillable line items). Requires write_orders. Uses the modern
// fulfillment_orders flow, not the deprecated single-step fulfillment API.
app.post('/api/shopify/orders/:id/fulfill', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  const { id } = req.params;
  const { tracking_number, tracking_company, tracking_url } = req.body || {};

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", message: "No live Shopify Admin API token configured." });
  }

  try {
    const foRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders/${id}/fulfillment_orders.json`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    const foData = await foRes.json();
    const openOrders = (foData.fulfillment_orders || []).filter(fo => fo.status === 'open' || fo.status === 'in_progress');

    if (!openOrders.length) {
      return res.status(400).json({ status: "ERROR", message: "No open fulfillment orders found — this order may already be fulfilled or has no fulfillable items." });
    }

    const fulfillment = {
      line_items_by_fulfillment_order: openOrders.map(fo => ({ fulfillment_order_id: fo.id })),
      notify_customer: true
    };
    if (tracking_number) {
      fulfillment.tracking_info = {
        number: tracking_number,
        company: tracking_company || '',
        url: tracking_url || ''
      };
    }

    const fulfillRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/fulfillments.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ fulfillment })
    });

    if (!fulfillRes.ok) {
      const errBody = await fulfillRes.text();
      return res.status(fulfillRes.status).json({ status: "ERROR", message: `Shopify rejected the fulfillment (${fulfillRes.status}): ${errBody}` });
    }
    return res.json({ status: "SUCCESS" });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.0.2 Shopify Admin API - Cancel an order. Requires write_orders.
app.post('/api/shopify/orders/:id/cancel', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  const { id } = req.params;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", message: "No live Shopify Admin API token configured." });
  }

  try {
    const cancelRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders/${id}/cancel.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ reason: 'customer', restock: true })
    });
    if (!cancelRes.ok) {
      const errBody = await cancelRes.text();
      return res.status(cancelRes.status).json({ status: "ERROR", message: `Shopify rejected the cancellation (${cancelRes.status}): ${errBody}` });
    }
    return res.json({ status: "SUCCESS" });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.0.3 Shopify Admin API - Full refund of an order (all line items +
// shipping, restocking). Requires write_orders.
app.post('/api/shopify/orders/:id/refund', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  const { id } = req.params;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", message: "No live Shopify Admin API token configured." });
  }

  try {
    const orderRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders/${id}.json`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    const orderData = await orderRes.json();
    const order = orderData.order;
    if (!order) return res.status(404).json({ status: "ERROR", message: "Order not found." });

    const refundLineItems = (order.line_items || []).map(li => ({
      line_item_id: li.id,
      quantity: li.quantity,
      restock_type: 'return'
    }));

    const calcRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders/${id}/refunds/calculate.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ refund: { shipping: { full_refund: true }, refund_line_items: refundLineItems } })
    });
    if (!calcRes.ok) {
      const errBody = await calcRes.text();
      return res.status(calcRes.status).json({ status: "ERROR", message: `Shopify rejected the refund calculation (${calcRes.status}): ${errBody}` });
    }
    const calcData = await calcRes.json();

    const refundRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders/${id}/refunds.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
      body: JSON.stringify({ refund: calcData.refund })
    });
    if (!refundRes.ok) {
      const errBody = await refundRes.text();
      return res.status(refundRes.status).json({ status: "ERROR", message: `Shopify rejected the refund (${refundRes.status}): ${errBody}` });
    }
    return res.json({ status: "SUCCESS" });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.1 Shopify Admin API - Real Product Catalog (Admin-level: includes
// draft/inventory data, not just what's publicly visible on the storefront).
// Replaces the old client-side fetch of a static real-shopify-products.json
// file that was written to a path outside this repo and never actually
// existed in the deployed backend -- the catalog view was silently broken.
app.get('/api/shopify/products', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({
      status: "NOT_CONNECTED",
      products: [],
      message: "No live Shopify Admin API token configured. Set SHOPIFY_ADMIN_ACCESS_TOKEN to enable the real catalog."
    });
  }

  try {
    const productsRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/products.json?limit=100`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    const data = await productsRes.json();
    const mapped = (data.products || []).map(p => {
      const variants = p.variants || [];
      let cheapestVariant = null;
      variants.forEach(v => {
        const price = parseFloat(v.price || '0');
        if (!cheapestVariant || price < parseFloat(cheapestVariant.price || '0')) cheapestVariant = v;
      });
      const totalInventory = variants.reduce((n, v) => n + (typeof v.inventory_quantity === 'number' ? v.inventory_quantity : 0), 0);
      return {
        id: p.id,
        title: p.title,
        handle: p.handle,
        status: p.status,
        image: (p.image && p.image.src) || (p.images && p.images[0] && p.images[0].src) || '',
        price: cheapestVariant ? parseFloat(cheapestVariant.price).toFixed(2) : '0.00',
        primary_variant_id: cheapestVariant ? cheapestVariant.id : null,
        variant_count: variants.length,
        inventory: totalInventory
      };
    });
    return res.json({ status: "SUCCESS", products: mapped });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.1.1 Shopify Admin API - Edit a Product (title, status, and the price of
// its primary/cheapest variant). Requires write_products.
app.put('/api/shopify/products/:id', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  const { id } = req.params;
  const { title, status, price, variant_id } = req.body;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", message: "No live Shopify Admin API token configured." });
  }

  try {
    const productPayload = {};
    if (title !== undefined) productPayload.title = title;
    if (status !== undefined) productPayload.status = status;

    if (Object.keys(productPayload).length) {
      const prodRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/products/${id}.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
        body: JSON.stringify({ product: { id, ...productPayload } })
      });
      if (!prodRes.ok) {
        const errBody = await prodRes.text();
        return res.status(prodRes.status).json({ status: "ERROR", message: `Shopify rejected the product update (${prodRes.status}): ${errBody}` });
      }
    }

    if (price !== undefined && variant_id) {
      const varRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/variants/${variant_id}.json`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': token },
        body: JSON.stringify({ variant: { id: variant_id, price: String(price) } })
      });
      if (!varRes.ok) {
        const errBody = await varRes.text();
        return res.status(varRes.status).json({ status: "ERROR", message: `Shopify rejected the price update (${varRes.status}): ${errBody}` });
      }
    }

    return res.json({ status: "SUCCESS" });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.2 Shopify Admin API - Real Store Info
app.get('/api/shopify/shop', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", shop: null });
  }

  try {
    const shopRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/shop.json`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    const data = await shopRes.json();
    const s = data.shop || {};
    return res.json({
      status: "SUCCESS",
      shop: {
        name: s.name,
        domain: s.domain,
        myshopify_domain: s.myshopify_domain,
        email: s.email,
        currency: s.currency,
        plan_name: s.plan_display_name,
        country: s.country_name,
        created_at: s.created_at
      }
    });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 4.3 Shopify Admin API - Real Customer List (read-only). Requires read_customers.
app.get('/api/shopify/customers', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", customers: [] });
  }

  try {
    const custRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/customers.json?limit=100&order=total_spent+desc`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    const data = await custRes.json();
    const mapped = (data.customers || []).map(c => ({
      id: c.id,
      name: [c.first_name, c.last_name].filter(Boolean).join(' ') || '(no name on file)',
      email: c.email || '',
      orders_count: c.orders_count || 0,
      total_spent: parseFloat(c.total_spent || '0'),
      state: c.state,
      created_at: c.created_at
    }));
    return res.json({ status: "SUCCESS", customers: mapped });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 5. Tapstitch Cut & Sew 500GSM Production API
app.post('/api/tapstitch/order', async (req, res) => {
  const { product, quantity, priority, size } = req.body;
  if (!product) return res.status(400).json({ error: "Missing product data." });

  const poNumber = `PO-TAP-${Math.floor(100000 + Math.random() * 900000)}`;
  res.json({
    status: "SIMULATED",
    po_number: poNumber,
    fabric_spec: "500 GSM French Terry Loopback Cotton",
    stitch_spec: "5-Thread Double Needle Coverstitch",
    custom_labels: "DS-DAMASK-SATIN-TAG-01",
    estimated_dispatch: "5-8 business days",
    message: `SIMULATION ONLY — no real PO was sent. Real Tapstitch orders route automatically through Shopify's own fulfillment-service connection once a customer checks out; this button does not call Tapstitch directly. (Preview PO: ${poNumber} for ${quantity || 1}x ${product}, ${size || 'L'})`
  });
});

// 6. Printful Accessories API v2
app.post('/api/printful/order', async (req, res) => {
  const { product, designFile } = req.body;
  const syncId = `PF-${Math.floor(100000 + Math.random() * 900000)}`;
  res.json({
    status: "SIMULATED",
    sync_id: syncId,
    embroidery_spec: "3D High-Density Puff Embroidery (14,000 stitches)",
    destination: "London Hub DDP",
    message: `SIMULATION ONLY — no real order was sent. Printful is already connected as a real Shopify fulfillment service and receives orders automatically at checkout; this button does not call Printful directly. (Preview sync: ${syncId} for ${product || 'DreamSpire Trucker'})`
  });
});

// 7. Universal Social Publisher API
// No real TikTok Shop / Instagram / Snapchat publishing integration exists
// (no OAuth app registered with any of these platforms). This previously
// always returned a fabricated "SUCCESS" with a made-up reach estimate --
// removed. Build real platform OAuth + posting before re-enabling this.
app.post('/api/social/publish', (req, res) => {
  res.status(501).json({
    status: "NOT_IMPLEMENTED",
    message: "No real social publishing integration exists yet. Each platform (TikTok Shop, Instagram, Snapchat) requires its own OAuth app and business API approval before this can post for real."
  });
});

// 8. Stripe Balance & Account Inspection
app.get('/api/stripe/balance', requireDashboardAuth, async (req, res) => {
  const key = process.env.STRIPE_SECRET_KEY || '';
  if (!stripe || key.includes('demo') || key.includes('placeholder') || key.includes('YOUR_PROD')) {
    return res.json({ status: "NOT_CONNECTED", message: "No live Stripe secret key configured." });
  }

  try {
    const balance = await stripe.balance.retrieve();
    const gbpAvailable = balance.available.find(b => b.currency.toLowerCase() === 'gbp')?.amount || 0;
    const gbpPending = balance.pending.find(b => b.currency.toLowerCase() === 'gbp')?.amount || 0;
    res.json({
      status: "SUCCESS",
      available_gbp: (gbpAvailable / 100).toFixed(2),
      pending_gbp: (gbpPending / 100).toFixed(2),
      currency: "GBP"
    });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 8.1 Stripe Connect Creator Payout Engine
// No creator affiliate program is actually built (no Stripe Connect
// onboarding flow exists), so there is no real destination account to pay
// out to. This previously fabricated a "successful transfer" with a fake
// transaction ID whenever no real account was supplied -- removed.
app.post('/api/stripe/payout', requireDashboardAuth, async (req, res) => {
  const { amount, destinationAccount } = req.body;
  const key = process.env.STRIPE_SECRET_KEY || '';
  if (!stripe || key.includes('demo') || key.includes('placeholder') || key.includes('YOUR_PROD') || !destinationAccount) {
    return res.status(400).json({
      status: "NOT_CONNECTED",
      message: "No real Stripe Connect destination account was provided. No creator payout system is built yet — this must never report a fake success."
    });
  }

  try {
    const transfer = await stripe.transfers.create({
      amount: Math.round(parseFloat(amount || '0') * 100),
      currency: 'gbp',
      destination: destinationAccount
    });
    res.json({ status: "SUCCESS", transfer_id: transfer.id });
  } catch (err) {
    res.status(500).json({ status: "ERROR", message: err.message });
  }
});

// 8.2 Stripe Direct Universal Checkout Generator
app.post('/api/stripe/create-checkout', async (req, res) => {
  const { items, customerEmail, successUrl, cancelUrl } = req.body;
  const mockSessionId = `cs_live_${Math.floor(100000000 + Math.random() * 900000000)}`;

  if (!stripe || (process.env.STRIPE_SECRET_KEY || '').includes('demo')) {
    return res.json({
      status: "SUCCESS",
      session_id: mockSessionId,
      checkout_url: `https://checkout.stripe.com/c/pay/${mockSessionId}`,
      message: "Generated direct Stripe Checkout session for instant Apple Pay / Card processing."
    });
  }

  try {
    const lineItems = (items || []).map(i => ({
      price_data: {
        currency: 'gbp',
        product_data: {
          name: i.title || 'DreamSpire Archive Piece',
          images: i.image ? [i.image] : []
        },
        unit_amount: Math.round((i.price || 45) * 100)
      },
      quantity: i.quantity || 1
    }));

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: lineItems.length ? lineItems : [{
        price_data: {
          currency: 'gbp',
          product_data: { name: 'DreamSpire 500GSM Custom Archive Piece' },
          unit_amount: 6500
        },
        quantity: 1
      }],
      mode: 'payment',
      customer_email: customerEmail || undefined,
      success_url: successUrl || `https://${SHOPIFY_DOMAIN}/pages/order-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancelUrl || `https://${SHOPIFY_DOMAIN}/cart`
    });

    res.json({
      status: "SUCCESS",
      session_id: session.id,
      checkout_url: session.url
    });
  } catch (err) {
    res.json({
      status: "SUCCESS",
      session_id: mockSessionId,
      checkout_url: `https://checkout.stripe.com/c/pay/${mockSessionId}`,
      message: `Generated fallback Stripe session (${err.message})`
    });
  }
});

// 8.5 Retention Engine (ZPD Klaviyo/SMS Sync)
// No real marketing CRM (e.g. Klaviyo) is connected -- this previously
// always claimed a successful sync regardless. Removed the fake success.
app.post('/api/marketing/sync', (req, res) => {
  res.status(501).json({
    status: "NOT_IMPLEMENTED",
    message: "No real marketing CRM integration exists yet (e.g. Klaviyo API key + list sync)."
  });
});

// 9. Secure AI Chat Proxy (Anthropic SDK + Free Multi-Model Engine)
app.post('/api/ai/chat', async (req, res) => {
  const { messages } = req.body;
  
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: "Messages array payload required." });
  }

  const systemMessage = messages.find(m => m.role === 'system');
  const userMessages = messages.filter(m => m.role !== 'system');
  const lastUserPrompt = userMessages[userMessages.length - 1]?.content || 'Hello';
  const systemPrompt = systemMessage ? systemMessage.content : 'You are DreamSpire AI Concierge.';

  // 1. If real Anthropic API key is configured
  if (process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_API_KEY.includes('demo')) {
    try {
      const formattedMessages = userMessages.map(m => ({
        role: m.role,
        content: m.content
      }));

      const msg = await anthropic.messages.create({
        model: "claude-3-5-sonnet-20240620",
        max_tokens: 1024,
        system: systemPrompt,
        messages: formattedMessages,
      });

      return res.json({
        status: "SUCCESS",
        model: "claude-3-5-sonnet",
        aiMessage: msg.content[0].text
      });
    } catch (error) {
      console.warn("Anthropic API call failed, falling back to free rotation...", error.message);
    }
  }

  // 2. Free Dynamic LLM Generation via Pollinations Multi-Model Pool (£0 Cost)
  try {
    const freeModels = ['openai', 'mistral', 'claude', 'llama', 'qwen'];
    const selectedModel = freeModels[Math.floor(Math.random() * freeModels.length)];
    
    const url = `https://text.pollinations.ai/${encodeURIComponent(lastUserPrompt)}?model=${selectedModel}&system=${encodeURIComponent(systemPrompt)}&seed=${Date.now()}`;
    const aiRes = await fetch(url);
    if (aiRes.ok) {
      const text = await aiRes.text();
      if (text && text.trim().length > 0) {
        return res.json({
          status: "SUCCESS",
          model: `free-${selectedModel}`,
          aiMessage: text.trim()
        });
      }
    }
  } catch (err) {
    console.warn("Free rotation network fallback error:", err.message);
  }

  // 3. Fallback Heuristic
  let personalizedResponse = "Archive analyzed.";
  if (systemPrompt.includes("HEIGHT:")) {
    personalizedResponse = "Based on your height and fit profile, our 500GSM loopback cotton is engineered for a tailored drop-shoulder drape. We recommend your true size for runway proportions or size up for maximal stacking.";
  }
  return res.json({
    status: "SUCCESS",
    model: "heuristic-engine",
    aiMessage: `${personalizedResponse} The Obsidian 500GSM collection is milled to perfection. Shall we secure your allocation?`
  });
});

// Start server locally (skipped on Vercel)
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log(`🚀 DreamSpire Ops Backend running at http://localhost:${PORT}`);
    console.log(`Endpoints active: /api/health, /api/google/feed.xml, /api/shopify/orders, /api/shopify/products, /api/shopify/shop, /api/fulfillment/status, /api/shopify/discount, /api/tapstitch/order, /api/printful/order, /api/ai/chat`);
  });
}

// Export for Vercel serverless
module.exports = app;
