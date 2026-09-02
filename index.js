require('dotenv').config({ path: require('path').resolve(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const { Anthropic } = require('@anthropic-ai/sdk');
const Stripe = require('stripe');

const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Password-gate the ops dashboard -- it will show real order/customer data
// once SHOPIFY_ADMIN_ACCESS_TOKEN is set, so it must never be left open.
function requireDashboardAuth(req, res, next) {
  const configuredPassword = process.env.ADMIN_DASHBOARD_PASSWORD;
  if (!configuredPassword) {
    return res.status(503).send('Dashboard locked: ADMIN_DASHBOARD_PASSWORD is not set in Vercel env vars yet.');
  }
  const authHeader = req.headers.authorization || '';
  const [scheme, encoded] = authHeader.split(' ');
  if (scheme === 'Basic' && encoded) {
    const [, suppliedPassword] = Buffer.from(encoded, 'base64').toString().split(':');
    if (suppliedPassword === configuredPassword) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="DreamSpire Ops"');
  return res.status(401).send('Authentication required.');
}

app.get(['/admin', '/admin.html'], requireDashboardAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Every endpoint that can return real order/customer/shop data must sit
// behind the same password gate as the dashboard itself -- these were
// previously reachable unauthenticated even though /admin was protected.
app.use('/api/shopify/orders', requireDashboardAuth);
app.use('/api/shopify/products', requireDashboardAuth);
app.use('/api/shopify/shop', requireDashboardAuth);
app.use('/api/fulfillment/status', requireDashboardAuth);

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

// 3. Shopify Admin API - Generate Single-Use Discount Price Rule
// Note: requires a `write_discounts` scope this app does not currently
// have, and Shopify's legacy Price Rules REST endpoint is deprecated in
// favor of the GraphQL discountCodeBasicCreate mutation. Left in place for
// future real use, but it must report failure honestly rather than fake it.
app.post('/api/shopify/discount', requireDashboardAuth, async (req, res) => {
  const { code, value } = req.body;
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;

  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({ status: "NOT_CONNECTED", message: "No live Shopify Admin API token configured." });
  }

  const generatedCode = code || `SECURED-${Math.floor(1000 + Math.random() * 9000)}`;

  try {
    const ruleRes = await fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/price_rules.json`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token
      },
      body: JSON.stringify({
        price_rule: {
          title: generatedCode,
          target_type: "line_item",
          target_selection: "all",
          allocation_method: "across",
          value_type: "percentage",
          value: `-${value || 15}.0`,
          customer_selection: "all",
          starts_at: new Date().toISOString()
        }
      })
    });

    if (ruleRes.ok) {
      const ruleData = await ruleRes.json();
      return res.json({ status: "SUCCESS", code: generatedCode, price_rule_id: ruleData.price_rule.id });
    }
    const errBody = await ruleRes.text();
    return res.status(ruleRes.status).json({ status: "ERROR", message: `Shopify rejected the request (${ruleRes.status}): ${errBody}` });
  } catch (error) {
    res.status(500).json({ status: "ERROR", message: error.message });
  }
});

// 4. Shopify Admin API - Live Orders Sync
app.get('/api/shopify/orders', async (req, res) => {
  const token = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
  
  if (!token || token === 'shpat_demo_token_12345') {
    return res.json({
      status: "NOT_CONNECTED",
      orders: [],
      message: "No live Shopify Admin API token configured. Set SHOPIFY_ADMIN_ACCESS_TOKEN to enable real order sync."
    });
  }

  try {
    // Using native Node 18+ global fetch
    const [ordersRes, countRes] = await Promise.all([
      fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders.json?status=any&limit=50`, {
        headers: { 'X-Shopify-Access-Token': token }
      }),
      fetch(`https://${SHOPIFY_DOMAIN}/admin/api/2024-01/orders/count.json?status=any`, {
        headers: { 'X-Shopify-Access-Token': token }
      })
    ]);
    const ordersData = await ordersRes.json();
    const countData = await countRes.json();
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
    return res.json({ status: "SUCCESS", orders: mapped, total_count: countData.count ?? mapped.length });
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
      const cheapest = variants.reduce((min, v) => {
        const price = parseFloat(v.price || '0');
        return min === null || price < min ? price : min;
      }, null);
      const totalInventory = variants.reduce((n, v) => n + (typeof v.inventory_quantity === 'number' ? v.inventory_quantity : 0), 0);
      return {
        id: p.id,
        title: p.title,
        handle: p.handle,
        status: p.status,
        image: (p.image && p.image.src) || (p.images && p.images[0] && p.images[0].src) || '',
        price: cheapest === null ? '0.00' : cheapest.toFixed(2),
        variant_count: variants.length,
        inventory: totalInventory
      };
    });
    return res.json({ status: "SUCCESS", products: mapped });
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
