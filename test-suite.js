// ============================================================
// DreamSpire Automated Integration Test Suite
// Validates all 10 core orchestrator endpoints
// ============================================================

const BASE_URL = process.env.TEST_API_URL || 'http://localhost:4000';

async function runTests() {
  console.log('\n============================================================');
  console.log(`🧪 DREAMSPIRE AUTOMATED INTEGRATION TEST SUITE`);
  console.log(`Target: ${BASE_URL}`);
  console.log('============================================================\n');

  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      process.stdout.write(`▸ Testing: ${name}... `);
      await fn();
      console.log('✓ PASS');
      passed++;
    } catch (err) {
      console.log(`✗ FAIL (${err.message})`);
      failed++;
    }
  }

  // 1. Health Endpoint
  await test('GET /api/health (Ecosystem Health Check)', async () => {
    const res = await fetch(`${BASE_URL}/api/health`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'OPERATIONAL') throw new Error('Status not OPERATIONAL');
    if (!data.stakeholders?.shopify) throw new Error('Missing Shopify stakeholder');
  });

  // 2. Google Product Feed XML
  await test('GET /api/google/feed.xml (Google Merchant Center RSS Feed)', async () => {
    const res = await fetch(`${BASE_URL}/api/google/feed.xml`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const xml = await res.text();
    if (!xml.includes('<rss') || !xml.includes('DreamSpire')) throw new Error('Invalid XML feed');
  });

  // 3. Shopify Dynamic Discount Engine
  await test('POST /api/shopify/discount (VIP Price Rule Generation)', async () => {
    const res = await fetch(`${BASE_URL}/api/shopify/discount`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'youth_pass', value: 15 })
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'SUCCESS' || !data.code) throw new Error('Failed to generate discount code');
  });

  // 4. Shopify Orders Sync
  await test('GET /api/shopify/orders (Live Admin Orders Sync)', async () => {
    const res = await fetch(`${BASE_URL}/api/shopify/orders`);
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'SUCCESS' || !Array.isArray(data.orders)) throw new Error('Orders not array');
  });

  // 5. Tapstitch Cut & Sew 500GSM Webhook
  await test('POST /api/tapstitch/order (500GSM Manufacturing Queue)', async () => {
    const res = await fetch(`${BASE_URL}/api/tapstitch/order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ product: 'DreamSpire 500GSM Hoodie', quantity: 2, size: 'XL', priority: 'HIGH' })
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'SUCCESS' || !data.po_number) throw new Error('No PO number generated');
  });

  // 6. Printful Accessories API
  await test('POST /api/printful/order (3D Puff Embroidery Queue)', async () => {
    const res = await fetch(`${BASE_URL}/api/printful/order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ product: 'DreamSpire Trucker Cap', designFile: 'embroidery_v1.dst' })
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'SUCCESS' || !data.sync_id) throw new Error('No sync ID generated');
  });

  // 7. Universal Social Publisher
  await test('POST /api/social/publish (TikTok/Snapchat/IG Broadcast)', async () => {
    const res = await fetch(`${BASE_URL}/api/social/publish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ campaign: 'Drop 001 Test Release', networks: ['TikTok Shop', 'Snapchat AR'] })
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'SUCCESS' || !data.reach_estimate) throw new Error('Invalid social dispatch');
  });

  // 8. Stripe Connect Instant Payout
  await test('POST /api/stripe/payout (15% Creator Commission Instant Payout)', async () => {
    const res = await fetch(`${BASE_URL}/api/stripe/payout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ creatorId: 'CR-UK-TEST', amount: '85.00' })
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'SUCCESS' || !data.transaction_id) throw new Error('No txn ID generated');
  });

  // 9. Zero-Party Data Marketing Sync
  await test('POST /api/marketing/sync (ZPD Klaviyo/SMS Pipeline)', async () => {
    const res = await fetch(`${BASE_URL}/api/marketing/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'test-vip@dreamspire.com',
        phone: '+447911123456',
        zpd: { height: '185cm', fit: 'Oversized', color: 'Obsidian' }
      })
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'SUCCESS') throw new Error('Failed to sync ZPD');
  });

  // 10. AI Concierge Multi-Tier Engine
  await test('POST /api/ai/chat (Multi-Tier AI Rotation & Stylist Engine)', async () => {
    const res = await fetch(`${BASE_URL}/api/ai/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages: [
          { role: 'system', content: 'You are DreamSpire AI Concierge. User HEIGHT: 180cm, FIT: Oversized.' },
          { role: 'user', content: 'What size hoodie should I get?' }
        ]
      })
    });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const data = await res.json();
    if (data.status !== 'SUCCESS' || !data.aiMessage) throw new Error('No AI message returned');
  });

  console.log('\n============================================================');
  console.log(`📊 TEST RESULTS: ${passed} PASSED / ${failed} FAILED (Total: ${passed + failed})`);
  console.log('============================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Fatal Test Runner Error:', err);
  process.exit(1);
});
