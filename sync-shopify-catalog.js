// ============================================================
// DreamSpire Live Catalog Sync Engine
// Pulls all live products, variants, images & pricing via GraphQL
// ============================================================

const fs = require('fs');
const path = require('path');

const SHOPIFY_DOMAIN = process.env.SHOPIFY_SHOP_URL || 'anznev-5s.myshopify.com';
const STOREFRONT_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN || 'd96a070069572cd2dcfa12f18b6dc8e5';
const OUTPUT_PATH = path.resolve(__dirname, '../website/real-shopify-products.json');

const GRAPHQL_QUERY = `
query GetAllProducts {
  products(first: 100) {
    edges {
      node {
        id
        title
        handle
        description
        vendor
        productType
        tags
        priceRange {
          minVariantPrice {
            amount
            currencyCode
          }
          maxVariantPrice {
            amount
            currencyCode
          }
        }
        images(first: 10) {
          edges {
            node {
              url
              altText
            }
          }
        }
        variants(first: 20) {
          edges {
            node {
              id
              title
              price {
                amount
                currencyCode
              }
              availableForSale
            }
          }
        }
      }
    }
  }
}
`;

async function syncCatalog() {
  console.log(`\n▸ Connecting to https://${SHOPIFY_DOMAIN}/api/2024-01/graphql.json...`);
  
  const response = await fetch(`https://${SHOPIFY_DOMAIN}/api/2024-01/graphql.json`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Storefront-Access-Token': STOREFRONT_TOKEN
    },
    body: JSON.stringify({ query: GRAPHQL_QUERY })
  });

  if (!response.ok) {
    throw new Error(`HTTP Error ${response.status}: ${response.statusText}`);
  }

  const json = await response.json();
  
  if (json.errors) {
    console.error('GraphQL Errors:', json.errors);
    throw new Error('Failed to query GraphQL API');
  }

  const productCount = json?.data?.products?.edges?.length || 0;
  console.log(`✓ Successfully pulled ${productCount} fresh products from live Shopify catalog.`);

  fs.writeFileSync(OUTPUT_PATH, JSON.stringify(json, null, 2));
  console.log(`✓ Updated: ${OUTPUT_PATH}`);

  // Also output a brief summary of live products
  console.log('\n--- FRESH CATALOG SUMMARY ---');
  json.data.products.edges.slice(0, 10).forEach((edge, idx) => {
    const p = edge.node;
    const price = p.priceRange?.minVariantPrice?.amount;
    const curr = p.priceRange?.minVariantPrice?.currencyCode;
    const variantCount = p.variants?.edges?.length || 0;
    console.log(`[${idx + 1}] ${p.title} | ${curr} ${price} | ${variantCount} Variants | Handle: ${p.handle}`);
  });
  if (productCount > 10) {
    console.log(`... and ${productCount - 10} more live products synced.\n`);
  }
}

syncCatalog().catch(err => {
  console.error('Sync failed:', err);
  process.exit(1);
});
