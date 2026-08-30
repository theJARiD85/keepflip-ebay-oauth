export const KEEPFLIP_EBAY_USER_SCOPES = Object.freeze([
    'https://api.ebay.com/oauth/api_scope',
    'https://api.ebay.com/oauth/api_scope/commerce.identity.readonly',
  
    // Create/manage inventory items, offers, locations, and listings.
    'https://api.ebay.com/oauth/api_scope/sell.inventory',
  
    // Read payment, fulfillment, and return business policies.
    // KeepFlip does not need permission to edit them for this test.
    'https://api.ebay.com/oauth/api_scope/sell.account.readonly',
  ]);
  
  export function enforceKeepFlipEbayUserScopes(environment = process.env) {
    const value = KEEPFLIP_EBAY_USER_SCOPES.join(' ');
    environment.EBAY_OAUTH_SCOPES = value;
    return value;
  }