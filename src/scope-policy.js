export const KEEPFLIP_EBAY_USER_SCOPES = Object.freeze([
  'https://api.ebay.com/oauth/api_scope',
  'https://api.ebay.com/oauth/api_scope/commerce.identity.readonly',
  'https://api.ebay.com/oauth/api_scope/sell.inventory',
  'https://api.ebay.com/oauth/api_scope/sell.account.readonly',
  'https://api.ebay.com/oauth/api_scope/sell.finances',
  'https://api.ebay.com/oauth/api_scope/sell.fulfillment',
]);

export function enforceKeepFlipEbayUserScopes(environment = process.env) {
  const value = KEEPFLIP_EBAY_USER_SCOPES.join(' ');
  environment.EBAY_OAUTH_SCOPES = value;
  return value;
}
