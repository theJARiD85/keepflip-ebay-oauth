import assert from 'node:assert/strict';
import test from 'node:test';

import {
  KEEPFLIP_EBAY_USER_SCOPES,
  enforceKeepFlipEbayUserScopes,
} from '../src/scope-policy.js';

test('uses only the scopes required by the connected-account identity flow', () => {
  assert.deepEqual(KEEPFLIP_EBAY_USER_SCOPES, [
    'https://api.ebay.com/oauth/api_scope',
    'https://api.ebay.com/oauth/api_scope/commerce.identity.readonly',
    'https://api.ebay.com/oauth/api_scope/sell.inventory',
  ]);
});

test('overwrites a stale broad OAuth scope environment value', () => {
  const environment = {
    EBAY_OAUTH_SCOPES:
      'https://api.ebay.com/oauth/api_scope/sell.inventory https://api.ebay.com/oauth/api_scope/commerce.message',
  };

  const value = enforceKeepFlipEbayUserScopes(environment);

  assert.equal(
    value,
    'https://api.ebay.com/oauth/api_scope https://api.ebay.com/oauth/api_scope/commerce.identity.readonly https://api.ebay.com/oauth/api_scope/sell.inventory',
  );
  assert.equal(environment.EBAY_OAUTH_SCOPES, value);
});
