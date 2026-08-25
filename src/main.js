import originalHandler from './original-main.js';
import {
  KEEPFLIP_EBAY_USER_SCOPES,
  enforceKeepFlipEbayUserScopes,
} from './scope-policy.js';

enforceKeepFlipEbayUserScopes();

export { KEEPFLIP_EBAY_USER_SCOPES, enforceKeepFlipEbayUserScopes } from './scope-policy.js';

export default async function main(context) {
  // Re-apply immediately before each request so a stale Appwrite Function
  // environment value cannot silently broaden the user-consent grant.
  enforceKeepFlipEbayUserScopes();
  return originalHandler(context);
}
