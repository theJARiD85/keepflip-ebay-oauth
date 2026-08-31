import {
  createCipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const EbayAuthToken = require('ebay-oauth-nodejs-client');
import { KEEPFLIP_EBAY_USER_SCOPES } from './scope-policy.js';

const STATE_PATTERN = /^[A-Za-z0-9_-]{32,256}$/;

class CallbackError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'CallbackError';
    this.status = status;
  }
}

class UpstreamError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'UpstreamError';
    this.status = status;
  }
}

function fail(status, message) {
  throw new CallbackError(status, message);
}

function cleanText(value, maxLength = 8_000) {
  if (typeof value !== 'string') return '';
  const text = value.trim();
  return text.length <= maxLength ? text : '';
}

function requestHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return '';

  if (typeof headers.get === 'function') {
    return cleanText(headers.get(name));
  }

  const expected = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== expected) continue;
    return cleanText(Array.isArray(value) ? value[0] : value);
  }

  return '';
}

function firstEnvironmentValue(names, fallback = '') {
  for (const name of names) {
    const value = cleanText(process.env[name]);
    if (value) return value;
  }

  return fallback;
}

function requiredEnvironmentValue(names) {
  const value = firstEnvironmentValue(names);
  if (!value) {
    fail(500, 'Missing required eBay OAuth callback configuration.');
  }

  return value;
}

function normalizeEnvironment(value, label = 'OAuth environment') {
  const environment = cleanText(String(value ?? '')).toLowerCase();
  if (environment === 'sandbox' || environment === 'production') {
    return environment;
  }

  fail(400, label + ' must be "sandbox" or "production".');
}

const EBAY_CALLBACK_PATH = '/oauth/ebay/callback';
const EBAY_DECLINED_PATH = '/oauth/ebay/declined';

function callbackRoute(path) {
  if (path === EBAY_CALLBACK_PATH) return 'callback';
  if (path === EBAY_DECLINED_PATH) return 'declined';
  return null;
}

function requestPath(req) {
  const raw = cleanText(req?.path || req?.url || '/') || '/';
  return new URL(raw, 'https://keepflip.invalid').pathname;
}

function queryCandidate(value, maxLength) {
  const raw = Array.isArray(value) ? value[0] : value;
  return cleanText(raw, maxLength);
}

function queryValue(req, name, maxLength = 2_048) {
  const query = req?.query;

  if (query && typeof query.get === 'function') {
    const value = queryCandidate(query.get(name), maxLength);
    if (value) return value;
  }

  if (typeof query === 'string') {
    const value = queryCandidate(
      new URLSearchParams(query.replace(/^\?/, '')).get(name),
      maxLength,
    );
    if (value) return value;
  }

  if (query && typeof query === 'object' && !Array.isArray(query)) {
    const value = queryCandidate(query[name], maxLength);
    if (value) return value;
  }

  const candidateUrls = [req?.url, req?.path, req?.queryString];
  for (const candidate of candidateUrls) {
    const raw = cleanText(candidate, 12_000);
    if (!raw) continue;

    const search =
      raw.includes('?') || raw.startsWith('/')
        ? new URL(raw, 'https://keepflip.invalid').searchParams
        : new URLSearchParams(raw.replace(/^\?/, ''));
    const value = queryCandidate(search.get(name), maxLength);
    if (value) return value;
  }

  return '';
}

function functionRuntime() {
  const endpoint = requiredEnvironmentValue(['APPWRITE_FUNCTION_API_ENDPOINT'])
    .replace(/\/+$/, '');
  const projectId = requiredEnvironmentValue(['APPWRITE_FUNCTION_PROJECT_ID']);

  return { endpoint, projectId };
}

function functionDynamicKey(req) {
  const key =
    requestHeader(req?.headers, 'x-appwrite-key') ||
    cleanText(process.env.APPWRITE_FUNCTION_API_KEY);

  if (!key) {
    fail(500, 'Appwrite did not provide this Function a dynamic API key.');
  }

  return key;
}

function tableConfiguration() {
  return {
    databaseId: firstEnvironmentValue(
      ['APPWRITE_EBAY_DATABASE_ID', 'APPWRITE_DATABASE_ID'],
      'keepflip',
    ),
    connectionsTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_CONNECTIONS_TABLE_ID',
        'APPWRITE_EBAY_CONNECTIONS_COLLECTION_ID',
        'APPWRITE_CONNECTIONS_TABLE_ID',
        'APPWRITE_CONNECTIONS_COLLECTION_ID',
      ],
      'ebay_connections',
    ),
    statesTableId: firstEnvironmentValue(
      [
        'APPWRITE_EBAY_OAUTH_STATES_TABLE_ID',
        'APPWRITE_EBAY_OAUTH_STATES_COLLECTION_ID',
        'APPWRITE_EBAY_STATES_TABLE_ID',
        'APPWRITE_EBAY_STATES_COLLECTION_ID',
      ],
      'ebay_oauth_states',
    ),
  };
}

function decodeBase64Key(name) {
  const text = requiredEnvironmentValue([name]);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    fail(500, name + ' must be Base64 for exactly 32 bytes.');
  }

  const key = Buffer.from(text, 'base64');
  if (key.length !== 32) {
    fail(500, name + ' must decode to exactly 32 bytes.');
  }

  return key;
}

function configurationFor(environment) {
  const normalized = normalizeEnvironment(environment);
  const prefix =
    normalized === 'production' ? 'EBAY_PRODUCTION' : 'EBAY_SANDBOX';

  return {
    ...tableConfiguration(),
    environment: normalized,
    clientId: requiredEnvironmentValue([prefix + '_CLIENT_ID']),
    clientSecret: requiredEnvironmentValue([prefix + '_CLIENT_SECRET']),
    ruName: requiredEnvironmentValue([
      prefix + '_RU_NAME',
      prefix + '_RUNAME',
    ]),
    scopeText: KEEPFLIP_EBAY_USER_SCOPES.join(' '),
    encryptionKey: decodeBase64Key('EBAY_TOKEN_ENCRYPTION_KEY'),
  };
}

function appwriteHeaders(runtime, apiKey) {
  return {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-Appwrite-Project': runtime.projectId,
    'X-Appwrite-Key': apiKey,
  };
}

async function parseResponseBody(response) {
  try {
    const text = await response.text();
    return text ? JSON.parse(text) : {};
  } catch {
    return {};
  }
}

async function appwriteJson({
  fetchImpl,
  runtime,
  apiKey,
  path,
  method = 'GET',
  body,
  failureMessage,
}) {
  let response;

  try {
    response = await fetchImpl(runtime.endpoint + path, {
      method,
      headers: appwriteHeaders(runtime, apiKey),
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new UpstreamError(0, failureMessage);
  }

  const payload = await parseResponseBody(response);
  if (!response.ok) {
    throw new UpstreamError(Number(response.status) || 0, failureMessage);
  }

  return payload;
}

function tableRowsPath(configuration, tableId) {
  return (
    '/tablesdb/' +
    encodeURIComponent(configuration.databaseId) +
    '/tables/' +
    encodeURIComponent(tableId) +
    '/rows'
  );
}

function rowPath(configuration, tableId, rowId) {
  return tableRowsPath(configuration, tableId) + '/' + encodeURIComponent(rowId);
}

function currentDate(now) {
  const value = now();
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (Number.isNaN(date.getTime())) {
    fail(500, 'The OAuth callback clock is invalid.');
  }

  return date;
}

function expiresAt(clock, seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) {
    fail(502, 'eBay returned incomplete authorization data.');
  }

  return new Date(clock.getTime() + value * 1_000).toISOString();
}

export function oauthStateRowId(state) {
  return createHash('sha256')
    .update('keepflip|ebay-oauth-state|v1|' + state, 'utf8')
    .digest('hex')
    .slice(0, 36);
}

export function connectionRowId(userId, environment) {
  return (
    'e' +
    createHash('sha256')
      .update(String(userId) + ':' + String(environment), 'utf8')
      .digest('hex')
      .slice(0, 35)
  );
}

function opaqueState(req) {
  const state = queryValue(req, 'state', 512);
  if (!STATE_PATTERN.test(state)) {
    fail(400, 'The eBay authorization request is invalid.');
  }

  return state;
}

function authorizationCode(req) {
  const code = queryValue(req, 'code', 2_048);
  if (!code) {
    fail(400, 'eBay did not return an authorization code.');
  }

  return code;
}

function authorizationDeclined(req) {
  return (
    Boolean(queryValue(req, 'error', 256)) ||
    queryValue(req, 'isAuthSuccessful', 32).toLowerCase() === 'false' ||
    !queryValue(req, 'code', 2_048)
  );
}

function appReturnUrl(environment, status, state = '') {
  const raw =
    firstEnvironmentValue(['EBAY_APP_RETURN_URL']) ||
    'keepflip://ebay/connected';
  let url;

  try {
    url = new URL(raw);
  } catch {
    fail(500, 'EBAY_APP_RETURN_URL must be a valid deep-link URL.');
  }

  if (url.protocol !== 'keepflip:') {
    fail(500, 'EBAY_APP_RETURN_URL must use the KeepFlip deep-link scheme.');
  }

  url.search = '';
  url.hash = '';
  url.searchParams.set('status', status);
  url.searchParams.set('environment', environment);
  if (state) url.searchParams.set('state', state);
  return url.toString();
}

function fallbackAppReturnUrl(environment, status, state = '') {
  try {
    return appReturnUrl(environment, status, state);
  } catch {
    return (
      'keepflip://ebay/connected?status=' +
      encodeURIComponent(status) +
      '&environment=' +
      encodeURIComponent(environment) +
      (state ? '&state=' + encodeURIComponent(state) : '')
    );
  }
}

function redirectToApp(res, environment, status, state = '') {
  return res.redirect(fallbackAppReturnUrl(environment, status, state), 302);
}

async function readAndClaimState({
  fetchImpl,
  req,
  runtime,
  configuration,
  state,
  now,
}) {
  const apiKey = functionDynamicKey(req);
  const stateRowId = oauthStateRowId(state);
  let record;

  try {
    record = await appwriteJson({
      fetchImpl,
      runtime,
      apiKey,
      path: rowPath(configuration, configuration.statesTableId, stateRowId),
      failureMessage: 'KeepFlip could not validate the eBay authorization request.',
    });
  } catch {
    fail(400, 'The eBay authorization request is invalid.');
  }

  const ownerId = cleanText(record?.ownerId, 64);
  const recordEnvironment = cleanText(record?.environment, 32).toLowerCase();
  const expiresAt = Date.parse(record?.expiresAt);
  const clock = currentDate(now).getTime();

  if (
    !ownerId ||
    !['sandbox', 'production'].includes(recordEnvironment) ||
    record?.status !== 'pending' ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= clock
  ) {
    fail(400, 'The eBay authorization request is invalid.');
  }

  let claimed;
  try {
    claimed = await appwriteJson({
      fetchImpl,
      runtime,
      apiKey,
      method: 'PATCH',
      path: tableRowsPath(configuration, configuration.statesTableId),
      body: {
        data: {
          status: 'processing',
          claimedAt: new Date(clock).toISOString(),
        },
        queries: [
          JSON.stringify({
            method: 'equal',
            attribute: '$id',
            values: [stateRowId],
          }),
          JSON.stringify({
            method: 'equal',
            attribute: 'status',
            values: ['pending'],
          }),
        ],
      },
      failureMessage: 'KeepFlip could not claim the eBay authorization request.',
    });
  } catch {
    fail(409, 'The eBay authorization request is unavailable.');
  }

  const affected =
    Number.isFinite(Number(claimed?.total))
      ? Number(claimed.total)
      : Array.isArray(claimed?.rows)
        ? claimed.rows.length
        : 0;
  if (affected !== 1) {
    fail(409, 'The eBay authorization request is unavailable.');
  }

  return { apiKey, ownerId, stateRowId, environment: recordEnvironment };
}

async function markState({
  fetchImpl,
  runtime,
  configuration,
  apiKey,
  stateRowId,
  status,
  now,
  failureCode,
}) {
  const data = {
    status,
    completedAt: currentDate(now).toISOString(),
  };

  if (failureCode) data.failureCode = failureCode;

  try {
    await appwriteJson({
      fetchImpl,
      runtime,
      apiKey,
      method: 'PATCH',
      path: rowPath(configuration, configuration.statesTableId, stateRowId),
      body: { data },
      failureMessage: 'KeepFlip could not update the eBay authorization request.',
    });
    return true;
  } catch {
    return false;
  }
}

function ebayEnvironmentName(environment) {
  return environment === 'production' ? 'PRODUCTION' : 'SANDBOX';
}

function createEbayClient(configuration, EbayAuthTokenImpl = EbayAuthToken) {
  return new EbayAuthTokenImpl({
    clientId: configuration.clientId,
    clientSecret: configuration.clientSecret,
    redirectUri: configuration.ruName,
    env: ebayEnvironmentName(configuration.environment),
  });
}

function parseTokenResponse(payload) {
  if (typeof payload === 'string') {
    try {
      return JSON.parse(payload);
    } catch {
      fail(502, 'eBay returned an invalid authorization response.');
    }
  }

  return payload && typeof payload === 'object' ? payload : {};
}

async function exchangeAuthorizationCode({
  configuration,
  code,
  ebayAuthTokenFactory,
}) {
  try {
    const payload = await ebayAuthTokenFactory(configuration).exchangeCodeForAccessToken(
      ebayEnvironmentName(configuration.environment),
      code,
    );
    const parsed = parseTokenResponse(payload);

    if (parsed.error) {
      fail(502, 'eBay did not authorize the connection.');
    }

    return parsed;
  } catch (caught) {
    if (caught instanceof CallbackError) throw caught;
    fail(502, 'KeepFlip could not exchange the eBay authorization.');
  }
}

function tokenBundleFromResponse({ payload, configuration, now }) {
  if (
    typeof payload?.access_token !== 'string' ||
    !payload.access_token ||
    typeof payload?.refresh_token !== 'string' ||
    !payload.refresh_token
  ) {
    fail(502, 'eBay returned incomplete authorization data.');
  }

  const clock = currentDate(now);
  return {
    accessToken: payload.access_token,
    refreshToken: payload.refresh_token,
    accessTokenExpiresAt: expiresAt(clock, payload.expires_in),
    refreshTokenExpiresAt: expiresAt(clock, payload.refresh_token_expires_in),
    scopeText: configuration.scopeText,
    updatedAt: clock.toISOString(),
  };
}

function encryptSecret(value, key, randomBytesImpl = randomBytes) {
  const iv = randomBytesImpl(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(value, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return [
    'v1',
    iv.toString('base64url'),
    tag.toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

async function saveConnection({
  fetchImpl,
  runtime,
  configuration,
  apiKey,
  ownerId,
  tokenBundle,
  randomBytesImpl,
}) {
  const data = {
    ownerId,
    encryptedTokens: encryptSecret(
      JSON.stringify(tokenBundle),
      configuration.encryptionKey,
      randomBytesImpl,
    ),
    revokedAt: null,
    updatedAt: tokenBundle.updatedAt,
    // This is the existing required Appwrite column spelling. Keep it until a
    // database migration can safely replace it with a correctly named field.
    envionment: configuration.environment,
  };

  const rowId = connectionRowId(ownerId, configuration.environment);

  try {
    await appwriteJson({
      fetchImpl,
      runtime,
      apiKey,
      method: 'POST',
      path: tableRowsPath(configuration, configuration.connectionsTableId),
      body: { rowId, data },
      failureMessage: 'KeepFlip could not save the eBay connection.',
    });
    return;
  } catch (caught) {
    if (!(caught instanceof UpstreamError && caught.status === 409)) {
      fail(500, 'KeepFlip could not save the eBay connection.');
    }
  }

  try {
    await appwriteJson({
      fetchImpl,
      runtime,
      apiKey,
      method: 'PATCH',
      path: rowPath(configuration, configuration.connectionsTableId, rowId),
      body: { data },
      failureMessage: 'KeepFlip could not save the eBay connection.',
    });
  } catch {
    fail(500, 'KeepFlip could not save the eBay connection.');
  }
}

async function handleCallback({
  req,
  res,
  log,
  error,
  declinedPath,
  fetchImpl,
  now,
  randomBytesImpl,
  ebayAuthTokenFactory,
}) {
  const runtime = functionRuntime();
  const stateConfiguration = tableConfiguration();
  let configuration;
  let environment = 'sandbox';
  let claimed;
  let callbackState = '';

  try {
    const state = opaqueState(req);
    callbackState = state;
    claimed = await readAndClaimState({
      fetchImpl,
      req,
      runtime,
      configuration: stateConfiguration,
      state,
      now,
    });
    environment = claimed.environment;
    configuration = configurationFor(environment);

    if (declinedPath || authorizationDeclined(req)) {
      const marked = await markState({
        fetchImpl,
        runtime,
        configuration,
        apiKey: claimed.apiKey,
        stateRowId: claimed.stateRowId,
        status: 'declined',
        now,
      });

      if (!marked && typeof error === 'function') {
        error('KeepFlip eBay OAuth callback could not mark a declined request.');
      }

      return redirectToApp(res, environment, 'declined', callbackState);
    }

    const tokenResponse = await exchangeAuthorizationCode({
      configuration,
      code: authorizationCode(req),
      ebayAuthTokenFactory,
    });
    const tokenBundle = tokenBundleFromResponse({
      payload: tokenResponse,
      configuration,
      now,
    });
    await saveConnection({
      fetchImpl,
      runtime,
      configuration,
      apiKey: claimed.apiKey,
      ownerId: claimed.ownerId,
      tokenBundle,
      randomBytesImpl,
    });
    if (typeof log === 'function') {
      log('KeepFlip eBay OAuth connection saved.');
    }

    const marked = await markState({
      fetchImpl,
      runtime,
      configuration,
      apiKey: claimed.apiKey,
      stateRowId: claimed.stateRowId,
      status: 'completed',
      now,
    });
    if (!marked && typeof error === 'function') {
      error('KeepFlip eBay OAuth callback could not mark a completed request.');
    }

    return redirectToApp(res, environment, 'connected', callbackState);
  } catch (caught) {
    if (claimed) {
      await markState({
        fetchImpl,
        runtime,
        configuration: configuration || stateConfiguration,
        apiKey: claimed.apiKey,
        stateRowId: claimed.stateRowId,
        status: 'failed',
        now,
        failureCode: 'CALLBACK_FAILED',
      });
    }

    if (typeof error === 'function') {
      error(
        'KeepFlip eBay OAuth callback failed: ' +
          (caught?.message || 'unknown callback error'),
      );
    }

    return redirectToApp(res, environment, 'error', callbackState);
  }
}

function safeError(error) {
  if (typeof error === 'function') {
    error('KeepFlip eBay OAuth callback failed.');
  }
}

export function createHandler({
  fetchImpl = globalThis.fetch,
  now = () => new Date(),
  randomBytesImpl = randomBytes,
  ebayAuthTokenFactory = (configuration) => createEbayClient(configuration),
} = {}) {
  if (typeof fetchImpl !== 'function') {
    fail(500, 'A fetch implementation is required.');
  }

  return async function main({ req, res, log, error } = {}) {
    const path = requestPath(req);
    const route = callbackRoute(path);

    if (req?.method === 'GET' && path === '/') {
      return res.json({
        ok: true,
        service: 'KeepFlip eBay OAuth callback',
        flow: 'authorization_code',
        routes: [
          EBAY_CALLBACK_PATH,
          EBAY_DECLINED_PATH,
        ],
      });
    }

    if (req?.method !== 'GET' || !route) {
      return res.json({ error: 'Endpoint not found.' }, 404);
    }

    try {
      return await handleCallback({
        req,
        res,
        log,
        error,
        declinedPath: route === 'declined',
        fetchImpl,
        now,
        randomBytesImpl,
        ebayAuthTokenFactory,
      });
    } catch {
      safeError(error);
      return redirectToApp(res, 'sandbox', 'error');
    }
  };
}

export const __testables = {
  encryptSecret,
  createEbayClient,
  parseTokenResponse,
};

export default createHandler();


