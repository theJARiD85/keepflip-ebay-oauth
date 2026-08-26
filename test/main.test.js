import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import {
  connectionRowId,
  createHandler,
  oauthStateRowId,
} from '../src/original-main.js';

const FIXED_NOW = new Date('2026-08-25T12:00:00.000Z');
const ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64');
const HMAC_KEY = Buffer.alloc(32, 8).toString('base64');

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  };
}

function installEnvironment(t) {
  const values = {
    APPWRITE_FUNCTION_API_ENDPOINT: 'https://appwrite.test/v1',
    APPWRITE_FUNCTION_PROJECT_ID: 'keepflip-project',
    EBAY_SANDBOX_CLIENT_ID: 'sandbox-client',
    EBAY_SANDBOX_CLIENT_SECRET: 'sandbox-secret',
    EBAY_SANDBOX_RU_NAME: 'KeepFlip-Sandbox-RuName',
    EBAY_PRODUCTION_CLIENT_ID: 'production-client',
    EBAY_PRODUCTION_CLIENT_SECRET: 'production-secret',
    EBAY_PRODUCTION_RU_NAME: 'KeepFlip-Production-RuName',
    EBAY_TOKEN_ENCRYPTION_KEY: ENCRYPTION_KEY,
    EBAY_USER_ID_HMAC_KEY: HMAC_KEY,
    EBAY_APP_RETURN_URL: 'keepflip://ebay/connected',
    APPWRITE_EBAY_DATABASE_ID: 'keepflip',
    APPWRITE_EBAY_CONNECTIONS_TABLE_ID: 'ebay_connections',
    APPWRITE_EBAY_OAUTH_STATES_TABLE_ID: 'ebay_oauth_states',
  };
  const previous = Object.fromEntries(
    Object.keys(values).map((key) => [key, process.env[key]]),
  );

  Object.assign(process.env, values);
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

function responseRecorder() {
  const result = {};
  return {
    result,
    res: {
      redirect(url, status) {
        result.redirect = { url, status };
        return result.redirect;
      },
      json(body, status = 200) {
        result.json = { body, status };
        return result.json;
      },
    },
  };
}

function callbackRequest(query, path = '/oauth/ebay/callback') {
  return {
    method: 'GET',
    path,
    query,
    headers: {
      'x-appwrite-key': 'dynamic-appwrite-key',
    },
  };
}

function stateRecord(environment, ownerId = 'keepflip-user-123') {
  return {
    ownerId,
    environment,
    status: 'pending',
    expiresAt: new Date(FIXED_NOW.getTime() + 60_000).toISOString(),
  };
}

test('exchanges a Sandbox callback, writes encrypted tokens, HMAC identity, and a display username, then deep-links safely', async (t) => {
  installEnvironment(t);
  const state = Buffer.alloc(32, 4).toString('base64url');
  const code = 'sandbox-authorize-code';
  const ownerId = 'keepflip-user-123';
  const rawEbayUserId = 'ebay-user-456';
  const calls = [];
  let savedConnection;

  const handler = createHandler({
    now: () => FIXED_NOW,
    randomBytesImpl: (size) => Buffer.alloc(size, 9),
    fetchImpl: async (url, options = {}) => {
      const request = {
        url: String(url),
        method: options.method || 'GET',
        body: options.body,
      };
      calls.push(request);
      const target = new URL(request.url);

      if (
        request.method === 'GET' &&
        target.pathname.endsWith(
          '/tablesdb/keepflip/tables/ebay_oauth_states/rows/' +
            oauthStateRowId(state),
        )
      ) {
        return jsonResponse(stateRecord('sandbox', ownerId));
      }

      if (
        request.method === 'PATCH' &&
        target.pathname.endsWith('/tablesdb/keepflip/tables/ebay_oauth_states/rows')
      ) {
        return jsonResponse({ total: 1 });
      }

      if (
        request.method === 'POST' &&
        request.url === 'https://api.sandbox.ebay.com/identity/v1/oauth2/token'
      ) {
        const form = new URLSearchParams(request.body);
        assert.equal(form.get('grant_type'), 'authorization_code');
        assert.equal(form.get('code'), code);
        assert.equal(form.get('redirect_uri'), 'KeepFlip-Sandbox-RuName');
        return jsonResponse({
          access_token: 'raw-access-token',
          refresh_token: 'raw-refresh-token',
          expires_in: 7_200,
          refresh_token_expires_in: 31_536_000,
        });
      }

      if (
        request.method === 'GET' &&
        request.url ===
          'https://apiz.sandbox.ebay.com/commerce/identity/v1/user/'
      ) {
        return jsonResponse({ userId: rawEbayUserId });
      }

      if (
        request.method === 'PUT' &&
        target.pathname.endsWith(
          '/tablesdb/keepflip/tables/ebay_connections/rows/' +
            connectionRowId(ownerId, 'sandbox'),
        )
      ) {
        savedConnection = JSON.parse(request.body);
        return jsonResponse({ $id: connectionRowId(ownerId, 'sandbox') }, 201);
      }

      throw new Error('Unexpected request: ' + request.method + ' ' + request.url);
    },
  });
  const { res, result } = responseRecorder();

  await handler({
    req: callbackRequest({ state, code }),
    res,
    error: () => {},
  });

  assert.deepEqual(result.redirect.status, 302);
  const destination = new URL(result.redirect.url);
  assert.equal(destination.protocol, 'keepflip:');
  assert.equal(destination.hostname, 'ebay');
  assert.equal(destination.pathname, '/connected');
  assert.equal(destination.searchParams.get('status'), 'connected');
  assert.equal(destination.searchParams.get('environment'), 'sandbox');
  assert.equal(destination.searchParams.has('state'), false);
  assert.equal(destination.searchParams.has('code'), false);
  assert.equal(result.redirect.url.includes('raw-access-token'), false);
  assert.equal(result.redirect.url.includes('raw-refresh-token'), false);

  assert.equal(savedConnection.data.ownerId, ownerId);
  assert.equal(
    savedConnection.data.hashedEbayId,
    createHmac('sha256', Buffer.from(HMAC_KEY, 'base64'))
      .update('keepflip|ebay-user-id|v1|' + rawEbayUserId, 'utf8')
      .digest('hex'),
  );
  assert.equal(savedConnection.data.hashedEbayId.length, 64);
  assert.equal(savedConnection.data.ebayUsername, rawEbayUserId);
  assert.equal(savedConnection.data.encryptedTokens.startsWith('v1.'), true);
  assert.equal(savedConnection.data.encryptedTokens.includes('raw-access-token'), false);
  assert.equal(savedConnection.data.encryptedTokens.includes('raw-refresh-token'), false);

  const stateWrites = calls
    .filter((call) => call.method === 'PATCH')
    .map((call) => JSON.parse(call.body));
  assert.equal(
    stateWrites.some((body) => JSON.stringify(body).includes(state)),
    false,
  );
  assert.equal(stateWrites[0].data.status, 'processing');
  assert.equal(stateWrites.at(-1).data.status, 'completed');
});

test('uses the environment saved with the state on the shared callback route', async (t) => {
  installEnvironment(t);
  const state = Buffer.alloc(32, 5).toString('base64url');
  const calls = [];
  const handler = createHandler({
    now: () => FIXED_NOW,
    fetchImpl: async (url, options = {}) => {
      const request = { url: String(url), method: options.method || 'GET' };
      calls.push(request);
      if (request.method === 'GET') return jsonResponse(stateRecord('sandbox'));
      if (request.method === 'PATCH') return jsonResponse({ total: 1 });
      if (
        request.url ===
        'https://api.sandbox.ebay.com/identity/v1/oauth2/token'
      ) {
        return jsonResponse({});
      }
      throw new Error('Unexpected request: ' + request.method + ' ' + request.url);
    },
  });
  const { res, result } = responseRecorder();

  await handler({
    req: callbackRequest({ state, code: 'should-not-exchange' }),
    res,
    error: () => {},
  });

  const destination = new URL(result.redirect.url);
  assert.equal(destination.searchParams.get('status'), 'error');
  assert.equal(destination.searchParams.get('environment'), 'sandbox');
  assert.equal(
    calls.some((call) => call.url.includes('api.sandbox.ebay.com/identity/v1/oauth2/token')),
    true,
  );
  assert.equal(
    calls.some((call) => call.url.includes('api.ebay.com/identity/v1/oauth2/token')),
    false,
  );
});

test('marks a user-declined Sandbox request without attempting token exchange', async (t) => {
  installEnvironment(t);
  const state = Buffer.alloc(32, 6).toString('base64url');
  const calls = [];
  const handler = createHandler({
    now: () => FIXED_NOW,
    fetchImpl: async (url, options = {}) => {
      calls.push({
        url: String(url),
        method: options.method || 'GET',
        body: options.body,
      });
      const target = new URL(String(url));
      if ((options.method || 'GET') === 'GET') {
        return jsonResponse(stateRecord('sandbox'));
      }
      if (
        options.method === 'PATCH' &&
        target.pathname.endsWith('/tablesdb/keepflip/tables/ebay_oauth_states/rows')
      ) {
        return jsonResponse({ total: 1 });
      }
      if (options.method === 'PATCH') {
        return jsonResponse({ $id: oauthStateRowId(state) });
      }
      throw new Error('Unexpected request');
    },
  });
  const { res, result } = responseRecorder();

  await handler({
    req: callbackRequest(
      { state },
      '/oauth/ebay/declined',
    ),
    res,
    error: () => {},
  });

  const destination = new URL(result.redirect.url);
  assert.equal(destination.searchParams.get('status'), 'declined');
  assert.equal(
    calls.some((call) => call.url.includes('api.sandbox.ebay.com/identity')),
    false,
  );
  const writes = calls
    .filter((call) => call.method === 'PATCH')
    .map((call) => JSON.parse(call.body));
  assert.equal(writes[0].data.status, 'processing');
  assert.equal(writes[1].data.status, 'declined');
});

test('does not replay a state whose conditional claim affects no row', async (t) => {
  installEnvironment(t);
  const state = Buffer.alloc(32, 7).toString('base64url');
  const calls = [];
  const handler = createHandler({
    now: () => FIXED_NOW,
    fetchImpl: async (url, options = {}) => {
      calls.push({ url: String(url), method: options.method || 'GET' });
      if ((options.method || 'GET') === 'GET') {
        return jsonResponse(stateRecord('sandbox'));
      }
      return jsonResponse({ total: 0 });
    },
  });
  const { res, result } = responseRecorder();

  await handler({
    req: callbackRequest({ state, code: 'replayed-code' }),
    res,
    error: () => {},
  });

  const destination = new URL(result.redirect.url);
  assert.equal(destination.searchParams.get('status'), 'error');
  assert.equal(
    calls.some((call) => call.url.includes('api.sandbox.ebay.com/identity/v1/oauth2/token')),
    false,
  );
});
