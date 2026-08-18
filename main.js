import { Account, Client, Databases } from 'node-appwrite';
import { createCipheriv, randomBytes } from 'node:crypto';

const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const SANDBOX_CALLBACK_PATH = '/oauth/sandbox/callback';
const PRODUCTION_CALLBACK_PATH = '/oauth/production/callback';

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function requiredEnv(name) {
  const value = process.env[name]?.trim();

  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
}

function normalizeEnvironment(value, source = 'eBay environment') {
  const environment = String(value ?? '').trim().toLowerCase();

  if (environment !== 'sandbox' && environment !== 'production') {
    throw new Error(`${source} must be either "sandbox" or "production".`);
  }

  return environment;
}

function defaultEnvironment() {
  return normalizeEnvironment(requiredEnv('EBAY_ENVIRONMENT'), 'EBAY_ENVIRONMENT');
}

function loadConfig(environment = defaultEnvironment()) {
  const resolvedEnvironment = normalizeEnvironment(environment);
  const credentialPrefix =
    resolvedEnvironment === 'sandbox' ? 'EBAY_SANDBOX' : 'EBAY_PRODUCTION';

  const tokenEncryptionKey = Buffer.from(
    requiredEnv('EBAY_TOKEN_ENCRYPTION_KEY'),
    'base64',
  );

  if (tokenEncryptionKey.length !== 32) {
    throw new Error(
      'EBAY_TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes.',
    );
  }

  const scopes = requiredEnv('EBAY_SCOPES')
    .split(/\s+/)
    .map((scope) => scope.trim())
    .filter(Boolean);

  if (scopes.length === 0) {
    throw new Error('EBAY_SCOPES must contain at least one eBay OAuth scope.');
  }

  return {
    environment: resolvedEnvironment,
    clientId: requiredEnv(`${credentialPrefix}_CLIENT_ID`),
    clientSecret: requiredEnv(`${credentialPrefix}_CLIENT_SECRET`),
    ruName: requiredEnv(`${credentialPrefix}_RU_NAME`),
    scopes,
    appReturnUrl: requiredEnv('EBAY_APP_RETURN_URL'),
    tokenEncryptionKey,
    databaseId: requiredEnv('APPWRITE_EBAY_DATABASE_ID'),
    statesCollectionId: requiredEnv(
      'APPWRITE_EBAY_OAUTH_STATES_COLLECTION_ID',
    ),
    connectionsCollectionId: requiredEnv(
      'APPWRITE_EBAY_CONNECTIONS_COLLECTION_ID',
    ),
  };
}

function createAdminDatabases(req) {
  const dynamicApiKey = req.headers['x-appwrite-key'];

  if (!dynamicApiKey) {
    throw new Error('Appwrite dynamic API key was not provided.');
  }

  const client = new Client()
    .setEndpoint(process.env.APPWRITE_FUNCTION_API_ENDPOINT)
    .setProject(process.env.APPWRITE_FUNCTION_PROJECT_ID)
    .setKey(dynamicApiKey);

  return new Databases(client);
}

async function getAuthenticatedUserId(req) {
  const userJwt = req.headers['x-appwrite-user-jwt'];

  if (!userJwt) {
    throw new HttpError(401, 'You must be signed in to connect eBay.');
  }

  try {
    const userClient = new Client()
      .setEndpoint(process.env.APPWRITE_FUNCTION_API_ENDPOINT)
      .setProject(process.env.APPWRITE_FUNCTION_PROJECT_ID)
      .setJWT(userJwt);

    const account = new Account(userClient);
    const user = await account.get();

    return user.$id;
  } catch {
    throw new HttpError(401, 'Your KeepFlip session has expired. Sign in again.');
  }
}

function createState(environment) {
  const marker = environment === 'sandbox' ? 's' : 'p';

  // Two-character environment prefix + 32 random base64url characters stays
  // below Appwrite's 36-character document-ID limit.
  return `s${marker}${randomBytes(24).toString('base64url')}`;
}

function environmentFromState(state) {
  if (typeof state !== 'string' || state.length < 3 || state[0] !== 's') {
    return null;
  }

  if (state[1] === 's') return 'sandbox';
  if (state[1] === 'p') return 'production';
  return null;
}

function getQueryValue(req, key) {
  const value = req.query?.[key];

  if (Array.isArray(value)) {
    return value[0] ?? '';
  }

  return typeof value === 'string' ? value : '';
}

function getRequestPath(req) {
  if (typeof req.path === 'string' && req.path) {
    return new URL(req.path, 'https://keepflip.invalid').pathname;
  }

  if (typeof req.url === 'string' && req.url) {
    return new URL(req.url, 'https://keepflip.invalid').pathname;
  }

  return '/';
}

function callbackEnvironmentFromPath(path) {
  if (path === SANDBOX_CALLBACK_PATH) return 'sandbox';
  if (path === PRODUCTION_CALLBACK_PATH) return 'production';
  return null;
}

function requestedEnvironment(body) {
  const requested = body?.environment;

  if (requested === undefined || requested === null || requested === '') {
    return defaultEnvironment();
  }

  return normalizeEnvironment(requested, 'OAuth start environment');
}

function getAuthorizationEndpoint(environment) {
  return environment === 'sandbox'
    ? 'https://auth.sandbox.ebay.com/oauth2/authorize'
    : 'https://auth.ebay.com/oauth2/authorize';
}

function getTokenEndpoint(environment) {
  return environment === 'sandbox'
    ? 'https://api.sandbox.ebay.com/identity/v1/oauth2/token'
    : 'https://api.ebay.com/identity/v1/oauth2/token';
}

function buildAuthorizationUrl(config, state) {
  const url = new URL(getAuthorizationEndpoint(config.environment));

  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', config.ruName);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', config.scopes.join(' '));
  url.searchParams.set('state', state);

  return url.toString();
}

function encryptToken(value, encryptionKey) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);

  const ciphertext = Buffer.concat([
    cipher.update(value, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return [
    'v1',
    iv.toString('base64url'),
    authTag.toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

function expiresAtFromSeconds(seconds, fieldName) {
  const value = Number(seconds);

  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`eBay did not return a valid ${fieldName}.`);
  }

  return new Date(Date.now() + value * 1000).toISOString();
}

async function exchangeAuthorizationCode(config, code) {
  const form = new URLSearchParams();

  form.set('grant_type', 'authorization_code');
  form.set('code', code);
  form.set('redirect_uri', config.ruName);

  const basicCredentials = Buffer.from(
    `${config.clientId}:${config.clientSecret}`,
  ).toString('base64');

  const response = await fetch(getTokenEndpoint(config.environment), {
    method: 'POST',
    headers: {
      authorization: `Basic ${basicCredentials}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: form.toString(),
  });

  let payload = null;

  try {
    payload = await response.json();
  } catch {
    // Do not expose a provider response to the user.
  }

  if (!response.ok) {
    throw new Error(`eBay token exchange failed with status ${response.status}.`);
  }

  if (!payload?.access_token || !payload?.refresh_token) {
    throw new Error('eBay returned an incomplete OAuth token response.');
  }

  return payload;
}

async function saveConnection({
  databases,
  config,
  userId,
  tokenResponse,
}) {
  const accessTokenExpiresAt = expiresAtFromSeconds(
    tokenResponse.expires_in,
    'access-token expiry',
  );

  const refreshTokenExpiresAt = expiresAtFromSeconds(
    tokenResponse.refresh_token_expires_in,
    'refresh-token expiry',
  );

  await databases.upsertDocument({
    databaseId: config.databaseId,
    collectionId: config.connectionsCollectionId,
    documentId: userId,
    data: {
      userId,
      environment: config.environment,
      accessTokenCiphertext: encryptToken(
        tokenResponse.access_token,
        config.tokenEncryptionKey,
      ),
      accessTokenExpiresAt,
      refreshTokenCiphertext: encryptToken(
        tokenResponse.refresh_token,
        config.tokenEncryptionKey,
      ),
      refreshTokenExpiresAt,
      scopeList: config.scopes.join(' '),
      isActive: true,
      connectedAt: new Date().toISOString(),
    },
  });
}

function escapeHtml(value) {
  const entities = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };

  return String(value).replace(/[&<>"']/g, (character) => entities[character]);
}

function resultPage(status, appUrl) {
  const messages = {
    connected: {
      title: 'eBay connected',
      body: 'Your eBay account is now connected to KeepFlip.',
    },
    declined: {
      title: 'Connection cancelled',
      body: 'No eBay account was connected.',
    },
    invalid: {
      title: 'Connection expired',
      body: 'Please return to KeepFlip and try connecting eBay again.',
    },
    error: {
      title: 'Could not connect eBay',
      body: 'Please return to KeepFlip and try again.',
    },
  };

  const message = messages[status] ?? messages.error;
  const safeHref = escapeHtml(appUrl);
  const appUrlForScript = JSON.stringify(appUrl).replace(/</g, '\\u003c');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${message.title}</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #070b16;
      color: #f7f8ff;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(420px, calc(100% - 48px));
      text-align: center;
    }
    h1 { margin: 0 0 12px; font-size: 28px; }
    p { margin: 0 0 28px; color: #b8c0d9; line-height: 1.5; }
    a {
      display: inline-block;
      padding: 14px 20px;
      border-radius: 12px;
      background: #7c5cff;
      color: #fff;
      text-decoration: none;
      font-weight: 700;
    }
  </style>
</head>
<body>
  <main>
    <h1>${message.title}</h1>
    <p>${message.body}</p>
    <a href="${safeHref}">Return to KeepFlip</a>
  </main>
  <script>
    window.setTimeout(function () {
      window.location.assign(${appUrlForScript});
    }, 150);
  </script>
</body>
</html>`;
}

function returnToApp(res, config, status, statusCode = 200) {
  const appUrl = new URL(config.appReturnUrl);
  appUrl.searchParams.set('ebay', status);
  appUrl.searchParams.set('ebayEnvironment', config.environment);

  return res.text(resultPage(status, appUrl.toString()), statusCode, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'content-security-policy':
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'",
  });
}

async function handleStart({ req, res, databases, config }) {
  const userId = await getAuthenticatedUserId(req);
  const state = createState(config.environment);

  await databases.createDocument({
    databaseId: config.databaseId,
    collectionId: config.statesCollectionId,
    documentId: state,
    data: {
      userId,
      expiresAt: new Date(Date.now() + OAUTH_STATE_TTL_MS).toISOString(),
      used: false,
    },
  });

  return res.json({
    environment: config.environment,
    authorizationUrl: buildAuthorizationUrl(config, state),
  });
}

async function handleStatus({ req, res, databases, config }) {
  const userId = await getAuthenticatedUserId(req);

  try {
    const connection = await databases.getDocument({
      databaseId: config.databaseId,
      collectionId: config.connectionsCollectionId,
      documentId: userId,
    });

    return res.json({
      connected: Boolean(connection.isActive),
      environment: connection.environment,
      accessTokenExpiresAt: connection.accessTokenExpiresAt,
      refreshTokenExpiresAt: connection.refreshTokenExpiresAt,
    });
  } catch (error) {
    if (Number(error?.code) === 404) {
      return res.json({ connected: false });
    }

    throw error;
  }
}

async function handleCallback({ req, res, log, error, databases, config }) {
  const state = getQueryValue(req, 'state');

  if (!state || environmentFromState(state) !== config.environment) {
    return returnToApp(res, config, 'invalid', 400);
  }

  let stateDocument;

  try {
    stateDocument = await databases.getDocument({
      databaseId: config.databaseId,
      collectionId: config.statesCollectionId,
      documentId: state,
    });
  } catch {
    return returnToApp(res, config, 'invalid', 400);
  }

  const stateExpiry = Date.parse(stateDocument.expiresAt);

  if (
    stateDocument.used === true ||
    !Number.isFinite(stateExpiry) ||
    stateExpiry < Date.now()
  ) {
    return returnToApp(res, config, 'invalid', 400);
  }

  // Consume state before exchanging the code so it cannot be replayed.
  await databases.updateDocument({
    databaseId: config.databaseId,
    collectionId: config.statesCollectionId,
    documentId: state,
    data: {
      used: true,
      usedAt: new Date().toISOString(),
    },
  });

  const oauthError = getQueryValue(req, 'error');

  if (oauthError) {
    log(`eBay ${config.environment} OAuth was cancelled or declined by the user.`);
    return returnToApp(res, config, 'declined');
  }

  const code = getQueryValue(req, 'code');

  if (!code) {
    return returnToApp(res, config, 'error', 400);
  }

  try {
    const tokenResponse = await exchangeAuthorizationCode(config, code);

    await saveConnection({
      databases,
      config,
      userId: stateDocument.userId,
      tokenResponse,
    });

    return returnToApp(res, config, 'connected');
  } catch (caughtError) {
    error(
      `eBay ${config.environment} OAuth callback failed: ${caughtError?.name ?? 'unknown error'}: ${caughtError?.message ?? 'no message'}`,
    );

    return returnToApp(res, config, 'error', 502);
  }
}

export default async ({ req, res, log, error }) => {
  let config;

  try {
    const databases = createAdminDatabases(req);
    const requestPath = getRequestPath(req);

    if (req.method === 'GET') {
      const callbackEnvironment = callbackEnvironmentFromPath(requestPath);

      if (!callbackEnvironment) {
        return res.json({ error: 'OAuth callback route not found.' }, 404);
      }

      config = loadConfig(callbackEnvironment);

      return handleCallback({
        req,
        res,
        log,
        error,
        databases,
        config,
      });
    }

    if (req.method !== 'POST') {
      return res.json({ error: 'Method not allowed.' }, 405);
    }

    const body = req.bodyJson ?? {};
    const action = body?.action;

    if (action === 'start') {
      config = loadConfig(requestedEnvironment(body));
      return handleStart({ req, res, databases, config });
    }

    if (action === 'status') {
      config = loadConfig(defaultEnvironment());
      return handleStatus({ req, res, databases, config });
    }

    return res.json(
      { error: 'Unsupported action. Use "start" or "status".' },
      400,
    );
  } catch (caughtError) {
    error(
      `eBay OAuth function failed: ${caughtError?.name ?? 'unknown error'}: ${caughtError?.message ?? 'no message'}`,
    );

    if (req.method === 'GET' && config) {
      return returnToApp(res, config, 'error', 500);
    }

    const status =
      caughtError instanceof HttpError ? caughtError.status : 500;

    return res.json(
      {
        error:
          caughtError instanceof HttpError
            ? caughtError.message
            : 'Unable to process the eBay connection.',
      },
      status,
    );
  }
};
