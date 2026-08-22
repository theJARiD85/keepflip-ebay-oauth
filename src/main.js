import { Client, Databases } from 'node-appwrite';
import {
    createCipheriv,
    createDecipheriv,
    createHash,
    createHmac,
    randomBytes,
    timingSafeEqual,
} from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const EbayAuthToken = require('ebay-oauth-nodejs-client');

const STATE_TTL_MS = 10 * 60 * 1000;
const EBAY_CALLBACK_PATH = '/oauth/callback';
const EBAY_DECLINED_PATH = '/oauth/declined';

class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.name = 'HttpError';
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

function normalizeEnvironment(value, label = 'environment') {
    const normalized = String(value ?? '').trim().toLowerCase();

    if (normalized !== 'sandbox' && normalized !== 'production') {
        throw new HttpError(
            400,
            `${label} must be "sandbox" or "production".`,
        );
    }

    return normalized;
}

function ebayEnvironmentName(environment) {
    return environment === 'production' ? 'PRODUCTION' : 'SANDBOX';
}

function scopesFromEnvironmentVariable(name) {
    const scopes = requiredEnv(name)
        .split(/\s+/)
        .map((scope) => scope.trim())
        .filter(Boolean);

    if (scopes.length === 0) {
        throw new Error(
            `${name} must contain at least one eBay OAuth scope.`,
        );
    }

    return scopes;
}

function tokenEncryptionKey() {
    const key = Buffer.from(
        requiredEnv('EBAY_TOKEN_ENCRYPTION_KEY'),
        'base64',
    );

    if (key.length !== 32) {
        throw new Error(
            'EBAY_TOKEN_ENCRYPTION_KEY must be base64 for exactly 32 bytes.',
        );
    }

    return key;
}

function stateSecret() {
    const secret = requiredEnv('EBAY_OAUTH_STATE_SECRET');

    if (Buffer.byteLength(secret, 'utf8') < 32) {
        throw new Error(
            'EBAY_OAUTH_STATE_SECRET must be at least 32 bytes long.',
        );
    }

    return secret;
}

function loadConfig(environment) {
    const normalized = normalizeEnvironment(environment);
  
    const prefix =
      normalized === 'sandbox'
        ? 'EBAY_SANDBOX'
        : 'EBAY_PRODUCTION';
  
    return {
      environment: normalized,
  
      ebayEnvironment:
        ebayEnvironmentName(normalized),
  
      clientId:
        requiredEnv(`${prefix}_CLIENT_ID`),
  
      clientSecret:
        requiredEnv(`${prefix}_CLIENT_SECRET`),
  
      ruName:
        requiredEnv(`${prefix}_RU_NAME`),
  
      scopes:
        scopesFromEnvironmentVariable(
          'EBAY_OAUTH_SCOPES',
        ),
  
      appReturnUrl:
        requiredEnv('EBAY_APP_RETURN_URL'),
  
      databaseId:
        requiredEnv(
          'APPWRITE_EBAY_DATABASE_ID',
        ),
  
      connectionsCollectionId:
        requiredEnv(
          'APPWRITE_EBAY_CONNECTIONS_COLLECTION_ID',
        ),
  
      encryptionKey:
        tokenEncryptionKey(),
  
      stateSecret:
        stateSecret(),
    };
  }

function createEbayClient(config) {
    return new EbayAuthToken({
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        redirectUri: config.ruName,
        env: config.ebayEnvironment,
    });
}

function createAdminDatabases(req) {
    const apiKey = req.headers['x-appwrite-key'];

    if (!apiKey) {
        throw new Error(
            'Appwrite did not provide the function dynamic API key.',
        );
    }

    const client = new Client()
        .setEndpoint(
            requiredEnv('APPWRITE_FUNCTION_API_ENDPOINT'),
        )
        .setProject(
            requiredEnv('APPWRITE_FUNCTION_PROJECT_ID'),
        )
        .setKey(apiKey);

    return new Databases(client);
}

function authenticatedUserId(req) {
    const userId = req.headers['x-appwrite-user-id'];

    if (!userId) {
        throw new HttpError(
            401,
            'You must be signed in to KeepFlip to connect eBay.',
        );
    }

    return userId;
}

function requestPath(req) {
    const raw = req.path || req.url || '/';

    return new URL(
        raw,
        'https://keepflip.invalid',
    ).pathname;
}

function requestBody(req) {
    const body = req.bodyJson;

    return body &&
        typeof body === 'object' &&
        !Array.isArray(body)
        ? body
        : {};
}

function queryValue(req, name) {
    const value = req.query?.[name];

    if (Array.isArray(value)) {
        return String(value[0] ?? '');
    }

    return value == null
        ? ''
        : String(value);
}

function encodeState(payload, secret) {
    const encodedPayload = Buffer.from(
        JSON.stringify(payload),
        'utf8',
    ).toString('base64url');

    const signature = createHmac(
        'sha256',
        secret,
    )
        .update(encodedPayload)
        .digest('base64url');

    return `${encodedPayload}.${signature}`;
}

function createState(
    userId,
    environment,
    secret,
) {
    return encodeState(
        {
            v: 1,
            userId,
            environment,
            expiresAt:
                Date.now() + STATE_TTL_MS,
            nonce: randomBytes(16).toString(
                'base64url',
            ),
        },
        secret,
    );
}

function verifyState(
    state,
    expectedEnvironment,
    secret,
) {
    if (
        typeof state !== 'string' ||
        !state.includes('.')
    ) {
        throw new HttpError(
            400,
            'The eBay OAuth state is missing or invalid.',
        );
    }

    const [
        encodedPayload,
        suppliedSignature,
        ...extra
    ] = state.split('.');

    if (
        !encodedPayload ||
        !suppliedSignature ||
        extra.length > 0
    ) {
        throw new HttpError(
            400,
            'The eBay OAuth state is invalid.',
        );
    }

    const expectedSignature = createHmac(
        'sha256',
        secret,
    )
        .update(encodedPayload)
        .digest('base64url');

    const supplied = Buffer.from(
        suppliedSignature,
        'utf8',
    );

    const expected = Buffer.from(
        expectedSignature,
        'utf8',
    );

    if (
        supplied.length !== expected.length ||
        !timingSafeEqual(
            supplied,
            expected,
        )
    ) {
        throw new HttpError(
            400,
            'The eBay OAuth state signature is invalid.',
        );
    }

    let payload;

    try {
        payload = JSON.parse(
            Buffer.from(
                encodedPayload,
                'base64url',
            ).toString('utf8'),
        );
    } catch {
        throw new HttpError(
            400,
            'The eBay OAuth state payload is invalid.',
        );
    }

    if (
        payload?.v !== 1 ||
        typeof payload.userId !== 'string' ||
        !payload.userId ||
        payload.environment !==
        expectedEnvironment ||
        !Number.isFinite(
            payload.expiresAt,
        ) ||
        payload.expiresAt < Date.now()
    ) {
        throw new HttpError(
            400,
            'The eBay OAuth state has expired or does not match this callback.',
        );
    }

    return payload;
}

function connectionDocumentId(
    userId,
    environment,
) {
    return createHash('sha256')
        .update(
            `${userId}:${environment}`,
            'utf8',
        )
        .digest('base64url')
        .slice(0, 36);
}

function encryptSecret(value, key) {
    const iv = randomBytes(12);

    const cipher = createCipheriv(
        'aes-256-gcm',
        key,
        iv,
    );

    const ciphertext =
        Buffer.concat([
            cipher.update(
                value,
                'utf8',
            ),
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

function decryptSecret(value, key) {
    const [
        version,
        ivText,
        tagText,
        ciphertextText,
        ...extra
    ] = String(value ?? '').split('.');

    if (
        version !== 'v1' ||
        !ivText ||
        !tagText ||
        !ciphertextText ||
        extra.length > 0
    ) {
        throw new Error(
            'Stored eBay token ciphertext is invalid.',
        );
    }

    const decipher =
        createDecipheriv(
            'aes-256-gcm',
            key,
            Buffer.from(
                ivText,
                'base64url',
            ),
        );

    decipher.setAuthTag(
        Buffer.from(
            tagText,
            'base64url',
        ),
    );

    return Buffer.concat([
        decipher.update(
            Buffer.from(
                ciphertextText,
                'base64url',
            ),
        ),
        decipher.final(),
    ]).toString('utf8');
}

function expiryIso(
    seconds,
    fieldName,
) {
    const numeric =
        Number(seconds);

    if (
        !Number.isFinite(numeric) ||
        numeric <= 0
    ) {
        throw new Error(
            `eBay did not return a valid ${fieldName}.`,
        );
    }

    return new Date(
        Date.now() +
        numeric * 1000,
    ).toISOString();
}

function tokenEndpoint(environment) {
    return environment ===
        'production'
        ? 'https://api.ebay.com/identity/v1/oauth2/token'
        : 'https://api.sandbox.ebay.com/identity/v1/oauth2/token';
}

async function postTokenRequest(
    config,
    form,
    operation,
) {
    const basicCredentials =
        Buffer.from(
            `${config.clientId}:${config.clientSecret}`,
            'utf8',
        ).toString('base64');

    const response =
        await fetch(
            tokenEndpoint(
                config.environment,
            ),
            {
                method: 'POST',

                headers: {
                    authorization:
                        `Basic ${basicCredentials}`,

                    'content-type':
                        'application/x-www-form-urlencoded',
                },

                body:
                    form.toString(),
            },
        );

    let payload;

    try {
        payload =
            await response.json();
    } catch {
        throw new Error(
            `eBay returned a non-JSON response during ${operation}.`,
        );
    }

    if (
        !response.ok ||
        payload?.error
    ) {
        const providerError =
            payload?.error ||
            `HTTP ${response.status}`;

        const description =
            payload?.error_description
                ? `: ${payload.error_description}`
                : '';

        throw new Error(
            `eBay OAuth ${operation} failed (${providerError}${description}).`,
        );
    }

    if (
        !payload?.access_token ||
        !payload?.expires_in
    ) {
        throw new Error(
            `eBay OAuth ${operation} did not return a usable access token.`,
        );
    }

    return payload;
}

async function exchangeAuthorizationCode(
    config,
    authorizationCode,
) {
    // eBay KB 5075 Step 2:
    // grant_type=authorization_code
    // code=<authorization code>
    // redirect_uri=<RuName>

    const form =
        new URLSearchParams();

    form.set(
        'grant_type',
        'authorization_code',
    );

    form.set(
        'code',
        authorizationCode,
    );

    form.set(
        'redirect_uri',
        config.ruName,
    );

    const payload =
        await postTokenRequest(
            config,
            form,
            'authorization-code exchange',
        );

    if (
        !payload.refresh_token ||
        !payload.refresh_token_expires_in
    ) {
        throw new Error(
            'eBay did not return the refresh token required for a user connection.',
        );
    }

    return payload;
}

async function exchangeRefreshToken(
    config,
    refreshToken,
) {
    // eBay KB 5075 Step 3:
    // grant_type=refresh_token
    // refresh_token=<refresh token>

    const form =
        new URLSearchParams();

    form.set(
        'grant_type',
        'refresh_token',
    );

    form.set(
        'refresh_token',
        refreshToken,
    );

    return postTokenRequest(
        config,
        form,
        'refresh-token exchange',
    );
}

async function saveNewConnection({
    databases,
    config,
    userId,
    tokenResponse,
}) {
    const now =
        new Date().toISOString();

    const documentId =
        connectionDocumentId(
            userId,
            config.environment,
        );

    const accessTokenExpiresAt =
        expiryIso(
            tokenResponse.expires_in,
            'access token expiry',
        );

    await databases.upsertDocument({
        databaseId:
            config.databaseId,

        collectionId:
            config.connectionsCollectionId,

        documentId,

        data: {
            userId,

            environment:
                config.environment,

            accessTokenCiphertext:
                encryptSecret(
                    tokenResponse.access_token,
                    config.encryptionKey,
                ),

            accessTokenExpiresAt,

            refreshTokenCiphertext:
                encryptSecret(
                    tokenResponse.refresh_token,
                    config.encryptionKey,
                ),

            refreshTokenExpiresAt:
                expiryIso(
                    tokenResponse.refresh_token_expires_in,
                    'refresh token expiry',
                ),

            scopeList:
                config.scopes.join(' '),

            tokenType:
                String(
                    tokenResponse.token_type ||
                    'User Access Token',
                ),

            isActive: true,

            connectedAt: now,

            updatedAt: now,
        },
    });
}

async function getConnection(
    databases,
    config,
    userId,
) {
    const documentId =
        connectionDocumentId(
            userId,
            config.environment,
        );

    try {
        return await databases.getDocument({
            databaseId:
                config.databaseId,

            collectionId:
                config.connectionsCollectionId,

            documentId,
        });
    } catch (caught) {
        if (
            Number(caught?.code) ===
            404
        ) {
            return null;
        }

        throw caught;
    }
}

async function refreshStoredConnection({
    databases,
    config,
    connection,
}) {
    const refreshExpiry =
        Date.parse(
            connection.refreshTokenExpiresAt ||
            '',
        );

    if (
        !Number.isFinite(
            refreshExpiry,
        ) ||
        refreshExpiry <= Date.now()
    ) {
        throw new HttpError(
            401,
            'Your eBay authorization has expired. Reconnect your eBay account.',
        );
    }

    const refreshToken =
        decryptSecret(
            connection.refreshTokenCiphertext,
            config.encryptionKey,
        );

    const tokenResponse =
        await exchangeRefreshToken(
            config,
            refreshToken,
        );

    const now =
        new Date().toISOString();

    const accessTokenExpiresAt =
        expiryIso(
            tokenResponse.expires_in,
            'access token expiry',
        );

    await databases.updateDocument({
        databaseId:
            config.databaseId,

        collectionId:
            config.connectionsCollectionId,

        documentId:
            connection.$id,

        data: {
            accessTokenCiphertext:
                encryptSecret(
                    tokenResponse.access_token,
                    config.encryptionKey,
                ),

            accessTokenExpiresAt,

            tokenType:
                String(
                    tokenResponse.token_type ||
                    connection.tokenType ||
                    'User Access Token',
                ),

            isActive: true,

            updatedAt: now,
        },
    });

    return {
        accessTokenExpiresAt,
        updatedAt: now,
    };
}

function appReturnUrl(
    config,
    status,
) {
    const url =
        new URL(
            config.appReturnUrl,
        );

    url.searchParams.set(
        'status',
        status,
    );

    url.searchParams.set(
        'environment',
        config.environment,
    );

    return url.toString();
}

async function handleConnect({
    req,
    res,
}) {
    const userId =
        authenticatedUserId(req);

    const body =
        requestBody(req);

    const environment =
        normalizeEnvironment(
            body.environment,
            'OAuth environment',
        );

    const config =
        loadConfig(environment);

    const state =
        createState(
            userId,
            environment,
            config.stateSecret,
        );

    const ebay =
        createEbayClient(config);

    const authorizationUrl =
        ebay.generateUserAuthorizationUrl(
            config.ebayEnvironment,
            config.scopes,
            {
                state,
            },
        );

    return res.json({
        authorizationUrl,
        environment,
    });
}

async function handleStatus({
    req,
    res,
    databases,
}) {
    const userId =
        authenticatedUserId(req);

    const body =
        requestBody(req);

    const environment =
        normalizeEnvironment(
            body.environment,
            'OAuth environment',
        );

    const config =
        loadConfig(environment);

    const connection =
        await getConnection(
            databases,
            config,
            userId,
        );

    if (
        !connection ||
        connection.isActive !== true
    ) {
        return res.json({
            connected: false,
            environment,
        });
    }

    const accessExpiry =
        Date.parse(
            connection.accessTokenExpiresAt ||
            '',
        );

    const refreshExpiry =
        Date.parse(
            connection.refreshTokenExpiresAt ||
            '',
        );

    const refreshExpired =
        !Number.isFinite(
            refreshExpiry,
        ) ||
        refreshExpiry <= Date.now();

    return res.json({
        connected:
            !refreshExpired,

        environment,

        accessTokenExpiresAt:
            connection.accessTokenExpiresAt,

        refreshTokenExpiresAt:
            connection.refreshTokenExpiresAt,

        accessTokenExpired:
            !Number.isFinite(
                accessExpiry,
            ) ||
            accessExpiry <= Date.now(),

        needsReconnect:
            refreshExpired,
    });
}

async function handleRefresh({
    req,
    res,
    databases,
}) {
    const userId =
        authenticatedUserId(req);

    const body =
        requestBody(req);

    const environment =
        normalizeEnvironment(
            body.environment,
            'OAuth environment',
        );

    const config =
        loadConfig(environment);

    const connection =
        await getConnection(
            databases,
            config,
            userId,
        );

    if (
        !connection ||
        connection.isActive !== true
    ) {
        throw new HttpError(
            404,
            'No connected eBay account was found.',
        );
    }

    const refreshed =
        await refreshStoredConnection({
            databases,
            config,
            connection,
        });

    return res.json({
        refreshed: true,
        connected: true,
        environment,

        accessTokenExpiresAt:
            refreshed.accessTokenExpiresAt,
    });
}

async function handleCallback({
    req,
    res,
    log,
    error,
    databases,
    environment,
}) {
    const config =
        loadConfig(environment);

    const authorizationCode =
        queryValue(
            req,
            'code',
        );

    const returnedState =
        queryValue(
            req,
            'state',
        );

    const providerError =
        queryValue(
            req,
            'error',
        );

    const isAuthSuccessful =
        queryValue(
            req,
            'isAuthSuccessful',
        );

    if (
        providerError ||
        isAuthSuccessful ===
        'false' ||
        !authorizationCode
    ) {
        log(
            `eBay ${environment} authorization was declined or returned without a code.`,
        );

        return res.redirect(
            appReturnUrl(
                config,
                'declined',
            ),
            302,
        );
    }

    try {
        const state =
            verifyState(
                returnedState,
                environment,
                config.stateSecret,
            );

        const tokenResponse =
            await exchangeAuthorizationCode(
                config,
                authorizationCode,
            );

        await saveNewConnection({
            databases,
            config,
            userId:
                state.userId,
            tokenResponse,
        });

        log(
            `eBay ${environment} account connected for KeepFlip user ${state.userId}.`,
        );

        return res.redirect(
            appReturnUrl(
                config,
                'connected',
            ),
            302,
        );
    } catch (caught) {
        error(
            `eBay ${environment} OAuth callback failed: ${caught?.message ||
            String(caught)
            }`,
        );

        return res.redirect(
            appReturnUrl(
                config,
                'error',
            ),
            302,
        );
    }
}

export default async function main({
    req,
    res,
    log,
    error,
}) {
    const path =
        requestPath(req);

    try {
        if (
            req.method === 'GET' &&
            path === '/'
        ) {
            return res.json({
                ok: true,
                service:
                    'KeepFlip eBay OAuth',
                flow:
                    'authorization_code',
            });
        }

        const databases =
            createAdminDatabases(req);

        if (
            req.method === 'POST' &&
            path === '/connect'
        ) {
            return await handleConnect({
                req,
                res,
            });
        }

        if (
            req.method === 'POST' &&
            path === '/status'
        ) {
            return await handleStatus({
                req,
                res,
                databases,
            });
        }

        if (
            req.method === 'POST' &&
            path === '/refresh'
        ) {
            return await handleRefresh({
                req,
                res,
                databases,
            });
        }

        if (
            req.method === 'GET' &&
            path ===
            SANDBOX_CALLBACK_PATH
        ) {
            return await handleCallback({
                req,
                res,
                log,
                error,
                databases,
                environment:
                    'sandbox',
            });
        }

        if (
            req.method === 'GET' &&
            path ===
            PRODUCTION_CALLBACK_PATH
        ) {
            return await handleCallback({
                req,
                res,
                log,
                error,
                databases,
                environment:
                    'production',
            });
        }

        return res.json(
            {
                error:
                    'Endpoint not found.',
            },
            404,
        );
    } catch (caught) {
        const status =
            caught instanceof
                HttpError
                ? caught.status
                : 500;

        if (status >= 500) {
            error(
                caught?.stack ||
                caught?.message ||
                String(caught),
            );
        }

        return res.json(
            {
                error:
                    status >= 500
                        ? 'KeepFlip could not complete the eBay OAuth request.'
                        : caught.message,
            },
            status,
        );
    }
}
