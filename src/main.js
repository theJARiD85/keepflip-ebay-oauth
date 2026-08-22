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
const EBAY_CALLBACK_PATH = '/oauth/ebay/callback';
const EBAY_DECLINED_PATH = '/oauth/ebay/declined';
// Keep the earlier portal routes working while the eBay developer portal
// finishes moving to the shared /oauth/ebay/* callback paths.
const LEGACY_EBAY_CALLBACK_PATH = '/oauth/callback';
const LEGACY_EBAY_DECLINED_PATH = '/oauth/declined';

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

function cleanText(value, maxLength = 8_000) {
    if (typeof value !== 'string') return '';
    const cleaned = value.trim();
    return cleaned.length <= maxLength
        ? cleaned
        : cleaned.slice(0, maxLength);
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
        ebayEnvironment: ebayEnvironmentName(normalized),

        clientId: requiredEnv(`${prefix}_CLIENT_ID`),
        clientSecret: requiredEnv(`${prefix}_CLIENT_SECRET`),
        ruName: requiredEnv(`${prefix}_RU_NAME`),

        // The eBay keysets share one approved scope list in Appwrite.
        // Environment selection still controls credentials, RuName, and
        // endpoint; scopes remain the single EBAY_OAUTH_SCOPES variable.
        scopes: scopesFromEnvironmentVariable('EBAY_OAUTH_SCOPES'),

        appReturnUrl: requiredEnv('EBAY_APP_RETURN_URL'),

        databaseId: requiredEnv(
            'APPWRITE_EBAY_DATABASE_ID',
        ),

        connectionsCollectionId: requiredEnv(
            'APPWRITE_EBAY_CONNECTIONS_COLLECTION_ID',
        ),

        encryptionKey: tokenEncryptionKey(),
        stateSecret: stateSecret(),
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
    const values = [];
    const parsedQuery = req?.query;

    if (parsedQuery && typeof parsedQuery === 'object' && !Array.isArray(parsedQuery)) {
        values.push(parsedQuery[name]);
    } else if (typeof parsedQuery === 'string') {
        values.push(new URLSearchParams(parsedQuery).get(name));
    }

    if (typeof req?.queryString === 'string') {
        values.push(new URLSearchParams(req.queryString).get(name));
    }

    const requestUrl = cleanText(req?.url, 8_000);
    if (requestUrl) {
        try {
            values.push(
                new URL(requestUrl, 'https://keepflip.invalid').searchParams.get(name),
            );
        } catch {
            // Use the other request representations when the URL is malformed.
        }
    }

    for (const value of values) {
        const first = Array.isArray(value) ? value[0] : value;
        const cleaned = cleanText(first, 8_000);
        if (cleaned) return cleaned;
    }

    return '';
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
        !['sandbox', 'production'].includes(payload.environment) ||
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

function requireTokenResponse(
    payload,
    requireRefreshToken = false,
) {
    let parsedPayload = payload;

    // The current official eBay Node client returns the token response body
    // as a JSON string. Normalize it at this boundary so the rest of the
    // function only handles the documented object shape.
    if (typeof parsedPayload === 'string') {
        try {
            parsedPayload = JSON.parse(parsedPayload);
        } catch {
            throw new Error(
                'eBay OAuth returned an invalid token response.',
            );
        }
    }

    if (parsedPayload?.error) {
        const description =
            parsedPayload.error_description ||
            parsedPayload.error;

        throw new Error(
            `eBay OAuth token request failed: ${description}`,
        );
    }

    if (
        !parsedPayload?.access_token ||
        !Number.isFinite(Number(parsedPayload?.expires_in))
    ) {
        throw new Error(
            'eBay OAuth did not return a usable access token.',
        );
    }

    if (
        requireRefreshToken &&
        (!parsedPayload.refresh_token ||
            !Number.isFinite(Number(parsedPayload.refresh_token_expires_in)))
    ) {
        throw new Error(
            'eBay did not return the refresh token required for a user connection.',
        );
    }

    return parsedPayload;
}

async function exchangeAuthorizationCode(
    config,
    authorizationCode,
) {
    // eBay's official client implements KB 5075 Step 2.
    const payload =
        await createEbayClient(config).exchangeCodeForAccessToken(
            config.ebayEnvironment,
            authorizationCode,
        );

    return requireTokenResponse(
        payload,
        true,
    );
}

async function exchangeRefreshToken(
    config,
    refreshToken,
) {
    // eBay's official client implements KB 5075 Step 3.
    const payload =
        await createEbayClient(config).getAccessToken(
            config.ebayEnvironment,
            refreshToken,
            config.scopes,
        );

    return requireTokenResponse(payload);
}

function ebayUserIdHmacKey() {
    // Prefer the dedicated stable key. The state secret is a server-only
    // fallback for existing deployments that have not added the dedicated key.
    return (
        cleanText(
            process.env.EBAY_USER_ID_HMAC_KEY,
            512,
        ) || stateSecret()
    );
}

function hashEbayUserId(ebayUserId) {
    return createHmac(
        'sha256',
        ebayUserIdHmacKey(),
    )
        .update(
            'keepflip|ebay-user-id|v1|' + ebayUserId,
            'utf8',
        )
        .digest('hex');
}

function ebayIdentityEndpoint(environment) {
    return environment === 'production'
        ? 'https://api.ebay.com/commerce/identity/v1/user/'
        : 'https://api.sandbox.ebay.com/commerce/identity/v1/user/';
}

async function getEbayIdentity(config, accessToken) {
    let response;

    try {
        response = await fetch(
            ebayIdentityEndpoint(config.environment),
            {
                method: 'GET',
                headers: {
                    Accept: 'application/json',
                    Authorization: 'Bearer ' + accessToken,
                },
            },
        );
    } catch {
        throw new Error(
            'KeepFlip could not reach eBay Identity to identify the connected account.',
        );
    }

    let payload = {};

    try {
        payload = JSON.parse(await response.text());
    } catch {
        payload = {};
    }

    if (!response.ok) {
        throw new Error(
            'eBay Identity rejected the connected account lookup.',
        );
    }

    const ebayUserId = cleanText(
        payload?.userId || payload?.userID,
        255,
    );

    if (!ebayUserId) {
        throw new Error(
            'eBay Identity did not return a usable user ID.',
        );
    }

    return {
        userId: ebayUserId,
        username:
            cleanText(
                payload?.username ||
                    payload?.displayName ||
                    ebayUserId,
                255,
            ) || ebayUserId,
    };
}

function tokenBundleFromResponse(
    config,
    tokenResponse,
    previous = null,
) {
    const now = new Date().toISOString();
    const refreshToken =
        tokenResponse.refresh_token ||
        previous?.refreshToken ||
        '';
    const refreshTokenExpiresAt =
        tokenResponse.refresh_token_expires_in
            ? expiryIso(
                  tokenResponse.refresh_token_expires_in,
                  'refresh token expiry',
              )
            : previous?.refreshTokenExpiresAt || '';

    if (!refreshToken || !refreshTokenExpiresAt) {
        throw new Error(
            'eBay did not return the refresh token required for a user connection.',
        );
    }

    return {
        version: 1,
        environment: config.environment,
        accessToken: tokenResponse.access_token,
        accessTokenExpiresAt: expiryIso(
            tokenResponse.expires_in,
            'access token expiry',
        ),
        refreshToken,
        refreshTokenExpiresAt,
        scopeList: config.scopes.join(' '),
        tokenType: String(
            tokenResponse.token_type ||
                previous?.tokenType ||
                'User Access Token',
        ),
        connectedAt: previous?.connectedAt || now,
        updatedAt: now,
    };
}

function readTokenBundle(connection, config) {
    let parsed;

    try {
        parsed = JSON.parse(
            decryptSecret(
                connection?.encryptedTokens,
                config.encryptionKey,
            ),
        );
    } catch {
        throw new Error(
            'Stored eBay token data is unreadable.',
        );
    }

    if (
        !parsed ||
        typeof parsed.accessToken !== 'string' ||
        typeof parsed.refreshToken !== 'string' ||
        typeof parsed.accessTokenExpiresAt !== 'string' ||
        typeof parsed.refreshTokenExpiresAt !== 'string'
    ) {
        throw new Error(
            'Stored eBay token data is incomplete.',
        );
    }

    return parsed;
}

async function saveNewConnection({
    databases,
    config,
    userId,
    tokenResponse,
    ebayIdentity,
}) {
    const tokenBundle = tokenBundleFromResponse(
        config,
        tokenResponse,
    );

    await databases.upsertDocument({
        databaseId:
            config.databaseId,
        collectionId:
            config.connectionsCollectionId,
        documentId:
            connectionDocumentId(
                userId,
                config.environment,
            ),
        data: {
            ownerId: userId,
            hashedEbayId: hashEbayUserId(
                ebayIdentity.userId,
            ),
            encryptedTokens: encryptSecret(
                JSON.stringify(tokenBundle),
                config.encryptionKey,
            ),
            ebayUsername:
                cleanText(
                    ebayIdentity.username ||
                        ebayIdentity.userId,
                    255,
                ) || ebayIdentity.userId,
            revokedAt: null,
            updatedAt: tokenBundle.updatedAt,
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
        if (Number(caught?.code) === 404) {
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
    const storedTokens = readTokenBundle(
        connection,
        config,
    );

    const refreshExpiry = Date.parse(
        storedTokens.refreshTokenExpiresAt || '',
    );

    if (
        !Number.isFinite(refreshExpiry) ||
        refreshExpiry <= Date.now()
    ) {
        throw new HttpError(
            401,
            'Your eBay authorization has expired. Reconnect your eBay account.',
        );
    }

    const tokenResponse = await exchangeRefreshToken(
        config,
        storedTokens.refreshToken,
    );

    const tokenBundle = tokenBundleFromResponse(
        config,
        tokenResponse,
        storedTokens,
    );

    await databases.updateDocument({
        databaseId:
            config.databaseId,
        collectionId:
            config.connectionsCollectionId,
        documentId:
            connection.$id,
        data: {
            encryptedTokens: encryptSecret(
                JSON.stringify(tokenBundle),
                config.encryptionKey,
            ),
            revokedAt: null,
            updatedAt: tokenBundle.updatedAt,
        },
    });

    return {
        accessTokenExpiresAt:
            tokenBundle.accessTokenExpiresAt,
        updatedAt: tokenBundle.updatedAt,
    };
}

function fallbackAppReturnUrl(status) {
    const url =
        new URL(
            requiredEnv('EBAY_APP_RETURN_URL'),
        );

    url.searchParams.set(
        'status',
        status,
    );

    return url.toString();
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

    const environment =
        normalizeEnvironment(
            requestBody(req).environment,
            'OAuth environment',
        );

    // The app owns the pre-generated eBay login URL. This endpoint only
    // issues a signed, one-time state that binds the callback to this user.
    const state =
        createState(
            userId,
            environment,
            stateSecret(),
        );

    return res.json({
        state,
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

    const environment =
        normalizeEnvironment(
            requestBody(req).environment,
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
        connection.revokedAt
    ) {
        return res.json({
            connected: false,
            environment,
        });
    }

    let storedTokens;

    try {
        storedTokens =
            readTokenBundle(
                connection,
                config,
            );
    } catch {
        throw new HttpError(
            500,
            'KeepFlip could not read the stored eBay connection.',
        );
    }

    const accessExpiry =
        Date.parse(
            storedTokens.accessTokenExpiresAt ||
                '',
        );

    const refreshExpiry =
        Date.parse(
            storedTokens.refreshTokenExpiresAt ||
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
            storedTokens.accessTokenExpiresAt,

        refreshTokenExpiresAt:
            storedTokens.refreshTokenExpiresAt,

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

    const environment =
        normalizeEnvironment(
            requestBody(req).environment,
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
        connection.revokedAt
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
    declinedPath,
}) {
    const legacyAuthToken =
        queryValue(
            req,
            'ebaytkn',
        );

    const legacyTokenExpiry =
        queryValue(
            req,
            'tknexp',
        );

    const legacyUsername =
        queryValue(
            req,
            'username',
        );

    if (
        legacyAuthToken ||
        legacyTokenExpiry ||
        legacyUsername
    ) {
        error(
            "eBay returned the legacy Auth'n'Auth callback parameters. " +
                'That flow does not provide an OAuth 2 authorization code or refresh token.',
        );

        return res.redirect(
            fallbackAppReturnUrl('error'),
            302,
        );
    }

    const returnedState =
        queryValue(
            req,
            'state',
        );

    let state;
    let config;

    try {
        state = verifyState(
            returnedState,
            stateSecret(),
        );
        config = loadConfig(state.environment);
    } catch (caught) {
        error(
            `eBay OAuth callback state validation failed: ${caught?.message || String(caught)}`,
        );

        return res.redirect(
            fallbackAppReturnUrl('error'),
            302,
        );
    }

    const authorizationCode =
        queryValue(
            req,
            'code',
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
        declinedPath ||
        providerError ||
        isAuthSuccessful ===
        'false' ||
        !authorizationCode
    ) {
        log(
            `eBay ${config.environment} authorization was declined or returned without a code.`,
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
        const tokenResponse =
            await exchangeAuthorizationCode(
                config,
                authorizationCode,
            );

        const ebayIdentity =
            await getEbayIdentity(
                config,
                tokenResponse.access_token,
            );

        await saveNewConnection({
            databases,
            config,
            userId:
                state.userId,
            tokenResponse,
            ebayIdentity,
        });

        log(
            `eBay ${config.environment} account connected for KeepFlip user ${state.userId}.`,
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
            `eBay ${config.environment} OAuth callback failed: ${caught?.message || String(caught)}`,
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
            (
                path === EBAY_CALLBACK_PATH ||
                path === LEGACY_EBAY_CALLBACK_PATH ||
                path === EBAY_DECLINED_PATH ||
                path === LEGACY_EBAY_DECLINED_PATH
            )
        ) {
            return await handleCallback({
                req,
                res,
                log,
                error,
                databases,
                declinedPath:
                    path === EBAY_DECLINED_PATH ||
                    path === LEGACY_EBAY_DECLINED_PATH,
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