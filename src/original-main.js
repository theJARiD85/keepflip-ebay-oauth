import { Client, Databases, Query } from 'node-appwrite';
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

function opaqueOAuthState(value) {
    if (typeof value !== 'string') {
        throw new HttpError(
            400,
            'The eBay OAuth state is missing or invalid.',
        );
    }

    const state = value.trim();

    if (
        state.length < 32 ||
        state.length > 512 ||
        !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(state)
    ) {        throw new HttpError(
            400,
            'The eBay OAuth state is missing or invalid.',
        );
    }

    return state;
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
        ruName:
            process.env[`${prefix}_RU_NAME`]?.trim() ||
            process.env[`${prefix}_RUNAME`]?.trim() ||
            requiredEnv(`${prefix}_RU_NAME`),

        // The eBay keysets share one approved scope list in Appwrite.
        // Environment selection still controls credentials, RuName, and
        // endpoint; scopes remain the single EBAY_OAUTH_SCOPES variable.
        scopes: scopesFromEnvironmentVariable('EBAY_OAUTH_SCOPES'),

        // These defaults preserve the identifiers used by the original
        // URL-serving ebay_oauth Function while allowing explicit overrides.
        appReturnUrl:
            process.env.EBAY_APP_RETURN_URL?.trim() ||
            'keepflip://ebay/connected',

        databaseId:
            process.env.APPWRITE_EBAY_DATABASE_ID?.trim() ||
            process.env.APPWRITE_DATABASE_ID?.trim() ||
            'keepflip',

        connectionsCollectionId:
            process.env.APPWRITE_EBAY_CONNECTIONS_COLLECTION_ID?.trim() ||
            process.env.APPWRITE_CONNECTIONS_COLLECTION_ID?.trim() ||
            'ebay_connections',

        oauthStatesCollectionId:
            process.env.APPWRITE_EBAY_OAUTH_STATES_COLLECTION_ID?.trim() ||
            process.env.APPWRITE_EBAY_STATES_COLLECTION_ID?.trim() ||
            'ebay_oauth_states',

        encryptionKey: tokenEncryptionKey(),
        stateSecret: stateSecret(),
    };
}

function loadOAuthStateStoreConfig() {
    return {
        databaseId:
            process.env.APPWRITE_EBAY_DATABASE_ID?.trim() ||
            process.env.APPWRITE_DATABASE_ID?.trim() ||
            'keepflip',

        oauthStatesCollectionId:
            process.env.APPWRITE_EBAY_OAUTH_STATES_COLLECTION_ID?.trim() ||
            process.env.APPWRITE_EBAY_STATES_COLLECTION_ID?.trim() ||
            'ebay_oauth_states',
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

function requestHeader(headers, name) {
    if (!headers || typeof headers !== 'object') return '';

    if (typeof headers.get === 'function') {
        const value = headers.get(name);
        if (value) return cleanText(value);
    }

    const expected = name.toLowerCase();

    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() !== expected) continue;
        return cleanText(Array.isArray(value) ? value[0] : value);
    }

    return '';
}

function createAdminDatabases(req) {
    const apiKey =
        requestHeader(req?.headers, 'x-appwrite-key') ||
        cleanText(process.env.APPWRITE_FUNCTION_API_KEY);

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
    // Appwrite custom IDs may not start with "-" or "_". Prefix the
    // deterministic hex digest to make every new connection ID valid.
    return `e${
        createHash('sha256')
            .update(
                `${userId}:${environment}`,
                'utf8',
            )
            .digest('hex')
            .slice(0, 35)
    }`;
}

function legacyConnectionDocumentId(
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

function isAppwriteDocumentId(value) {
    return /^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$/.test(value);
}

function oauthStateDocumentId(state) {
    return createHash('sha256')
        .update(
            `keepflip|ebay-oauth-state|v1|${state}`,
            'utf8',
        )
        .digest('hex')
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
        ? 'https://apiz.ebay.com/commerce/identity/v1/user/'
        : 'https://apiz.sandbox.ebay.com/commerce/identity/v1/user/';
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

    const responseText = await response.text();
    let payload = {};

    try {
        payload = JSON.parse(responseText);
    } catch {
        payload = {};
    }

    if (!response.ok) {
        const firstProviderError =
            Array.isArray(payload?.errors) ? payload.errors[0] : null;
        const providerErrorId = cleanText(
            firstProviderError?.errorId ||
                payload?.errorId ||
                payload?.error,
            80,
        );
        const providerMessage = cleanText(
            firstProviderError?.message ||
                firstProviderError?.longMessage ||
                payload?.error_description ||
                payload?.message,
            300,
        );
        const providerDetail = [
            providerErrorId,
            providerMessage,
        ]
            .filter(Boolean)
            .join(': ');

        throw new Error(
            `eBay Identity rejected the connected account lookup (HTTP ${response}${
                providerDetail ? `: ${providerDetail}` : ''
            }).`,
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
    const tokenCiphertext =
        typeof connection?.tokenCiphertext === 'string' &&
        connection.tokenCiphertext
            ? connection.tokenCiphertext
            : connection?.encryptedTokens;

    try {
        parsed = JSON.parse(
            decryptSecret(
                tokenCiphertext,
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
    const existingConnection =
        await getConnection(
            databases,
            config,
            userId,
        );
    const documentId =
        existingConnection?.$id ||
        connectionDocumentId(
            userId,
            config.environment,
        );

    await databases.upsertDocument({
        databaseId:
            config.databaseId,
        collectionId:
            config.connectionsCollectionId,
        documentId,
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
    const currentDocumentId =
        connectionDocumentId(
            userId,
            config.environment,
        );
    const legacyDocumentId =
        legacyConnectionDocumentId(
            userId,
            config.environment,
        );
    const documentIds = [
        currentDocumentId,
    ];

    if (
        legacyDocumentId !== currentDocumentId &&
        isAppwriteDocumentId(legacyDocumentId)
    ) {
        documentIds.push(legacyDocumentId);
    }

    for (const documentId of documentIds) {
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
                continue;
            }

            throw caught;
        }
    }

    return null;
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
            process.env.EBAY_APP_RETURN_URL?.trim() ||
                'keepflip://ebay/connected',
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
    state,
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

    if (state) {
        url.searchParams.set(
            'state',
            state,
        );
    }

    return url.toString();
}

async function readOAuthStateRecord({
    databases,
    state,
}) {
    const stateStore =
        loadOAuthStateStoreConfig();
    const documentId =
        oauthStateDocumentId(state);

    let record;

    try {
        record =
            await databases.getDocument({
                databaseId:
                    stateStore.databaseId,
                collectionId:
                    stateStore.oauthStatesCollectionId,
                documentId,
            });
    } catch (caught) {
        if (Number(caught?.code) === 404) {
            throw new HttpError(
                400,
                'The eBay OAuth state is missing or invalid.',
            );
        }

        throw new Error(
            'KeepFlip could not read the eBay OAuth state.',
        );
    }

    const userId =
        cleanText(record?.ownerId, 128);

    if (!userId) {
        throw new HttpError(
            400,
            'The eBay OAuth state is missing or invalid.',
        );
    }

    return {
        environment:
            normalizeEnvironment(
                record?.environment,
                'stored OAuth environment',
            ),
        userId,
    };
}

async function claimOAuthState({
    databases,
    config,
    state,
    payload,
}) {
    const documentId =
        oauthStateDocumentId(state);

    let record;

    try {
        record =
            await databases.getDocument({
                databaseId:
                    config.databaseId,
                collectionId:
                    config.oauthStatesCollectionId,
                documentId,
            });
    } catch (caught) {
        if (Number(caught?.code) === 404) {
            throw new HttpError(
                400,
                'The eBay OAuth state is missing or invalid.',
            );
        }

        throw new Error(
            'KeepFlip could not read the eBay OAuth state.',
        );
    }

    const expiresAt =
        Date.parse(
            String(record?.expiresAt || ''),
        );

    if (
        record?.ownerId !== payload.userId ||
        record?.environment !== payload.environment ||
        record?.status !== 'pending' ||
        !Number.isFinite(expiresAt) ||
        expiresAt <= Date.now()
    ) {
        throw new HttpError(
            400,
            'The eBay OAuth state has expired, was already used, or does not match this callback.',
        );
    }

    const claimedAt =
        new Date().toISOString();

    let updateResponse;

    try {
        updateResponse =
            await databases.updateDocuments({
                databaseId:
                    config.databaseId,
                collectionId:
                    config.oauthStatesCollectionId,
                queries: [
                    Query.equal(
                        '$id',
                        documentId,
                    ),
                    Query.equal(
                        'status',
                        'pending',
                    ),
                ],
                data: {
                    status: 'processing',
                    claimedAt,
                },
            });
    } catch {
        throw new Error(
            'KeepFlip could not claim the eBay OAuth state.',
        );
    }

    const updatedCount =
        Number(
            updateResponse?.total ??
                updateResponse?.documents?.length ??
                0,
        );

    if (updatedCount < 1) {
        throw new HttpError(
            400,
            'The eBay OAuth state has expired, was already used, or does not match this callback.',
        );
    }

    return {
        documentId,
        claimedAt,
    };
}

async function markOAuthState({
    databases,
    config,
    documentId,
    status,
    failureCode,
}) {
    const data = {
        status,
        completedAt:
            new Date().toISOString(),
    };

    if (failureCode) {
        data.failureCode = failureCode;
    }

    try {
        await databases.updateDocument({
            databaseId:
                config.databaseId,
            collectionId:
                config.oauthStatesCollectionId,
            documentId,
            data,
        });
        return true;
    } catch {
        return false;
    }
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

    const rawReturnedState =
        queryValue(
            req,
            'state',
        );

    const stateFormat =
        rawReturnedState.length === 0
            ? 'missing'
            : 'opaque';

    log(
        `eBay OAuth callback state received: ${stateFormat}; ` +
            `length=${rawReturnedState.length}.`,
    );

    let state;
    let config;
    let stateDocumentId;
    let stateClaimed = false;
    let returnedState;

    try {
        returnedState = opaqueOAuthState(
            rawReturnedState,
        );
        const storedState =
            await readOAuthStateRecord({
                databases,
                state: returnedState,
            });
        state = {
            environment: storedState.environment,
            userId: storedState.userId,
        };
        config = loadConfig(state.environment);

        const claim =
            await claimOAuthState({
                databases,
                config,
                state: returnedState,
                payload: state,
            });

        stateDocumentId = claim.documentId;
        stateClaimed = true;
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

        const marked =
            await markOAuthState({
                databases,
                config,
                documentId: stateDocumentId,
                status: 'declined',
            });

        if (!marked) {
            error(
                'eBay OAuth state could not be marked declined.',
            );
        }

        return res.redirect(
            appReturnUrl(
                config,
                'declined',
                returnedState,
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

        const marked =
            await markOAuthState({
                databases,
                config,
                documentId: stateDocumentId,
                status: 'completed',
            });

        if (!marked) {
            error(
                'eBay OAuth state could not be marked completed.',
            );
        }

        log(
            `eBay ${config.environment} account connected for KeepFlip user ${state.userId}.`,
        );

        return res.redirect(
            appReturnUrl(
                config,
                'connected',
                returnedState,
            ),
            302,
        );
    } catch (caught) {
        if (stateClaimed) {
            const marked =
                await markOAuthState({
                    databases,
                    config,
                    documentId: stateDocumentId,
                    status: 'failed',
                    failureCode: 'CALLBACK_FAILED',
                });

            if (!marked) {
                error(
                    'eBay OAuth state could not be marked failed.',
                );
            }
        }

        error(
            `eBay ${config.environment} OAuth callback failed: ${caught?.message || String(caught)}`,
        );

        return res.redirect(
            appReturnUrl(
                config,
                'error',
                returnedState,
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
                    'KeepFlip eBay OAuth callback',
                flow:
                    'authorization_code',
                routes: [
                    EBAY_CALLBACK_PATH,
                    EBAY_DECLINED_PATH,
                ],
            });
        }

        if (
            req.method !== 'GET' ||
            (
                path !== EBAY_CALLBACK_PATH &&
                path !== EBAY_DECLINED_PATH
            )
        ) {
            return res.json(
                {
                    error: 'Endpoint not found.',
                },
                404,
            );
        }

        const callbackRequest =
            req.method === 'GET' &&
            (
                path === EBAY_CALLBACK_PATH ||
                path === EBAY_DECLINED_PATH
            );

        const hasLegacyAuthCallbackParameters =
            callbackRequest &&
            (
                queryValue(req, 'ebaytkn') ||
                queryValue(req, 'tknexp') ||
                queryValue(req, 'username')
            );

        if (hasLegacyAuthCallbackParameters) {
            error(
                "eBay returned the legacy Auth'n'Auth callback parameters. " +
                    'That flow does not provide an OAuth 2 authorization code or refresh token.',
            );

            return res.json(
                {
                    error:
                        "eBay returned legacy Auth'n'Auth parameters. " +
                        'Restart the OAuth 2 authorization-code flow so eBay returns code and state.',
                },
                400,
            );
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
                path === EBAY_DECLINED_PATH
            )
        ) {
            return await handleCallback({
                req,
                res,
                log,
                error,
                databases,
                declinedPath:
                    path === EBAY_DECLINED_PATH,
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