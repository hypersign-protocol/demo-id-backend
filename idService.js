const { KYC_BASE_URL } = require('./config')

/**
 * Initializes a new KYC verification session and retrieves a unique Session ID.
 * * This is typically the first step in the KYC process, creating a context 
 * for the subsequent document and identity verification steps.
 * * @async
 * @function initializeVerificationSession
 * @param {string} kycAdminToken - The administrative access token for the KYC service.
 * @returns {Promise<string>} A promise that resolves to the unique sessionId.
 * @throws {Error} Throws an error if the request fails or the response format is invalid.
 */
async function initializeVerificationSession(kycAdminToken) {
    try {
        const response = await fetch(`${KYC_BASE_URL}/api/v2/session`, {
            method: 'POST',
            headers: {
                'x-kyc-access-token': kycAdminToken,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to start KYC session: ${response.status} - ${errorText}`);
        }

        const result = await response.json();

        // Validate that the nested sessionId exists in the data object
        if (!result.data || !result.data.sessionId) {
            throw new Error("Invalid response format: 'sessionId' is missing from response data.");
        }

        return result.data.sessionId;

    } catch (error) {
        console.error(`[Session Initialization Error]: ${error.message}`);
        throw error;
    }
}

/**
 * Exchanges a DID-signed JWT for a specific KYC Service User Access Token.
 * * This function performs the final step of the authentication handshake by submitting 
 * the proof-of-identity (DID JWT) along with administrative credentials to the KYC 
 * service to establish a verified user session.
 * * @async
 * @function exchangeJwtForKycAccessToken
 * @param {string} didJwt - The JWT signed by the issuer's DID, acting as the primary authorization bearer.
 * @param {string} kycAdminToken - The administrative access token for the KYC service (X-KYC-Access-Token).
 * @param {string} ssiAdminToken - The administrative access token for the SSI service (X-SSI-Access-Token).
 * @param {string} sessionId - A unique identifier for the current verification session.
 * * @throws {Error} Throws an error if the HTTP response is not OK (e.g., 401 Unauthorized or 400 Bad Request).
 * @throws {Error} Throws an error if the API response structure is missing the expected `kycServiceUserAccessToken`.
 * * @returns {Promise<string>} A promise that resolves to the `kycServiceUserAccessToken` string.
 */
async function exchangeJwtForKycAccessToken(didJwt, kycAdminToken, ssiAdminToken, sessionId) {
    const response = await fetch(`${KYC_BASE_URL}/api/v2/auth/exchange`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "x-ssi-access-token": ssiAdminToken,
            "x-kyc-access-token": kycAdminToken,
            "Authorization": `Bearer ${didJwt}`,
        },
        body: JSON.stringify({
            provider: "client_auth",
            sessionId
        })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`KYC Auth Exchange failed: ${response.status} - ${errorText}`);
    }

    const result = await response.json();

    // Ensure the nested structure matches your API response
    if (!result.data || !result.data.kycServiceUserAccessToken) {
        throw new Error("Invalid response format: kycServiceUserAccessToken missing.");
    }

    return result.data.kycServiceUserAccessToken;
}

module.exports = {
    initializeVerificationSession,
    exchangeJwtForKycAccessToken
}