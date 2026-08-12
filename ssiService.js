const { SSI_BASE_URL, KYC_BASE_URL, X_ISSUER_VERMETHOD_ID, X_ISSUER_DID } = require('./config')

/**
 * Registers a new Decentralized Identifier (DID) for a user via the SSI Service.
 * * This function creates a DID on the network and extracts a specific 
 * Verification Method ID (Ed25519) required for future cryptographic signatures.
 * * @async
 * @function registerUserDid
 * @param {string} ssiAdminToken - The administrative access token for the SSI service.
 * @param {string} [namespace=''] - The optional namespace for the DID (defaults to empty).
 * @returns {Promise<{did: string, verificationMethodId: string}>} The generated DID and its specific Ed25519 method ID.
 * @throws {Error} Throws if DID creation fails or the required verification method is not found.
 */
async function registerUserDid(ssiAdminToken, namespace = '') {
    const url = `${SSI_BASE_URL}/api/v1/did/create`;

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${ssiAdminToken}`
            },
            body: JSON.stringify({ namespace })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`SSI DID Creation failed [${response.status}]: ${errorText}`);
        }

        const result = await response.json();

        // Navigate the metadata to find the specific Ed25519 verification method
        const verificationMethods = result.metaData?.didDocument?.verificationMethod || [];
        const targetMethod = verificationMethods.find(m => m.type === 'Ed25519VerificationKey2020');

        if (!targetMethod) {
            throw new Error("Invalid DID Document: Ed25519VerificationKey2020 method not found.");
        }

        return {
            did: result.did,
            verificationMethodId: targetMethod.id
        };

    } catch (error) {
        console.error(`[DID Registration Error]: ${error.message}`);
        throw error;
    }
}

/**
 * STEP 1: Signs user claims using the Issuer's DID to create a verifiable JWT.
 */
async function requestDidJwtSignature(claims, ssiAdminToken) {
    const response = await fetch(`${SSI_BASE_URL}/api/v1/did/auth/issue-jwt`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${ssiAdminToken}`,
        },
        body: JSON.stringify({
            issuer: {
                verificationMethodId: X_ISSUER_VERMETHOD_ID,
                did: X_ISSUER_DID
            },
            audience: KYC_BASE_URL,
            claims: claims,
            ttlSeconds: 3600
        })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`DID JWT Issuance failed: ${response.status} - ${errorText}`);
    }

    const result = await response.json();
    return result.accessToken;
}



module.exports = { registerUserDid, requestDidJwtSignature }