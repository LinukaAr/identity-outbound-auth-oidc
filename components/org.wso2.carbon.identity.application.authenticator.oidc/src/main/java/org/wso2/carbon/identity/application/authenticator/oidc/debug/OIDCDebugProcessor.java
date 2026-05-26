/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.OAuth2TokenClient;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.TokenResponse;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCConfiguration;
import org.wso2.carbon.identity.application.common.model.AccountLookupAttributeMappingConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugProcessor;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OIDC-specific implementation of IdpDebugProcessor.
 * Handles the OIDC authorization code callback: validates the callback parameters, exchanges the code for tokens,
 * extracts and maps claims, evaluates account linking, and persists the debug result.
 */
public class OIDCDebugProcessor extends IdpDebugProcessor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugProcessor.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Override
    protected boolean validateCallback(HttpServletRequest request, DebugContext context,
            HttpServletResponse response, String state, String resourceIdentifier) throws IOException {

        String code = request.getParameter(OIDCDebugConstants.OIDC_CODE_PARAM);
        String error = request.getParameter(OIDCDebugConstants.OIDC_ERROR_PARAM);
        String errorDescription = request.getParameter(OIDCDebugConstants.OIDC_ERROR_DESCRIPTION_PARAM);

        if (StringUtils.isNotEmpty(resourceIdentifier)) {
            context.setProperty(OIDCDebugConstants.DEBUG_IDP_NAME, resourceIdentifier);
        }

        if (error != null) {
            LOG.error("OIDC error from IdP: " + error + " - " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, error + ": " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheErrorResponse(error, errorDescription, state, context);
            return false;
        }

        if (StringUtils.isBlank(code)) {
            LOG.error("Authorization code missing in OIDC callback");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Authorization code not received");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheErrorResponse("NO_CODE", "Authorization code not received from IdP", state, context);
            return false;
        }

        if (StringUtils.isBlank(state)) {
            LOG.error("State parameter missing in OIDC callback");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR,
                    "State parameter missing - possible CSRF attack");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheErrorResponse("NO_STATE", "State parameter missing - possible CSRF attack", state, context);
            return false;
        }

        String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
        if (debugId == null || !state.trim().equals(debugId)) {
            LOG.error("State parameter mismatch - CSRF attack detected");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR,
                    "State validation failed - possible CSRF attack");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheErrorResponse("STATE_MISMATCH", "State validation failed - possible CSRF attack",
                    state, context);
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("OIDC callback validation passed for state: " + state);
        }
        return true;
    }

    @Override
    protected boolean processAuthentication(HttpServletRequest request, DebugContext context,
            HttpServletResponse response, String state, String resourceIdentifier) throws IOException {

        String code = request.getParameter(OIDCDebugConstants.OIDC_CODE_PARAM);
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_STARTED, "Starting OIDC token exchange.");

        try {
            IdentityProvider idp = resolveIdentityProvider(context, state);
            if (idp == null) {
                LOG.error("IdP configuration not found in context");
                DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                        OIDCDebugConstants.STATUS_FAILED, "Identity Provider configuration was not found.");
                buildAndCacheErrorResponse("IDP_CONFIG_MISSING",
                        "Identity Provider configuration not found", state, context);
                context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
                return false;
            }

            context.setProperty(OIDCDebugConstants.DEBUG_IDP_NAME, idp.getIdentityProviderName());
            context.setProperty(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID, idp.getResourceId());
            context.setProperty(OIDCDebugConstants.IDP_CONFIG, idp);

            OIDCConfiguration config = extractOIDCConfiguration(context, idp);
            if (!config.isValid()) {
                LOG.error("Token exchange failed: OIDC configuration is invalid");
                handleConfigurationError(config, state, context);
                return false;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Starting token exchange with IdP: " + config.getIdpName() +
                        ", Token Endpoint: " + config.getTokenEndpoint());
            }

            TokenResponse tokenResponse = new OAuth2TokenClient().exchangeCodeForTokens(
                    code, config.getTokenEndpoint(), config.getClientId(), config.getClientSecret(),
                    config.getCallbackUrl(), config.getCodeVerifier(), config.getIdpName());

            if (tokenResponse.hasError()) {
                String errorCode = tokenResponse.getErrorCode();
                String errorDesc = tokenResponse.getErrorDescription();
                DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                        OIDCDebugConstants.STATUS_FAILED, "Failed to obtain tokens",
                        buildErrorDetails(errorCode, errorDesc));
                context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, errorDesc);
                context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
                buildAndCacheErrorResponse(errorCode, errorDesc, state, context);
                return false;
            }

            context.setProperty(OIDCDebugConstants.ACCESS_TOKEN, tokenResponse.getAccessToken());
            if (StringUtils.isNotBlank(tokenResponse.getIdToken())) {
                context.setProperty(OIDCDebugConstants.ID_TOKEN, tokenResponse.getIdToken());
            }
            if (StringUtils.isNotBlank(tokenResponse.getTokenType())) {
                context.setProperty(OIDCDebugConstants.TOKEN_TYPE, tokenResponse.getTokenType());
            }
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_SUCCESS, "Token received successfully.");
            return true;

        } catch (RuntimeException e) {
            // OAuth2TokenClient encapsulates token-exchange errors in TokenResponse;
            // anything reaching here is a runtime fault (NPE on missing config, etc).
            LOG.error("Unexpected error during OIDC token exchange: " + e.getMessage(), e);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "OIDC token exchange failed with an exception.",
                    buildErrorDetails("TOKEN_EXCHANGE_ERROR", e.getMessage()));
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Token exchange error: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheErrorResponse("TOKEN_EXCHANGE_ERROR",
                    "Token exchange error: " + e.getMessage(), state, context);
            return false;
        }
    }

    /**
     * Resolves the IdP for this debug session using a two-step strategy:
     * 1. Direct IDP_CONFIG in context (fastest path).
     * 2. Re-resolve from stored resource ID or name via IdentityProviderManager.
     * Step 2 is needed because the OIDC callback arrives in a new request with no in-memory IdP object.
     */
    private IdentityProvider resolveIdentityProvider(DebugContext context, String state) {

        Object cachedIdp = context.getProperty(OIDCDebugConstants.IDP_CONFIG);
        if (cachedIdp instanceof IdentityProvider) {
            return (IdentityProvider) cachedIdp;
        }

        if (state != null) {
            restoreContextFromSessionCache(state, context);
            cachedIdp = context.getProperty(OIDCDebugConstants.IDP_CONFIG);
            if (cachedIdp instanceof IdentityProvider) {
                return (IdentityProvider) cachedIdp;
            }
        }

        return resolveIdpFromContext(context, state);
    }

    /**
     * Resolves the IdP from stored context properties.
     * Tries resource ID first (more stable), then falls back to name lookup.
     */
    private IdentityProvider resolveIdpFromContext(DebugContext context, String state) {

        try {
            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
            String resourceId = (String) context.getProperty(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID);
            String idpName = (String) context.getProperty(OIDCDebugConstants.DEBUG_IDP_NAME);

            if (StringUtils.isEmpty(resourceId) && StringUtils.isEmpty(idpName)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("IdP identifier not found in context for state: " + state);
                }
                return null;
            }

            IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
            IdentityProvider idp = null;
            if (StringUtils.isNotEmpty(resourceId)) {
                idp = idpManager.getIdPByResourceId(resourceId, tenantDomain, true);
            }
            if (idp == null && StringUtils.isNotEmpty(idpName)) {
                idp = idpManager.getIdPByName(idpName, tenantDomain, true);
            }

            if (idp != null) {
                context.setProperty(OIDCDebugConstants.IDP_CONFIG, idp);
                context.setProperty(OIDCDebugConstants.DEBUG_IDP_NAME, idp.getIdentityProviderName());
                context.setProperty(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID, idp.getResourceId());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Resolved IdP from context cache for state: " + state + ", IdP: "
                            + idp.getIdentityProviderName());
                }
            } else if (LOG.isDebugEnabled()) {
                LOG.debug("Could not resolve IdP by name: " + idpName);
            }

            return idp;

        } catch (IdentityProviderManagementException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error resolving IdP from context: " + e.getMessage(), e);
            }
            return null;
        }
    }

    /**
     * Extracts OIDC configuration from context first, falling back to the IdP authenticator config
     * if any required value is missing. Context values take priority because they may have been
     * overridden at session-start time (e.g. PKCE code verifier).
     */
    private OIDCConfiguration extractOIDCConfiguration(DebugContext context, IdentityProvider idp) {

        OIDCConfiguration config = new OIDCConfiguration();
        config.setIdpName(idp.getIdentityProviderName());
        config.setCodeVerifier((String) context.getProperty(OIDCDebugConstants.DEBUG_CODE_VERIFIER));
        config.setTokenEndpoint((String) context.getProperty(OIDCDebugConstants.TOKEN_ENDPOINT));
        config.setClientId((String) context.getProperty(OIDCDebugConstants.CLIENT_ID));
        config.setClientSecret((String) context.getProperty(OIDCDebugConstants.CLIENT_SECRET));

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange - from context: tokenEndpoint=" +
                    (config.getTokenEndpoint() != null ? OIDCDebugConstants.STATUS_FOUND : "null") +
                    ", clientId=" + (config.getClientId() != null ? OIDCDebugConstants.STATUS_FOUND : "null") +
                    ", clientSecret="
                    + (config.getClientSecret() != null ? OIDCDebugConstants.STATUS_FOUND : "null"));
        }

        if ((!config.hasRequiredEndpoints() || StringUtils.isBlank(config.getClientSecret()))
                && idp.getFederatedAuthenticatorConfigs() != null) {
            extractFromIdPConfig(idp, config);
        }

        // The debug flow always uses the server's /commonauth endpoint as the redirect URI,
        // matching the authorization URL built by OIDCDebugExecutor.
        config.setCallbackUrl(IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true));

        return config;
    }

    private void extractFromIdPConfig(IdentityProvider idp, OIDCConfiguration config) {

        for (FederatedAuthenticatorConfig authConfig : idp.getFederatedAuthenticatorConfigs()) {
            if (authConfig == null || authConfig.getProperties() == null) {
                continue;
            }
            for (Property prop : authConfig.getProperties()) {
                if (prop == null || prop.getName() == null || prop.getValue() == null) {
                    continue;
                }
                if (OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL.equals(prop.getName())
                        && StringUtils.isNotEmpty(prop.getValue())) {
                    config.setTokenEndpoint(prop.getValue());
                } else if (OIDCAuthenticatorConstants.CLIENT_ID.equals(prop.getName())
                        && StringUtils.isNotEmpty(prop.getValue())) {
                    config.setClientId(prop.getValue());
                } else if (OIDCAuthenticatorConstants.CLIENT_SECRET.equals(prop.getName())
                        && StringUtils.isNotEmpty(prop.getValue())) {
                    config.setClientSecret(prop.getValue());
                }
            }
            if (config.hasRequiredEndpoints()) {
                break;
            }
        }
    }

    private void handleConfigurationError(OIDCConfiguration config, String state, DebugContext context) {

        boolean missingEndpoint = StringUtils.isBlank(config.getTokenEndpoint());
        boolean missingClientId = StringUtils.isBlank(config.getClientId());

        String errorCode;
        String errorDescription;
        if (missingEndpoint && missingClientId) {
            errorCode = "CONFIG_MISSING";
            errorDescription = "Token endpoint and client ID are not configured for the IdP.";
        } else if (missingEndpoint) {
            errorCode = "TOKEN_ENDPOINT_MISSING";
            errorDescription = "Token endpoint is not configured for the IdP.";
        } else {
            errorCode = "CLIENT_ID_MISSING";
            errorDescription = "Client ID is not configured for the IdP.";
        }
        LOG.error("Token exchange configuration error: " + errorDescription);
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_FAILED, errorDescription);
        buildAndCacheErrorResponse(errorCode, errorDescription, state, context);
    }

    @Override
    protected Map<String, Object> extractDebugData(DebugContext context) {

        try {
            String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
            if (StringUtils.isBlank(idToken)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No ID token available for claim extraction");
                }
                DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                        OIDCDebugConstants.STATUS_FAILED, "ID token is not available for claim extraction.");
                return new HashMap<>();
            }

            Map<String, Object> claims = parseIdTokenClaims(idToken);

            if (!isValidNonceClaim(context, claims)) {
                DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                        OIDCDebugConstants.STATUS_FAILED,
                        "ID token nonce claim validation failed.",
                        buildErrorDetails("NONCE_VALIDATION_FAILED",
                                "ID token nonce claim is missing or does not match the original request nonce."));
                return new HashMap<>();
            }

            if (claims.isEmpty()) {
                DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                        OIDCDebugConstants.STATUS_FAILED, "No claims could be extracted from the OIDC tokens.");
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No claims extracted from ID token");
                }
                return new HashMap<>();
            }

            context.setProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS, claims);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                    OIDCDebugConstants.STATUS_SUCCESS, "Claims extracted successfully from tokens.");
            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully extracted " + claims.size() + " claims from tokens: " + claims.keySet());
            }
            return claims;

        } catch (RuntimeException e) {
            LOG.error("Error extracting user claims from OIDC tokens: " + e.getMessage(), e);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                    OIDCDebugConstants.STATUS_FAILED, "Error extracting claims from OIDC tokens.",
                    buildErrorDetails("CLAIM_EXTRACTION_ERROR", e.getMessage()));
            return new HashMap<>();
        }
    }

    private Map<String, Object> parseIdTokenClaims(String idToken) {

        try {
            String[] parts = idToken.split("\\.");
            if (parts.length != 3) {
                LOG.error("Invalid ID token format - expected 3 parts, got " + parts.length);
                return new HashMap<>();
            }
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = OBJECT_MAPPER.readValue(payload, Map.class);
            return claims != null ? claims : new HashMap<>();
        } catch (IllegalArgumentException | IOException e) {
            LOG.error("Error parsing ID token claims: " + e.getMessage(), e);
            return new HashMap<>();
        }
    }

    private boolean isValidNonceClaim(DebugContext context, Map<String, Object> claims) {

        String expectedNonce = (String) context.getProperty(OIDCDebugConstants.DEBUG_NONCE);
        if (StringUtils.isBlank(expectedNonce)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Expected nonce is not available in debug context. Skipping nonce validation.");
            }
            return true;
        }

        Object tokenNonceObj = claims.get(OIDCDebugConstants.CLAIM_NONCE);
        String tokenNonce = tokenNonceObj != null ? String.valueOf(tokenNonceObj) : null;
        if (StringUtils.isBlank(tokenNonce)) {
            LOG.error("ID token nonce claim is missing while request nonce is present.");
            return false;
        }

        if (!StringUtils.equals(expectedNonce, tokenNonce)) {
            LOG.error("Nonce mismatch detected between request context and ID token claims.");
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("ID token nonce claim validation succeeded.");
        }
        return true;
    }

    @Override
    protected boolean validateDebugData(Map<String, Object> claims, DebugContext context,
            HttpServletResponse response, String state, String resourceIdentifier) throws IOException {

        if (claims == null || claims.isEmpty()) {
            LOG.error("No claims extracted from OIDC tokens");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "No user claims extracted from IdP");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheErrorResponse("NO_CLAIMS", "No user claims available from IdP", state, context);
            return false;
        }

        boolean hasUserIdentifier = claims.containsKey(OIDCDebugConstants.CLAIM_SUB)
                || claims.containsKey(OIDCDebugConstants.CLAIM_USER_ID)
                || claims.containsKey(OIDCDebugConstants.CLAIM_USER_ID_ALT)
                || claims.containsKey(OIDCDebugConstants.CLAIM_EMAIL);
        if (!hasUserIdentifier) {
            LOG.error("Required user identifier claim not found in extracted claims");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "User identifier claim missing");
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            buildAndCacheErrorResponse("NO_USER_IDENTIFIER",
                    "User identifier (sub/user_id/email) not found in claims", state, context);
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Claims extraction validation passed. Claims found: " + claims.keySet());
        }
        return true;
    }

    @Override
    protected void buildAndCacheDebugResult(DebugContext context, String state) {

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> rawClaims = (Map<String, Object>) context
                    .getProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS);
            Map<String, Object> normalizedClaims = normalizeIncomingClaims(
                    rawClaims != null ? rawClaims : new HashMap<>());

            // Resolve the IdP once and reuse it across claim mapping and account linking.
            IdentityProvider idp = resolveIdentityProvider(context, null);

            Map<String, Object> debugResult = new HashMap<>();
            processClaimMappings(context, idp, normalizedClaims, debugResult);
            evaluateAccountLinking(context, idp, normalizedClaims);
            buildResultMetadata(debugResult, context);
            persistDebugResult(state, context, debugResult);

        } catch (RuntimeException e) {
            LOG.error("Error building and caching debug result: " + e.getMessage(), e);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Error caching debug result: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
        }
    }

    private void processClaimMappings(DebugContext context, IdentityProvider idp,
            Map<String, Object> incomingClaims, Map<String, Object> debugResult) {

        // Map keyed by remoteClaimUri -> localClaimUri.
        Map<String, String> idpClaimMappings = extractIdPClaimMappings(idp);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Building mapped claims array from " + idpClaimMappings.size() +
                    " configured mappings. Incoming claims: " +
                    (incomingClaims.isEmpty() ? "none" : incomingClaims.keySet()));
        }

        List<Map<String, Object>> mappedClaimsArray = buildMappedClaimsArray(idpClaimMappings, incomingClaims);
        debugResult.put(OIDCDebugConstants.RESULT_MAPPED_CLAIMS, mappedClaimsArray);

        // SUCCESS if all mappings resolved, PARTIAL if any remain unmapped.
        String claimMappingStatus = determineClaimMappingStatus(mappedClaimsArray, idpClaimMappings);
        String statusMessage = OIDCDebugConstants.STATUS_PARTIAL.equals(claimMappingStatus)
                ? "Claim mappings are partially successful."
                : "Claim mapping processing successful.";
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_MAPPING, claimMappingStatus,
                statusMessage, buildClaimMappingDiagnosticDetails(claimMappingStatus, mappedClaimsArray));
    }

    /**
     * Builds diagnostic details for a PARTIAL claim mapping result.
     * Returns an empty map for SUCCESS — no extra detail needed in that case.
     * Only reports the first unmapped claim; subsequent ones can be fixed iteratively.
     */
    private Map<String, Object> buildClaimMappingDiagnosticDetails(String claimMappingStatus,
            List<Map<String, Object>> mappedClaimsArray) {

        if (!OIDCDebugConstants.STATUS_PARTIAL.equals(claimMappingStatus)) {
            return new LinkedHashMap<>();
        }

        for (Map<String, Object> claim : mappedClaimsArray) {
            if (!OIDCDebugConstants.CLAIM_STATUS_NOT_MAPPED.equals(claim.get(OIDCDebugConstants.CLAIM_MAPPING_STATUS))) {
                continue;
            }
            String idpClaim = objectToString(claim.get(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM));
            String localClaim = objectToString(claim.get(OIDCDebugConstants.CLAIM_MAPPING_LOCAL_CLAIM));

            Map<String, Object> details = new LinkedHashMap<>();
            details.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION,
                    buildUnmappedClaimErrorDescription(idpClaim, localClaim));
            return details;
        }

        return new LinkedHashMap<>();
    }

    private String buildUnmappedClaimErrorDescription(String unmappedIdpClaim, String unmappedLocalClaim) {

        if (StringUtils.isNotBlank(unmappedIdpClaim) && StringUtils.isNotBlank(unmappedLocalClaim)) {
            return "The IdP claim '" + unmappedIdpClaim + "' is not mapped to the IS local claim '" +
                    unmappedLocalClaim + "'.";
        }
        if (StringUtils.isNotBlank(unmappedIdpClaim)) {
            return "The IdP claim '" + unmappedIdpClaim + "' is not mapped to an IS local claim.";
        }
        if (StringUtils.isNotBlank(unmappedLocalClaim)) {
            return "The IS local claim '" + unmappedLocalClaim + "' does not have a mapped IdP claim.";
        }
        return "Couldn't map one or more IdP claims to local claims. Please review claim mappings.";
    }

    /**
     * Returns SUCCESS if all configured mappings resolved, PARTIAL if any are missing.
     * Returns SUCCESS immediately when there are no configured mappings (nothing to fail).
     */
    private String determineClaimMappingStatus(List<Map<String, Object>> mappedClaimsArray,
            Map<String, String> idpClaimMappings) {

        if (idpClaimMappings.isEmpty()) {
            return OIDCDebugConstants.STATUS_SUCCESS;
        }

        for (Map<String, Object> claim : mappedClaimsArray) {
            if (OIDCDebugConstants.CLAIM_STATUS_NOT_MAPPED.equals(claim.get(OIDCDebugConstants.CLAIM_MAPPING_STATUS))) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Claim mapping status: PARTIAL.");
                }
                return OIDCDebugConstants.STATUS_PARTIAL;
            }
        }
        return OIDCDebugConstants.STATUS_SUCCESS;
    }

    private List<Map<String, Object>> buildMappedClaimsArray(
            Map<String, String> idpClaimMappings, Map<String, Object> incomingClaims) {

        List<Map<String, Object>> mappedClaimsArray = new ArrayList<>();
        for (Map.Entry<String, String> mapping : idpClaimMappings.entrySet()) {
            String remoteClaimUri = mapping.getKey();
            String localClaimUri = mapping.getValue();

            Map<String, Object> claimEntry = new HashMap<>();
            claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM, remoteClaimUri);
            claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_LOCAL_CLAIM,
                    localClaimUri != null ? localClaimUri : "");

            if (incomingClaims.containsKey(remoteClaimUri)) {
                claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_VALUE,
                        incomingClaims.get(remoteClaimUri).toString());
                claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_STATUS, OIDCDebugConstants.CLAIM_STATUS_SUCCESSFUL);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Mapped claim: " + remoteClaimUri + " -> " + localClaimUri);
                }
            } else {
                claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_VALUE, null);
                claimEntry.put(OIDCDebugConstants.CLAIM_MAPPING_STATUS, OIDCDebugConstants.CLAIM_STATUS_NOT_MAPPED);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Claim not found in incoming claims: " + remoteClaimUri);
                }
            }
            mappedClaimsArray.add(claimEntry);
        }
        return mappedClaimsArray;
    }

    private void buildResultMetadata(Map<String, Object> debugResult, DebugContext context) {

        String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
        if (StringUtils.isNotBlank(externalRedirectUrl)) {
            debugResult.put(OIDCDebugConstants.RESULT_EXTERNAL_REDIRECT_URL, externalRedirectUrl);
        }

        String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
        if (StringUtils.isNotBlank(idToken)) {
            debugResult.put(OIDCDebugConstants.ID_TOKEN, idToken);
        }

        debugResult.put(OIDCDebugConstants.DEBUG_DIAGNOSTICS,
                transformDiagnostics(DebugDiagnosticsUtil.getDiagnostics(context)));
    }

    private void persistDebugResult(String state, DebugContext context, Map<String, Object> debugResult) {

        String debugResultJson;
        try {
            debugResultJson = OBJECT_MAPPER.writeValueAsString(debugResult);
        } catch (JsonProcessingException e) {
            LOG.error("Failed to serialize debug result to JSON: " + e.getMessage(), e);
            return;
        }

        context.setProperty(OIDCDebugConstants.DEBUG_RESULT_CACHE_KEY, debugResultJson);
        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, true);
        String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
        persistJsonToSessionStore(debugId, state, debugResultJson);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Debug result cached and persisted for debugId: " + debugId);
        }
    }

    private Map<String, String> extractIdPClaimMappings(IdentityProvider idp) {

        Map<String, String> mappings = new HashMap<>();
        if (idp == null || idp.getClaimConfig() == null || idp.getClaimConfig().getClaimMappings() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No claim configuration found in IdP");
            }
            return mappings;
        }

        for (ClaimMapping claimMapping : idp.getClaimConfig().getClaimMappings()) {
            if (claimMapping == null || claimMapping.getRemoteClaim() == null
                    || claimMapping.getLocalClaim() == null) {
                continue;
            }
            String remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();
            if (StringUtils.isBlank(remoteClaimUri)) {
                LOG.warn("Skipping claim mapping with blank remote claim URI");
                continue;
            }
            mappings.put(remoteClaimUri, claimMapping.getLocalClaim().getClaimUri());

            if (LOG.isDebugEnabled()) {
                LOG.debug("Extracted claim mapping: " + remoteClaimUri + " -> "
                        + claimMapping.getLocalClaim().getClaimUri());
            }
        }
        return mappings;
    }

    /**
     * Serializes a structured error response to JSON and persists it to DebugSessionStore so the
     * API can return it when the client polls for the result. Also snapshots the current diagnostics
     * so partial progress is visible even on early failures.
     */
    private void buildAndCacheErrorResponse(String errorCode, String errorDescription,
            String state, DebugContext context) {

        context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, Boolean.FALSE);
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put(OIDCDebugConstants.DEBUG_RESULT_SUCCESS, false);
        errorResponse.put(OIDCDebugConstants.RESULT_ERROR_CODE, errorCode);
        errorResponse.put(OIDCDebugConstants.OIDC_ERROR_DESCRIPTION_PARAM,
                StringUtils.isNotBlank(errorDescription)
                        ? errorDescription : "An error occurred during OIDC debug processing.");

        String externalRedirectUrl = (String) context.getProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL);
        if (StringUtils.isNotBlank(externalRedirectUrl)) {
            errorResponse.put(OIDCDebugConstants.RESULT_EXTERNAL_REDIRECT_URL, externalRedirectUrl);
        }

        errorResponse.put(OIDCDebugConstants.DEBUG_DIAGNOSTICS,
                transformDiagnostics(DebugDiagnosticsUtil.getDiagnostics(context)));

        String errorResponseJson;
        try {
            errorResponseJson = OBJECT_MAPPER.writeValueAsString(errorResponse);
        } catch (JsonProcessingException e) {
            LOG.error("Failed to serialize error response to JSON: " + e.getMessage(), e);
            return;
        }
        context.setProperty(OIDCDebugConstants.DEBUG_RESULT_CACHE_KEY, errorResponseJson);
        String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);
        persistJsonToSessionStore(debugId, state, errorResponseJson);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Error response cached for state: " + state + " with error: " + errorCode);
        }
    }

    private void evaluateAccountLinking(DebugContext context, IdentityProvider idp,
            Map<String, Object> incomingClaims) {

        if (!isAccountLinkingEnabled(idp) || hasResolvedAccountLinkingStatus(context)) {
            return;
        }

        if (idp.getJustInTimeProvisioningConfig() == null) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                    OIDCDebugConstants.STATUS_PENDING, "Account linking configuration is not available.",
                    buildAccountLinkingDetails(context));
            return;
        }

        AccountLookupAttributeMappingConfig[] accountLookupMappings =
                idp.getJustInTimeProvisioningConfig().getAccountLookupAttributeMappings();
        if (accountLookupMappings == null || accountLookupMappings.length == 0) {
            evaluateDefaultAccountLinkingAttribute(context, incomingClaims);
        } else {
            evaluateConfiguredAccountLinkingAttributes(context, incomingClaims, accountLookupMappings);
        }

        String accountLinkingStatus = resolveAccountLinkingStatus(context);
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                accountLinkingStatus,
                OIDCDebugConstants.STATUS_FAILED.equals(accountLinkingStatus)
                        ? "Account linking attribute check failed."
                        : "Account linking attribute check successful.",
                buildAccountLinkingDetails(context));
    }

    private String resolveAccountLinkingStatus(DebugContext context) {

        Object status = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        return (status instanceof String && StringUtils.isNotBlank((String) status))
                ? (String) status : OIDCDebugConstants.STATUS_PENDING;
    }

    /**
     * Builds diagnostic details for account linking events.
     * Parses the failure message to extract the specific federated attribute name so it can be
     * surfaced as a structured field in the API response rather than buried in a free-text string.
     */
    private Map<String, Object> buildAccountLinkingDetails(DebugContext context) {

        Map<String, Object> details = new LinkedHashMap<>();
        Object accountLinkingMessage = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE);
        if (!(accountLinkingMessage instanceof String)
                || StringUtils.isBlank((String) accountLinkingMessage)) {
            return details;
        }

        String message = (String) accountLinkingMessage;
        details.put(OIDCDebugConstants.ACCOUNT_LINKING_REASON, message);

        String marker = "Required Federated IdP attribute '";
        if (message.startsWith(marker)) {
            int start = marker.length();
            int end = message.indexOf('\'', start);
            if (end > start) {
                details.put(OIDCDebugConstants.DIAG_FEDERATED_ATTRIBUTE, message.substring(start, end));
            }
        }
        return details;
    }

    /**
     * Flattens the OIDC "address" structured claim into individual keys so they can be matched
     * against IdP claim mappings that reference either format (e.g. "street_address" or "address.street_address").
     */
    private Map<String, Object> normalizeIncomingClaims(Map<String, Object> incomingClaims) {

        Map<String, Object> normalizedClaims = new HashMap<>(incomingClaims);
        Object addressClaim = incomingClaims.get(OIDCDebugConstants.CLAIM_ADDRESS);
        if (!(addressClaim instanceof Map)) {
            return normalizedClaims;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> addressClaims = (Map<String, Object>) addressClaim;
        for (Map.Entry<String, Object> entry : addressClaims.entrySet()) {
            if (entry.getValue() == null) {
                continue;
            }
            normalizedClaims.putIfAbsent(entry.getKey(), entry.getValue());
            normalizedClaims.put(OIDCDebugConstants.CLAIM_ADDRESS_PREFIX + entry.getKey(), entry.getValue());
        }
        return normalizedClaims;
    }

    private void evaluateDefaultAccountLinkingAttribute(DebugContext context,
            Map<String, Object> incomingClaims) {

        if (StringUtils.isBlank(getStringClaim(incomingClaims, OIDCDebugConstants.CLAIM_EMAIL))) {
            setAccountLinkingFailure(context, "\"email\" is missing.");
        } else {
            setAccountLinkingSuccess(context);
        }
    }

    private void evaluateConfiguredAccountLinkingAttributes(DebugContext context,
            Map<String, Object> incomingClaims,
            AccountLookupAttributeMappingConfig[] accountLookupMappings) {

        for (AccountLookupAttributeMappingConfig mappingConfig : accountLookupMappings) {
            if (mappingConfig == null || StringUtils.isBlank(mappingConfig.getFederatedAttribute())) {
                continue;
            }
            if (StringUtils.isBlank(getStringClaim(incomingClaims, mappingConfig.getFederatedAttribute()))) {
                setAccountLinkingFailure(context, buildMissingAccountLinkingAttributeMessage(mappingConfig));
                return;
            }
        }
        setAccountLinkingSuccess(context);
    }

    private boolean hasResolvedAccountLinkingStatus(DebugContext context) {

        Object status = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        return status instanceof String && StringUtils.isNotBlank((String) status);
    }

    private void setAccountLinkingSuccess(DebugContext context) {

        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS, OIDCDebugConstants.STATUS_SUCCESS);
        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE, null);
    }

    private void setAccountLinkingFailure(DebugContext context, String message) {

        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS, OIDCDebugConstants.STATUS_FAILED);
        context.setProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_MESSAGE, message);
    }

    private String buildMissingAccountLinkingAttributeMessage(AccountLookupAttributeMappingConfig mappingConfig) {

        String federatedAttribute = mappingConfig.getFederatedAttribute();
        String localAttribute = mappingConfig.getLocalAttribute();
        if (StringUtils.isNotBlank(localAttribute)) {
            return "Required Federated IdP attribute '" + federatedAttribute +
                    "' is missing for account linking to local attribute '" + localAttribute + "'.";
        }
        return "Required Federated IdP attribute '" + federatedAttribute + "' is missing for account linking.";
    }

    private boolean isAccountLinkingEnabled(IdentityProvider idp) {

        if (idp == null) {
            return false;
        }
        JustInTimeProvisioningConfig jitConfig = idp.getJustInTimeProvisioningConfig();
        return jitConfig != null && jitConfig.isProvisioningEnabled() && jitConfig.isAssociateLocalUserEnabled();
    }

    private String getStringClaim(Map<String, Object> claims, String claimName) {

        Object value = claims.get(claimName);
        return value instanceof String ? (String) value : null;
    }

    /**
     * Persists the JSON result under the debugId, which is the only key the API client can use to
     * retrieve it (the start-session response returns the debugId). The OAuth {@code state} is only
     * used as a fallback when the debugId is unavailable on an early error path.
     */
    private void persistJsonToSessionStore(String debugId, String state, String resultJson) {

        String storeKey = StringUtils.isNotBlank(debugId) ? debugId : state;
        if (StringUtils.isBlank(storeKey)) {
            LOG.error("Cannot persist debug result: neither debugId nor state is available.");
            return;
        }

        try {
            DebugSessionStore.getInstance().putResult(storeKey, resultJson);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Debug result persisted under key: " + storeKey);
            }
        } catch (DebugFrameworkServerException e) {
            LOG.error("Error persisting debug result to cache: " + e.getMessage(), e);
        }
    }

    @Override
    protected void sendDebugResponse(HttpServletResponse response, String state,
            String resourceIdentifier) throws IOException {

        if (response.isCommitted()) {
            return;
        }

        String encodedState = URLEncoder.encode(StringUtils.defaultString(state), StandardCharsets.UTF_8.name());
        String encodedIdpId = URLEncoder.encode(StringUtils.defaultString(resourceIdentifier), StandardCharsets.UTF_8.name());

        // IdentityUtil resolves the correct host/port for this deployment (handles proxy, port-offset, etc.).
        String successPageUrl = IdentityUtil.getServerURL(OIDCDebugConstants.DEBUG_SUCCESS_PAGE, true, true);
        response.sendRedirect(successPageUrl + "?state=" + encodedState + "&idpId=" + encodedIdpId);
    }

    /**
     * Restores context properties from DebugSessionStore using the state parameter.
     * Required because the OIDC callback arrives in a new request with no in-memory context.
     */
    private void restoreContextFromSessionCache(String state, DebugContext context) {

        Map<String, Object> cachedContext;
        try {
            cachedContext = DebugSessionStore.getInstance().get(state);
        } catch (DebugFrameworkServerException e) {
            LOG.warn("Unable to restore context from DebugSessionStore for state: " + state, e);
            return;
        }
        if (cachedContext == null || cachedContext.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No cached context found for state: " + state);
            }
            return;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Restoring context from DebugSessionStore for state: " + state);
        }

        // CLIENT_SECRET is intentionally excluded — it is nulled out before caching in OIDCDebugExecutor.
        String[] propertiesToRestore = {
                OIDCDebugConstants.TOKEN_ENDPOINT, OIDCDebugConstants.CLIENT_ID,
                OIDCDebugConstants.DEBUG_CODE_VERIFIER,
                OIDCDebugConstants.DEBUG_IDP_NAME, OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID,
                OIDCDebugConstants.AUTHORIZATION_ENDPOINT, OIDCDebugConstants.DEBUG_ID,
                OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL, OIDCDebugConstants.DEBUG_DIAGNOSTICS,
                OIDCDebugConstants.ACCESS_TOKEN, OIDCDebugConstants.ID_TOKEN, OIDCDebugConstants.TOKEN_TYPE,
                OIDCDebugConstants.DEBUG_NONCE,
        };
        for (String property : propertiesToRestore) {
            Object value = cachedContext.get(property);
            if (value != null) {
                context.setProperty(property, value);
            }
        }
    }

    private Map<String, Object> buildErrorDetails(String errorCode, String errorDescription) {

        Map<String, Object> details = new LinkedHashMap<>();
        if (StringUtils.isNotBlank(errorCode)) {
            details.put(OIDCDebugConstants.DIAG_ERROR_CODE, errorCode);
        }
        if (StringUtils.isNotBlank(errorDescription)) {
            details.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION, errorDescription);
        }
        return details;
    }

    private List<Map<String, Object>> transformDiagnostics(List<Map<String, Object>> diagnostics) {

        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, Object> diagnostic : diagnostics) {
            result.add(transformDiagnosticEvent(diagnostic));
        }
        return result;
    }

    /**
     * Reshapes a raw diagnostic event map for the API response:
     * promotes selected keys (errorCode, errorDescription, federatedAttribute) from the nested
     * "details" object up to the top level, and drops internal keys that must not leak to clients.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> transformDiagnosticEvent(Map<String, Object> diagnostic) {

        Map<String, Object> sanitizedEvent = new LinkedHashMap<>(diagnostic);
        Object detailsObj = sanitizedEvent.get(DebugFrameworkConstants.DIAGNOSTIC_DETAILS);
        if (!(detailsObj instanceof Map)) {
            return sanitizedEvent;
        }

        Map<String, Object> details = new LinkedHashMap<>((Map<String, Object>) detailsObj);

        // Promote selected keys from details up to the event level.
        Object errorCode = details.remove(OIDCDebugConstants.DIAG_ERROR_CODE);
        Object errorDescription = details.remove(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION);
        Object accountLinkingReason = details.remove(OIDCDebugConstants.ACCOUNT_LINKING_REASON);
        Object federatedAttribute = details.remove(OIDCDebugConstants.DIAG_FEDERATED_ATTRIBUTE);

        // Drop internal keys that must not leak into the API response.
        OIDCDebugConstants.DIAGNOSTIC_INTERNAL_DETAIL_KEYS.forEach(details::remove);

        if (errorCode != null) {
            sanitizedEvent.put(OIDCDebugConstants.DIAG_ERROR_CODE, errorCode);
        }
        if (errorDescription == null && accountLinkingReason != null) {
            errorDescription = accountLinkingReason;
        }
        if (errorDescription != null) {
            sanitizedEvent.put(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION, errorDescription);
        }
        if (federatedAttribute != null) {
            sanitizedEvent.put(OIDCDebugConstants.DIAG_FEDERATED_ATTRIBUTE, federatedAttribute);
        }

        if (details.isEmpty()) {
            sanitizedEvent.remove(DebugFrameworkConstants.DIAGNOSTIC_DETAILS);
        } else {
            sanitizedEvent.put(DebugFrameworkConstants.DIAGNOSTIC_DETAILS, details);
        }
        return sanitizedEvent;
    }

    private String objectToString(Object obj) {
        return obj != null ? obj.toString() : null;
    }
}
