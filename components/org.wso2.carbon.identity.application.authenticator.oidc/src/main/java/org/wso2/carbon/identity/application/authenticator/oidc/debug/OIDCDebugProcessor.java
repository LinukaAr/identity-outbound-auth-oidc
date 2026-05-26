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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.OAuth2TokenClient;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.client.TokenResponse;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCConfiguration;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugProcessor;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
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
    private final OIDCDebugResultBuilder resultBuilder = new OIDCDebugResultBuilder();

    @Override
    protected boolean processAuthentication(HttpServletRequest request, DebugContext context,
            HttpServletResponse response, String state, String resourceIdentifier) throws DebugFrameworkServerException {

        String error = request.getParameter(OIDCDebugConstants.OIDC_ERROR_PARAM);
        if (error != null) {
            String errorDescription = request.getParameter(OIDCDebugConstants.OIDC_ERROR_DESCRIPTION_PARAM);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, error + ": " + errorDescription);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            resultBuilder.buildAndCacheErrorResponse(error, errorDescription, state, context);
            return false;
        }

        OIDCConfiguration config = resolveOIDCConfiguration(context, state);
        if (config == null) {
            return false;
        }

        return exchangeCodeForTokens(request, context, state, config);
    }

    private OIDCConfiguration resolveOIDCConfiguration(DebugContext context, String state) {

        IdentityProvider idp = resolveIdentityProvider(context);
        if (idp == null) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "Identity Provider configuration was not found.");
            resultBuilder.buildAndCacheErrorResponse("IDP_CONFIG_MISSING",
                    "Identity Provider configuration not found", state, context);
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            return null;
        }

        context.setProperty(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID, idp.getResourceId());
        context.setProperty(OIDCDebugConstants.IDP_CONFIG, idp);

        OIDCConfiguration config = extractOIDCConfiguration(context, idp);
        if (!config.isValid()) {
            handleConfigurationError(config, state, context);
            return null;
        }
        return config;
    }

    private boolean exchangeCodeForTokens(HttpServletRequest request, DebugContext context,
            String state, OIDCConfiguration config) {

        String code = request.getParameter(OIDCDebugConstants.OIDC_CODE_PARAM);
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_STARTED, "Starting OIDC token exchange.");

        try {
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
                resultBuilder.buildAndCacheErrorResponse(errorCode, errorDesc, state, context);
                return false;
            }

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
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                    OIDCDebugConstants.STATUS_FAILED, "OIDC token exchange failed with an exception.",
                    buildErrorDetails("TOKEN_EXCHANGE_ERROR", e.getMessage()));
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Token exchange error: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
            resultBuilder.buildAndCacheErrorResponse("TOKEN_EXCHANGE_ERROR",
                    "Token exchange error: " + e.getMessage(), state, context);
            return false;
        }
    }

    private IdentityProvider resolveIdentityProvider(DebugContext context) {

        try {
            String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
            String resourceId = (String) context.getProperty(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID);

            IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
            IdentityProvider idp = null;
            if (StringUtils.isNotEmpty(resourceId)) {
                idp = idpManager.getIdPByResourceId(resourceId, tenantDomain, true);
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
     */
    private OIDCConfiguration extractOIDCConfiguration(DebugContext context, IdentityProvider idp) {

        OIDCConfiguration config = new OIDCConfiguration();
        config.setTokenEndpoint((String) context.getProperty(OIDCDebugConstants.TOKEN_ENDPOINT));
        config.setClientId((String) context.getProperty(OIDCDebugConstants.CLIENT_ID));
        config.setCodeVerifier((String) context.getProperty(OIDCDebugConstants.DEBUG_CODE_VERIFIER));
        config.setClientSecret(extractClientSecretFromIdp(idp));
        config.setCallbackUrl(IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true));
        return config;
    }

    private String extractClientSecretFromIdp(IdentityProvider idp) {

        if (idp.getFederatedAuthenticatorConfigs() == null) {
            return null;
        }
        for (FederatedAuthenticatorConfig authConfig : idp.getFederatedAuthenticatorConfigs()) {
            if (authConfig == null || authConfig.getProperties() == null) {
                continue;
            }
            for (Property prop : authConfig.getProperties()) {
                if (prop != null && OIDCAuthenticatorConstants.CLIENT_SECRET.equals(prop.getName())
                        && StringUtils.isNotEmpty(prop.getValue())) {
                    return prop.getValue();
                }
            }
        }
        return null;
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
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_TOKEN_EXCHANGE,
                OIDCDebugConstants.STATUS_FAILED, errorDescription);
        resultBuilder.buildAndCacheErrorResponse(errorCode, errorDescription, state, context);
    }

    @Override
    protected Map<String, Object> extractDebugData(DebugContext context, String state) {

        try {
            String idToken = (String) context.getProperty(OIDCDebugConstants.ID_TOKEN);
            if (StringUtils.isBlank(idToken)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No ID token available for claim extraction");
                }
                DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                        OIDCDebugConstants.STATUS_FAILED, "ID token is not available for claim extraction.");
                resultBuilder.buildAndCacheErrorResponse("NO_ID_TOKEN", "ID token is not available for claim extraction.",
                        state, context);
                return null;
            }

            Map<String, Object> claims = parseIdTokenClaims(idToken);

            if (!isValidNonceClaim(context, claims)) {
                DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                        OIDCDebugConstants.STATUS_FAILED,
                        "ID token nonce claim validation failed.",
                        buildErrorDetails("NONCE_VALIDATION_FAILED",
                                "ID token nonce claim is missing or does not match the original request nonce."));
                resultBuilder.buildAndCacheErrorResponse("NONCE_VALIDATION_FAILED",
                        "ID token nonce claim is missing or does not match the original request nonce.",
                        state, context);
                return null;
            }

            context.setProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS, claims);
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                    OIDCDebugConstants.STATUS_SUCCESS, "Claims extracted successfully from tokens.");
            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully extracted " + claims.size() + " claims from tokens: " + claims.keySet());
            }
            return claims;

        } catch (RuntimeException e) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_CLAIM_EXTRACTION,
                    OIDCDebugConstants.STATUS_FAILED, "Error extracting claims from OIDC tokens.",
                    buildErrorDetails("CLAIM_EXTRACTION_ERROR", e.getMessage()));
            resultBuilder.buildAndCacheErrorResponse("CLAIM_EXTRACTION_ERROR",
                    "Error extracting claims from OIDC tokens: " + e.getMessage(), state, context);
            return null;
        }
    }

    private Map<String, Object> parseIdTokenClaims(String idToken) {

        try {
            String[] parts = idToken.split("\\.");
            if (parts.length != 3) {
                return new HashMap<>();
            }
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = OBJECT_MAPPER.readValue(payload, Map.class);
            return claims != null ? claims : new HashMap<>();
        } catch (IllegalArgumentException | IOException e) {
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
            return false;
        }

        if (!StringUtils.equals(expectedNonce, tokenNonce)) {
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("ID token nonce claim validation succeeded.");
        }
        return true;
    }

    @Override
    protected void buildAndCacheDebugResult(DebugContext context, String state) {

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> rawClaims = (Map<String, Object>) context
                    .getProperty(OIDCDebugConstants.DEBUG_INCOMING_CLAIMS);
            Map<String, Object> normalizedClaims = resultBuilder.normalizeIncomingClaims(
                    rawClaims != null ? rawClaims : new HashMap<>());

            IdentityProvider idp = (IdentityProvider) context.getProperty(OIDCDebugConstants.IDP_CONFIG);

            Map<String, Object> debugResult = new HashMap<>();
            resultBuilder.processClaimMappings(context, idp, normalizedClaims, debugResult);
            resultBuilder.evaluateAccountLinking(context, idp, normalizedClaims);
            resultBuilder.buildResultMetadata(debugResult, context);
            resultBuilder.persistDebugResult(state, context, debugResult);

        } catch (RuntimeException e) {
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_ERROR, "Error caching debug result: " + e.getMessage());
            context.setProperty(OIDCDebugConstants.DEBUG_AUTH_SUCCESS, false);
        }
    }

    @Override
    protected void sendDebugResponse(HttpServletResponse response, String state,
            String resourceIdentifier) throws DebugFrameworkServerException {

        if (response.isCommitted()) {
            return;
        }

        try {
            String encodedState = URLEncoder.encode(StringUtils.defaultString(state), StandardCharsets.UTF_8.name());
            String encodedIdpId = URLEncoder.encode(StringUtils.defaultString(resourceIdentifier),
                    StandardCharsets.UTF_8.name());
            String successPageUrl = IdentityUtil.getServerURL(OIDCDebugConstants.DEBUG_SUCCESS_PAGE, true, true);
            response.sendRedirect(successPageUrl + "?state=" + encodedState + "&idpId=" + encodedIdpId);
        } catch (IOException e) {
            throw new DebugFrameworkServerException(
                    DebugFrameworkConstants.ErrorMessages.ERROR_CODE_SERVER_ERROR.getCode(),
                    DebugFrameworkConstants.ErrorMessages.ERROR_CODE_SERVER_ERROR.getMessage(),
                    e.getMessage(),
                    e);
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

}
