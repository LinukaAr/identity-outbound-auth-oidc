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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.debug.util.OIDCDebugUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants.ErrorMessages;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.exception.DebugExecutionException;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.model.DebugResult;
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * OIDC debug flow executor.
 * Reads resolved OIDC parameters from the context (populated by OIDCContextProvider) and generates a complete
 * Authorization URL with PKCE and nonce parameters, then persists the context to the session store for callback
 * retrieval.
 */
public class OIDCDebugExecutor extends DebugExecutor {

    private static final Log LOG = LogFactory.getLog(OIDCDebugExecutor.class);

    @Override
    public DebugResult execute(DebugContext context) throws DebugExecutionException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Executing OIDC authorization URL generation");
        }

        try {
            String clientId = (String) context.getProperty(OIDCDebugConstants.CLIENT_ID);
            String authzEndpoint = (String) context.getProperty(OIDCDebugConstants.AUTHORIZATION_ENDPOINT);
            String redirectUri = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);

            String codeVerifier = OIDCDebugUtil.generatePKCECodeVerifier();
            String codeChallenge = OIDCDebugUtil.generatePKCECodeChallenge(codeVerifier);
            String nonce = OIDCDebugUtil.generateNonce();
            String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);

            context.setProperty(OIDCDebugConstants.DEBUG_CODE_VERIFIER, codeVerifier);
            // Nonce stored here is validated against the id_token nonce claim during callback processing.
            context.setProperty(OIDCDebugConstants.DEBUG_NONCE, nonce);

            String authorizationUrl = buildAuthorizationUrl(authzEndpoint, clientId, redirectUri, debugId,
                    codeChallenge, context);
            context.setProperty(OIDCDebugConstants.DEBUG_EXTERNAL_REDIRECT_URL, authorizationUrl);

            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_SUCCESS, "Configurations validated successfully.");

            cacheDebugContext(context);

            DebugResult result = new DebugResult();
            result.setDebugId(debugId);
            result.setStatus(DebugFrameworkConstants.DEBUG_STATUS_SUCCESS_INCOMPLETE);
            result.addResultData(OIDCDebugConstants.RESULT_AUTHORIZATION_URL, authorizationUrl);

            if (LOG.isDebugEnabled()) {
                LOG.debug("OIDC Authorization URL generated: debugId=" + debugId);
            }
            return result;

        } catch (DebugExecutionException e) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, e.getMessage());
            throw e;
        } catch (UnsupportedEncodingException e) {
            DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_AUTHORIZATION_REQUEST,
                    OIDCDebugConstants.STATUS_FAILED, "Error encoding authorization URL: " + e.getMessage());
            throw new DebugExecutionException(ErrorMessages.ERROR_CODE_EXECUTION_FAILED.getCode(),
                    ErrorMessages.ERROR_CODE_EXECUTION_FAILED.getMessage(),
                    "Error encoding authorization URL: " + e.getMessage(), e);
        }
    }

    /**
     * Builds the complete OIDC Authorization URL with required parameters (client_id, redirect_uri, scope, state),
     * PKCE (code_challenge/method), and nonce.
     */
    protected String buildAuthorizationUrl(String authzEndpoint, String clientId, String redirectUri,
            String state, String codeChallenge, DebugContext context)
            throws DebugExecutionException, UnsupportedEncodingException {

        String scope = (String) context.getProperty(OIDCDebugConstants.IDP_SCOPE);

        StringBuilder urlBuilder = new StringBuilder(authzEndpoint);
        urlBuilder.append(authzEndpoint.contains("?") ? "&" : "?").append("response_type=code");
        urlBuilder.append("&client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8.name()));
        urlBuilder.append("&redirect_uri=").append(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8.name()));
        urlBuilder.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8.name()));
        urlBuilder.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8.name()));
        urlBuilder.append("&code_challenge=").append(URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8.name()));
        urlBuilder.append("&").append(OIDCDebugConstants.CODE_CHALLENGE_METHOD_PARAM).append("=")
                .append(OIDCDebugConstants.PKCE_METHOD_S256);

        String nonce = (String) context.getProperty(OIDCDebugConstants.DEBUG_NONCE);
        if (StringUtils.isNotEmpty(nonce)) {
            urlBuilder.append("&nonce=").append(URLEncoder.encode(nonce, StandardCharsets.UTF_8.name()));
        }
        return urlBuilder.toString();
    }

    /**
     * Persists a sanitized copy of the context to the session store so it can be retrieved during the OIDC callback.
     * Credentials (clientSecret) are nulled out before storage and cleared from the live context after.
     */
    private void cacheDebugContext(DebugContext context) throws DebugExecutionException {

        String debugId = (String) context.getProperty(OIDCDebugConstants.DEBUG_ID);

        try {
            DebugContext sanitizedContext = DebugContext.buildFromMap(context.getProperties());
            sanitizedContext.setResourceType(context.getResourceType());
            sanitizedContext.setProperty(OIDCDebugConstants.CLIENT_SECRET, null);
            DebugSessionStore.getInstance().put(debugId, sanitizedContext);
        } catch (DebugFrameworkServerException e) {
            throw new DebugExecutionException(e.getErrorCode(), e.getMessage(),
                    "Failed to cache debug context for debugId: " + debugId, e);
        }

        context.setProperty(OIDCDebugConstants.CLIENT_SECRET, null);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Debug context cached successfully with debugId: " + debugId);
        }
    }
}
