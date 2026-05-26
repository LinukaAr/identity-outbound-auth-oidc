/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.debug.client;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.wso2.carbon.identity.application.authenticator.oidc.CustomURLConnectionClient;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;

/**
 * Responsible for performing OAuth2 token exchanges. Isolates HTTP/network logic from higher-level processors.
 * OAuth2TokenClient is stateless and protocol-focused - it receives pre-extracted configuration from the caller.
 */
public class OAuth2TokenClient {

    private static final Log LOG = LogFactory.getLog(OAuth2TokenClient.class);

    /**
     * Exchange an authorization code for tokens using the Apache Oltu OAuth client.
     * All configuration parameters must be provided by the caller (typically OAuth2DebugProcessor).
     *
     * @param authorizationCode The authorization code from the IdP.
     * @param tokenEndpoint The token endpoint URL of the IdP.
     * @param clientId The OAuth2 client ID.
     * @param clientSecret The OAuth2 client secret.
     * @param redirectUri The redirect URI.
     * @param codeVerifier The PKCE code verifier (may be null).
     * @param idpName The IdP name for logging and special-case handling.
     * @return TokenResponse with either tokens or error details.
     */
    public TokenResponse exchangeCodeForTokens(String authorizationCode, String tokenEndpoint, String clientId,
            String clientSecret, String redirectUri, String codeVerifier, String idpName) {

        try {
            OAuthClientRequest request = buildTokenRequest(tokenEndpoint, clientId, clientSecret, redirectUri,
                    authorizationCode, codeVerifier, idpName);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Exchanging authorization code for tokens at endpoint: " + tokenEndpoint +
                        " for IdP: " + idpName);
            }

            OAuthClient oAuthClient = new OAuthClient(new CustomURLConnectionClient());
            OAuthJSONAccessTokenResponse oAuthResponse = oAuthClient.accessToken(request);

            return extractTokenResponse(oAuthResponse, idpName);
        } catch (Exception e) {
            return handleTokenExchangeError(e, idpName);
        }
    }

    /**
     * Builds the OAuth2 token request with appropriate headers and parameters.
     *
     * @param tokenEndpoint The token endpoint URL.
     * @param clientId The OAuth2 client ID.
     * @param clientSecret The OAuth2 client secret.
     * @param redirectUri The redirect URI.
     * @param authorizationCode The authorization code.
     * @param codeVerifier The PKCE code verifier (may be null).
     * @param idpName The IdP name for special handling.
     * @return Configured OAuthClientRequest ready to send.
     */
    private OAuthClientRequest buildTokenRequest(String tokenEndpoint, String clientId, String clientSecret,
            String redirectUri, String authorizationCode, String codeVerifier, String idpName) {

        try {
            OAuthClientRequest.TokenRequestBuilder builder = OAuthClientRequest.tokenLocation(tokenEndpoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(clientId)
                    .setClientSecret(clientSecret)
                    .setRedirectURI(redirectUri)
                    .setCode(authorizationCode);

            // Only add code_verifier when present to avoid sending literal "null" string.
            if (StringUtils.isNotBlank(codeVerifier)) {
                builder.setParameter("code_verifier", codeVerifier);
            }

            OAuthClientRequest request = builder.buildBodyMessage();

            // Explicitly request JSON — required for GitHub (which defaults to form-urlencoded) and
            // consistent with OAuthJSONAccessTokenResponse which always parses JSON.
            request.addHeader("Accept", "application/json");

            return request;
        } catch (Exception e) {
            // Re-throw to be caught by the calling method's try-catch.
            throw new IllegalStateException("Failed to build OAuth2 token request", e);
        }
    }

    /**
     * Extracts tokens from the OAuth2 response.
     *
     * @param oAuthResponse The OAuth2 response from the IdP.
     * @param idpName The IdP name for logging.
     * @return TokenResponse with extracted tokens.
     */
    private TokenResponse extractTokenResponse(OAuthJSONAccessTokenResponse oAuthResponse, String idpName) {

        String tokenType = oAuthResponse.getParam("token_type");
        String idToken = oAuthResponse.getParam("id_token");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange successful for IdP: " + idpName + ".");
        }

        return TokenResponse.success(idToken, tokenType);
    }

    private TokenResponse handleTokenExchangeError(Exception e, String idpName) {

        String errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Token exchange failed for IdP: " + idpName + " - " + errorMessage);
        }

        return TokenResponse.error("TOKEN_EXCHANGE_ERROR", errorMessage);
    }

}
