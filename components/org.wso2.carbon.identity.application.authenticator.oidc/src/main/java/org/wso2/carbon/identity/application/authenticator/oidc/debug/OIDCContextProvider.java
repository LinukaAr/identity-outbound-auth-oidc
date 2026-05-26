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

package org.wso2.carbon.identity.application.authenticator.oidc.debug;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants.ErrorMessages;
import org.wso2.carbon.identity.debug.framework.exception.ContextResolutionException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugConstants;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugContextProvider;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * OIDC context resolver for debug operations.
 * Extends the framework's IdpDebugContextProvider to provide OIDC-specific context resolution from IdP configuration.
 */
public class OIDCContextProvider extends IdpDebugContextProvider {

    private static final Log LOG = LogFactory.getLog(OIDCContextProvider.class);
    private static final OpenIDConnectExecutor OIDC_EXECUTOR = new OpenIDConnectExecutor();

    @Override
    public DebugContext resolveContext(String idpId, String authenticator, IdentityProvider preloadedIdp)
            throws ContextResolutionException {

        validateIdpIsEnabled(preloadedIdp);

        Map<String, Object> contextMap = new HashMap<>();
        contextMap.put(OIDCDebugConstants.DEBUG_IDP_RESOURCE_ID,
                StringUtils.defaultIfEmpty(preloadedIdp.getResourceId(), preloadedIdp.getIdentityProviderName()));

        FederatedAuthenticatorConfig authenticatorConfig = findOIDCAuthenticatorConfig(preloadedIdp, authenticator);
        if (authenticatorConfig == null) {
            throw contextError("No OIDC authenticator configuration found for IdP: "
                    + preloadedIdp.getIdentityProviderName());
        }

        extractOIDCConfigs(authenticatorConfig, contextMap);

        contextMap.put(OIDCDebugConstants.DEBUG_ID,
                DebugFrameworkConstants.DEBUG_PREFIX + UUID.randomUUID());
        contextMap.put(OIDCDebugConstants.CONTEXT_PROTOCOL, OIDCDebugConstants.IDP_TYPE);

        return DebugContext.buildFromMap(contextMap);
    }

    private void validateIdpIsEnabled(IdentityProvider idp) throws ContextResolutionException {

        if (!idp.isEnable()) {
            throw contextError("IdP is not available: " + idp.getIdentityProviderName());
        }
    }

    private FederatedAuthenticatorConfig findOIDCAuthenticatorConfig(IdentityProvider idp,
            String authenticatorName) {

        FederatedAuthenticatorConfig[] configs = idp.getFederatedAuthenticatorConfigs();
        if (configs == null || configs.length == 0) {
            return null;
        }

        // 1. Exact match on the requested authenticator name.
        if (StringUtils.isNotEmpty(authenticatorName)) {
            for (FederatedAuthenticatorConfig config : configs) {
                if (config != null && config.isEnabled() && authenticatorName.equals(config.getName())) {
                    return config;
                }
            }
        }

        // 2. Any enabled config that looks like an OIDC authenticator (known impl or *OIDCAuthenticator).
        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && config.isEnabled() && isOidcAuthenticator(config.getName())) {
                return config;
            }
        }

        return null;
    }

    private boolean isOidcAuthenticator(String implementationName) {

        return isKnownOidcImplementation(implementationName)
                || (StringUtils.isNotEmpty(implementationName) && implementationName.endsWith("OIDCAuthenticator"));
    }

    private boolean isKnownOidcImplementation(String implementationName) {

        return IdpDebugConstants.IMPLEMENTATION_OPENID_CONNECT.equals(implementationName)
                || IdpDebugConstants.IMPLEMENTATION_GOOGLE_OIDC.equals(implementationName)
                || IdpDebugConstants.IMPLEMENTATION_GITHUB.equals(implementationName);
    }

    private void extractOIDCConfigs(FederatedAuthenticatorConfig config, Map<String, Object> context)
            throws ContextResolutionException {

        Property[] properties = config.getProperties();
        if (properties == null || properties.length == 0) {
            throw contextError("No properties found in authenticator configuration");
        }

        Map<String, String> propertyMap = new HashMap<>();
        for (Property prop : properties) {
            if (prop != null && prop.getName() != null && prop.getValue() != null) {
                propertyMap.put(prop.getName(), prop.getValue());
            }
        }
        OpenIDConnectExecutor executor = resolveExecutor(config.getName());

        String clientId = propertyMap.get(OIDCAuthenticatorConstants.CLIENT_ID);
        if (StringUtils.isEmpty(clientId)) {
            throw contextError("Client ID not found in authenticator configuration");
        }
        context.put(OIDCDebugConstants.CLIENT_ID, clientId);

        context.put(OIDCDebugConstants.AUTHORIZATION_ENDPOINT,
                resolveEndpoint(executor, propertyMap, config.getName(), true));
        context.put(OIDCDebugConstants.TOKEN_ENDPOINT,
                resolveEndpoint(executor, propertyMap, config.getName(), false));
        context.put(OIDCDebugConstants.IDP_SCOPE, resolveScope(propertyMap, executor));

        String clientSecret = propertyMap.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        if (StringUtils.isNotEmpty(clientSecret)) {
            context.put(OIDCDebugConstants.CLIENT_SECRET, clientSecret);
        }
    }

    protected OpenIDConnectExecutor resolveExecutor(String authenticatorName) {

        return isKnownOidcImplementation(authenticatorName) ? OIDC_EXECUTOR : null;
    }

    private String resolveEndpoint(OpenIDConnectExecutor executor, Map<String, String> propertyMap,
            String authenticatorName, boolean isAuthorizationEndpoint) throws ContextResolutionException {

        String endpoint = null;
        if (executor != null) {
            try {
                endpoint = isAuthorizationEndpoint
                        ? executor.getAuthorizationServerEndpoint(propertyMap)
                        : executor.getTokenEndpoint(propertyMap);
            } catch (RuntimeException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to get endpoint from executor: " + e.getMessage());
                }
            }
        }

        if (StringUtils.isEmpty(endpoint)) {
            endpoint = isAuthorizationEndpoint
                    ? propertyMap.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL)
                    : propertyMap.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
        }

        if (StringUtils.isEmpty(endpoint) && IdpDebugConstants.IMPLEMENTATION_GOOGLE_OIDC.equals(authenticatorName)) {
            endpoint = isAuthorizationEndpoint
                    ? IdentityApplicationConstants.GOOGLE_OAUTH_URL
                    : IdentityApplicationConstants.GOOGLE_TOKEN_URL;
        }

        if (StringUtils.isEmpty(endpoint)) {
            throw contextError((isAuthorizationEndpoint ? "Authorization" : "Token")
                    + " endpoint not found in authenticator configuration");
        }
        return endpoint;
    }

    private String resolveScope(Map<String, String> propertyMap, OpenIDConnectExecutor executor) {

        String scope = propertyMap.get(IdentityApplicationConstants.Authenticator.OIDC.SCOPES);
        if (StringUtils.isNotEmpty(scope)) {
            return scope;
        }

        String additionalParams = propertyMap.get(OIDCDebugConstants.PROP_ADDITIONAL_QUERY_PARAMS);
        if (StringUtils.isNotEmpty(additionalParams)) {
            scope = extractScopeFromQueryParams(additionalParams);
            if (StringUtils.isNotEmpty(scope)) {
                return scope;
            }
        }

        if (executor != null) {
            scope = executor.getScope(propertyMap);
            if (StringUtils.isNotEmpty(scope)) {
                return scope;
            }
        }

        return OIDCDebugConstants.DEFAULT_SCOPE;
    }

    private String extractScopeFromQueryParams(String queryParams) {

        for (String param : queryParams.split("&")) {
            if (!param.trim().startsWith("scope=")) {
                continue;
            }
            try {
                return URLDecoder.decode(param.substring("scope=".length()), StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException e) {
                // unreachable — UTF-8 is always supported on the JVM.
                return null;
            }
        }
        return null;
    }

    private ContextResolutionException contextError(String description) {

        return new ContextResolutionException(
                ErrorMessages.ERROR_CODE_CONTEXT_RESOLUTION_FAILED.getCode(),
                ErrorMessages.ERROR_CODE_CONTEXT_RESOLUTION_FAILED.getMessage(),
                description);
    }
}
