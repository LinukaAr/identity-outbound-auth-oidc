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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.AccountLookupAttributeMappingConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;
import org.wso2.carbon.identity.debug.framework.util.DebugDiagnosticsUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds, serializes, and persists OIDC debug results and error responses to the session store.
 * Also owns claim mapping and account linking evaluation logic.
 */
public class OIDCDebugResultBuilder {

    private static final Log LOG = LogFactory.getLog(OIDCDebugResultBuilder.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Serializes the success result map to JSON and persists it to the session store.
     */
    public void persistDebugResult(String state, DebugContext context, Map<String, Object> debugResult) {

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

    /**
     * Builds a structured error response, serializes it to JSON, and persists it to the session store.
     * Snapshots current diagnostics so partial progress is visible even on early failures.
     */
    public void buildAndCacheErrorResponse(String errorCode, String errorDescription,
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

    /**
     * Appends the authorization URL, raw ID token, and diagnostics snapshot to the result map.
     */
    public void buildResultMetadata(Map<String, Object> debugResult, DebugContext context) {

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

    /**
     * Processes IdP claim mappings against incoming OIDC claims and writes the mapped claims array
     * to the debug result. Records a diagnostic event for the claim mapping stage.
     */
    public void processClaimMappings(DebugContext context, IdentityProvider idp,
            Map<String, Object> incomingClaims, Map<String, Object> debugResult) {

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
     * Evaluates account linking readiness by checking whether the required federated attributes
     * are present in the incoming claims. Records a diagnostic event for the account linking stage.
     */
    public void evaluateAccountLinking(DebugContext context, IdentityProvider idp,
            Map<String, Object> incomingClaims) {

        Object existingStatus = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        if (!isAccountLinkingEnabled(idp) || (existingStatus instanceof String
                && StringUtils.isNotBlank((String) existingStatus))) {
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

        Object statusProp = context.getProperty(OIDCDebugConstants.CONTEXT_ACCOUNT_LINKING_STATUS);
        String accountLinkingStatus = (statusProp instanceof String && StringUtils.isNotBlank((String) statusProp))
                ? (String) statusProp : OIDCDebugConstants.STATUS_PENDING;
        DebugDiagnosticsUtil.recordEvent(context, OIDCDebugConstants.STAGE_ACCOUNT_LINKING,
                accountLinkingStatus,
                OIDCDebugConstants.STATUS_FAILED.equals(accountLinkingStatus)
                        ? "Account linking attribute check failed."
                        : "Account linking attribute check successful.",
                buildAccountLinkingDetails(context));
    }

    /**
     * Flattens the OIDC "address" structured claim into individual keys so they can be matched
     * against IdP claim mappings that reference either format (e.g. "street_address" or "address.street_address").
     */
    public Map<String, Object> normalizeIncomingClaims(Map<String, Object> incomingClaims) {

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

    /**
     * Persists the JSON result under the debugId (preferred) or state (fallback on early error paths).
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
            Object idpClaimObj = claim.get(OIDCDebugConstants.CLAIM_MAPPING_IDP_CLAIM);
            Object localClaimObj = claim.get(OIDCDebugConstants.CLAIM_MAPPING_LOCAL_CLAIM);
            String idpClaim = idpClaimObj != null ? idpClaimObj.toString() : null;
            String localClaim = localClaimObj != null ? localClaimObj.toString() : null;

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

        Object errorCode = details.remove(OIDCDebugConstants.DIAG_ERROR_CODE);
        Object errorDescription = details.remove(OIDCDebugConstants.DIAG_ERROR_DESCRIPTION);
        Object accountLinkingReason = details.remove(OIDCDebugConstants.ACCOUNT_LINKING_REASON);
        Object federatedAttribute = details.remove(OIDCDebugConstants.DIAG_FEDERATED_ATTRIBUTE);

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
}
