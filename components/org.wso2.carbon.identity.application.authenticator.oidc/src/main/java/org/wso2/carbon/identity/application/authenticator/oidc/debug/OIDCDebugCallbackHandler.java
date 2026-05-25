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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.framework.store.DebugSessionStore;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugConstants;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugProcessor;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OAuth-style debug callback handler owned by the OIDC protocol bundle.
 * Processes callbacks for OIDC and related protocols (e.g., Google, GitHub) during the debug flow.
 */
public class OIDCDebugCallbackHandler implements DebugCallbackHandler {

    private static final Log LOG = LogFactory.getLog(OIDCDebugCallbackHandler.class);

    private final IdpDebugProcessor processor;
    private final Set<String> supportedProtocols;

    public OIDCDebugCallbackHandler(IdpDebugProcessor processor) {

        this(processor, OIDCDebugConstants.IDP_TYPE, IdpDebugConstants.IDP_TYPE_GOOGLE,
                IdpDebugConstants.IDP_TYPE_GITHUB);
    }

    public OIDCDebugCallbackHandler(IdpDebugProcessor processor, String... supportedProtocols) {

        this.processor = processor;
        Set<String> normalizedProtocols = new HashSet<>();
        if (supportedProtocols != null) {
            Arrays.stream(supportedProtocols)
                    .filter(StringUtils::isNotBlank)
                    .map(protocol -> protocol.trim().toLowerCase(Locale.ROOT))
                    .forEach(normalizedProtocols::add);
        }
        this.supportedProtocols = Collections.unmodifiableSet(normalizedProtocols);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return isSupportedProtocol(request.getParameter(OIDCDebugConstants.OIDC_STATE_PARAM));
    }

    @Override
    public boolean handleCallback(HttpServletRequest request, HttpServletResponse response)
            throws DebugFrameworkServerException {

        if (!canHandle(request)) {
            return false;
        }

        String code = request.getParameter(OIDCDebugConstants.OIDC_CODE_PARAM);
        String state = request.getParameter(OIDCDebugConstants.OIDC_STATE_PARAM);

        DebugContext context = retrieveOrCreateContext(state);
        setContextProperties(context, code, state);

        if (response.isCommitted()) {
            // Earlier filter already responded; nothing to add. Still claim the callback.
            return true;
        }

        // Propagate processor failures to the coordinator, which owns the error response.
        processor.processCallback(request, response, context);
        return true;
    }

    private boolean isSupportedProtocol(String state) {

        if (CollectionUtils.isEmpty(supportedProtocols)) {
            return true;
        }

        Map<String, Object> cachedContext;
        try {
            cachedContext = DebugSessionStore.getInstance().get(state);
        } catch (DebugFrameworkServerException e) {
            // canHandle is a routing decision and cannot throw; a store outage means we
            // cannot confidently claim ownership, so defer to other handlers.
            LOG.debug("Unable to resolve cached debug protocol for state: " + state, e);
            return false;
        }
        if (cachedContext == null || cachedContext.isEmpty()) {
            return false;
        }

        Object protocol = cachedContext.get(OIDCDebugConstants.CONTEXT_PROTOCOL);
        if (protocol == null) {
            return false;
        }
        return supportedProtocols.contains(protocol.toString().trim().toLowerCase(Locale.ENGLISH));
    }

    private DebugContext retrieveOrCreateContext(String state) throws DebugFrameworkServerException {

        Map<String, Object> cachedContextMap = DebugSessionStore.getInstance().get(state);
        if (cachedContextMap != null && !cachedContextMap.isEmpty()) {
            return DebugContext.buildFromMap(cachedContextMap);
        }

        DebugContext context = new DebugContext();
        context.setProperty(DebugFrameworkConstants.DEBUG_FLOW_TYPE, DebugFrameworkConstants.FLOW_TYPE_CALLBACK);
        context.setProperty(DebugFrameworkConstants.DEBUG_CONTEXT_CREATED, DebugFrameworkConstants.TRUE_VALUE);
        context.setProperty(DebugFrameworkConstants.DEBUG_CREATION_TIMESTAMP, System.currentTimeMillis());
        return context;
    }

    private void setContextProperties(DebugContext context, String code, String state) {

        if (StringUtils.isNotBlank(code)) {
            context.setProperty(DebugFrameworkConstants.DEBUG_PROTOCOL_CODE, code);
        }
        if (StringUtils.isNotBlank(state)) {
            context.setProperty(DebugFrameworkConstants.DEBUG_PROTOCOL_STATE, state);
        }
    }
}
