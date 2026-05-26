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
import org.wso2.carbon.identity.debug.framework.DebugFrameworkConstants;
import org.wso2.carbon.identity.debug.framework.exception.DebugFrameworkServerException;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;
import org.wso2.carbon.identity.debug.framework.model.DebugContext;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugProcessor;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OAuth-style debug callback handler for OIDC and OIDC-based protocols (Google, GitHub).
 * Routing is performed by the interceptor using the protocol key stored in the debug session;
 * this handler only processes the callback once routed.
 */
public class OIDCDebugCallbackHandler implements DebugCallbackHandler {

    private final IdpDebugProcessor processor;

    public OIDCDebugCallbackHandler(IdpDebugProcessor processor) {

        this.processor = processor;
    }

    @Override
    public String getSupportedProtocol() {

        return OIDCDebugConstants.IDP_TYPE.toLowerCase();
    }

    @Override
    public boolean handleCallback(HttpServletRequest request, HttpServletResponse response,
            Map<String, Object> sessionData) throws DebugFrameworkServerException {

        String code = request.getParameter(OIDCDebugConstants.OIDC_CODE_PARAM);
        String state = request.getParameter(OIDCDebugConstants.OIDC_STATE_PARAM);

        DebugContext context = buildContext(sessionData);
        setContextProperties(context, code, state);

        if (response.isCommitted()) {
            return true;
        }

        processor.processCallback(request, response, context);
        return true;
    }

    private DebugContext buildContext(Map<String, Object> sessionData) {

        if (sessionData != null && !sessionData.isEmpty()) {
            return DebugContext.buildFromMap(sessionData);
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
