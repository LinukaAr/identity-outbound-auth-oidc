/*
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

import org.wso2.carbon.identity.debug.framework.extension.DebugTypeProvider;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugConstants;
import org.wso2.carbon.identity.debug.framework.core.DebugContextProvider;
import org.wso2.carbon.identity.debug.framework.core.DebugExecutor;
import org.wso2.carbon.identity.debug.framework.core.DebugProcessor;
import org.wso2.carbon.identity.debug.idp.core.IdpDebugProcessor;
import org.wso2.carbon.identity.debug.framework.extension.DebugCallbackHandler;

/**
 * OIDC implementation of DebugTypeProvider.
 */
public class OIDCDebugTypeProvider implements DebugTypeProvider {

    private final DebugContextProvider contextProvider;
    private final DebugExecutor executor;
    private final IdpDebugProcessor processor;
    private final DebugCallbackHandler callbackHandler;

    public OIDCDebugTypeProvider() {

        this(new OIDCContextProvider(), new OIDCDebugExecutor(), new OIDCDebugProcessor());
    }

    public OIDCDebugTypeProvider(DebugContextProvider contextProvider, DebugExecutor executor,
                                 IdpDebugProcessor processor) {

        this.contextProvider = contextProvider;
        this.executor = executor;
        this.processor = processor;
        this.callbackHandler = new OIDCDebugCallbackHandler(processor,
                OIDCDebugConstants.IDP_TYPE, IdpDebugConstants.IDP_TYPE_GOOGLE,
                IdpDebugConstants.IDP_TYPE_GITHUB);
    }

    @Override
    public String getProtocolType() {

        return OIDCDebugConstants.IDP_TYPE;
    }

    @Override
    public DebugContextProvider getContextProvider() {

        return contextProvider;
    }

    @Override
    public DebugExecutor getExecutor() {

        return executor;
    }

    public DebugProcessor getProcessor() {

        return processor;
    }

    @Override
    public DebugCallbackHandler getCallbackHandler() {

        return callbackHandler;
    }

}
