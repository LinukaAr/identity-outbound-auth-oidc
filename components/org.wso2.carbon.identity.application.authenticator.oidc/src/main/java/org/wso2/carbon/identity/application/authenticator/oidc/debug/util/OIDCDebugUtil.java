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

package org.wso2.carbon.identity.application.authenticator.oidc.debug.util;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Nonce generation helpers for the OIDC debug flow.
 */
public final class OIDCDebugUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private OIDCDebugUtil() {
    }

    /**
     * Generates a cryptographic nonce for OIDC ID Token replay protection.
     * Uses SecureRandom for 32 bytes of entropy, encoded as URL-safe Base64.
     * The nonce is included in the authorization request and validated against
     * the ID token nonce claim per OIDC Core §3.1.2.1.
     *
     * @return Cryptographically random nonce string.
     */
    public static String generateNonce() {

        byte[] nonceBytes = new byte[32];
        SECURE_RANDOM.nextBytes(nonceBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
    }
}
