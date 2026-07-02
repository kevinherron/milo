/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.security;

import java.util.concurrent.CompletableFuture;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;

/**
 * SPI providing runtime key material for a SecurityGroup, bound via {@code PubSubBindings}.
 *
 * <p>Mirrors the Security Key Service {@code GetSecurityKeys} method (OPC UA Part 14 §8.3.2):
 * implementations range from pre-shared keys ({@link StaticSecurityKeyProvider}) to a full SKS pull
 * client. The engine's key manager drives this SPI: it fetches at component startup and on the
 * §8.3.2 refresh cadence, and a failed future feeds the Part 14 state rules — components stay
 * PreOperational until the first successful fetch, and go to Error when key material goes stale
 * (§5.4.5.3).
 *
 * <p><b>Policy precedence.</b> The returned {@link SecurityKeySet#securityPolicyUri()} is
 * authoritative for the key material. If the configuration also pins a security policy URI (on
 * {@code MessageSecurityConfig} or {@code SecurityGroupConfig}) and the provider returns a
 * different one, the fetch is treated as <b>failed</b> — key material is never silently used under
 * a different security level than the operator pinned. When no policy URI is configured, any
 * supported policy is accepted (one that {@link PubSubSecurityPolicy#fromUri(String)} resolves; an
 * unsupported URI also fails the fetch).
 */
@FunctionalInterface
public interface SecurityKeyProvider {

  /**
   * Get key material for a SecurityGroup.
   *
   * @param securityGroupId the id of the SecurityGroup to get keys for.
   * @param startingTokenId the id of the first token to return; 0 requests the current token.
   * @param requestedKeyCount the number of future keys requested in addition to the starting
   *     token's key (§8.3.2: the returned set carries the starting token's key plus up to this many
   *     subsequent keys; if 0 is requested, no future keys are returned). This matches the wire
   *     semantics of the {@code GetSecurityKeys} RequestedKeyCount argument.
   * @return a {@link CompletableFuture} that completes with the requested {@link SecurityKeySet},
   *     or completes exceptionally if the keys could not be obtained.
   */
  CompletableFuture<SecurityKeySet> getKeys(
      String securityGroupId, UInteger startingTokenId, UInteger requestedKeyCount);
}
