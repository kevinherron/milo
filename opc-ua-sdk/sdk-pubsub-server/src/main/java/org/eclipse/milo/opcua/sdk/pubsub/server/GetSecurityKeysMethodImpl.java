/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.server;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.methods.Out;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubKeyServiceType;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.jspecify.annotations.Nullable;

/**
 * The {@code GetSecurityKeys} handler installed on the ns0 PublishSubscribe method node ({@code
 * i=15215}) when {@link ServerPubSubOptions.Builder#sksServerEnabled} is set, serving keys from the
 * attached {@link SecurityGroupKeyStore} (OPC UA Part 14 §8.3.2).
 *
 * <p>Check order (K17):
 *
 * <ol>
 *   <li>Channel mode: the session's channel must be {@code SignAndEncrypt}, else {@code
 *       Bad_SecurityModeInsufficient} ("Encryption is required for this Method"). This
 *       belt-and-suspenders check duplicates the ns0 {@code AccessRestrictions(3)} enforcement in
 *       the access controller: fragment-grafted nodes ship no AccessRestrictions, and the handler
 *       must not depend on node attributes for a spec-mandated result code.
 *   <li>Authorization via {@link PubSubMethodAuthorizer#checkKeyAccess}, <em>before</em> the
 *       existence check so unauthorized callers cannot probe SecurityGroupIds; {@code DENY} maps to
 *       {@code Bad_UserAccessDenied}.
 *   <li>Existence: an unknown SecurityGroupId yields {@code Bad_NotFound}.
 * </ol>
 *
 * <p>An absent session marks an internal invocation ({@code AccessContext.INTERNAL}): per its
 * contract "no user- or session-related restrictions should be applied", so the channel-mode and
 * authorization checks are skipped. The client-facing Call service path always carries a session.
 */
final class GetSecurityKeysMethodImpl extends PubSubKeyServiceType.GetSecurityKeysMethod {

  private final SecurityGroupKeyStore keyStore;
  private final PubSubMethodAuthorizer authorizer;

  GetSecurityKeysMethodImpl(
      UaMethodNode node, SecurityGroupKeyStore keyStore, PubSubMethodAuthorizer authorizer) {

    super(node);

    this.keyStore = keyStore;
    this.authorizer = authorizer;
  }

  @Override
  protected void invoke(
      InvocationContext context,
      @Nullable String securityGroupId,
      @Nullable UInteger startingTokenId,
      @Nullable UInteger requestedKeyCount,
      Out<String> securityPolicyUri,
      Out<UInteger> firstTokenId,
      Out<ByteString[]> keys,
      Out<Double> timeToNextKey,
      Out<Double> keyLifetime)
      throws UaException {

    SecurityGroupConfig group = securityGroupId != null ? keyStore.getGroup(securityGroupId) : null;

    Session session = context.getSession().orElse(null);

    if (session != null) {
      if (session.getEndpoint().getSecurityMode() != MessageSecurityMode.SignAndEncrypt) {
        throw new UaException(StatusCodes.Bad_SecurityModeInsufficient);
      }

      if (authorizer.checkKeyAccess(session, securityGroupId, group)
          != PubSubMethodAuthorizer.Decision.ALLOW) {
        throw new UaException(StatusCodes.Bad_UserAccessDenied);
      }
    }

    if (group == null) {
      throw new UaException(StatusCodes.Bad_NotFound);
    }

    SecurityKeySet keySet =
        keyStore.getSecurityKeys(
            group.getSecurityGroupId(),
            startingTokenId != null ? startingTokenId : uint(0),
            requestedKeyCount != null ? requestedKeyCount : uint(0));

    if (keySet == null) {
      throw new UaException(StatusCodes.Bad_NotFound);
    }

    securityPolicyUri.set(keySet.securityPolicyUri());
    firstTokenId.set(keySet.firstTokenId());
    keys.set(keySet.keys().toArray(ByteString[]::new));
    timeToNextKey.set((double) keySet.timeToNextKey().toMillis());
    keyLifetime.set((double) keySet.keyLifetime().toMillis());
  }
}
