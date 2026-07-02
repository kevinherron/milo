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

import java.util.Optional;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.methods.MethodInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The opt-in, minimal Security Key Service face of {@link ServerPubSub}: binds the {@code
 * GetSecurityKeys} handler to the well-known ns0 method node ({@code i=15215} on the
 * PublishSubscribe object {@code i=14443}) and manages the {@link SecurityGroupKeyStore} lifecycle.
 *
 * <p>Deliberately not implemented in this version: {@code GetSecurityGroup}, the SecurityGroups
 * folder methods ({@code AddSecurityGroup}/{@code RemoveSecurityGroup} and the folder variants),
 * {@code InvalidateKeys}, and {@code ForceKeyRotation} — their ns0 nodes keep returning {@code
 * Bad_NotImplemented}. Push distribution ({@code SetSecurityKeys}) is not supported in this
 * version.
 *
 * <p>At most one SKS-enabled {@link ServerPubSub} may be attached to a given {@link OpcUaServer}:
 * the handler binding on the shared ns0 node is exclusive, and shutdown restores {@code
 * Bad_NotImplemented} unconditionally.
 *
 * <p>Driven by the owning {@link ServerPubSub}: {@link #startup()} on {@code
 * ServerPubSub.startup()}, {@link #shutdown()} on {@code ServerPubSub.shutdown()}/{@code close()}.
 */
final class SksServer {

  private static final Logger LOGGER = LoggerFactory.getLogger(SksServer.class);

  private @Nullable UaMethodNode methodNode;

  private final OpcUaServer server;
  private final SecurityGroupKeyStore keyStore;
  private final PubSubMethodAuthorizer authorizer;

  SksServer(OpcUaServer server, SecurityGroupKeyStore keyStore, PubSubMethodAuthorizer authorizer) {

    this.server = server;
    this.keyStore = keyStore;
    this.authorizer = authorizer;
  }

  /** The key store serving this SKS face. */
  SecurityGroupKeyStore getKeyStore() {
    return keyStore;
  }

  /** Start key housekeeping and bind the GetSecurityKeys handler to the ns0 method node. */
  void startup() {
    keyStore.startup();

    Optional<UaNode> node =
        server.getAddressSpaceManager().getManagedNode(NodeIds.PublishSubscribe_GetSecurityKeys);

    if (node.orElse(null) instanceof UaMethodNode methodNode) {
      methodNode.setInvocationHandler(
          new GetSecurityKeysMethodImpl(methodNode, keyStore, authorizer));
      this.methodNode = methodNode;
    } else {
      LOGGER.warn(
          "ns0 GetSecurityKeys method node not found: {}",
          NodeIds.PublishSubscribe_GetSecurityKeys);
    }
  }

  /** Restore the ns0 method node to {@code Bad_NotImplemented} and stop key housekeeping. */
  void shutdown() {
    UaMethodNode methodNode = this.methodNode;
    if (methodNode != null) {
      methodNode.setInvocationHandler(MethodInvocationHandler.NOT_IMPLEMENTED);
      this.methodNode = null;
    }

    keyStore.shutdown();
  }
}
