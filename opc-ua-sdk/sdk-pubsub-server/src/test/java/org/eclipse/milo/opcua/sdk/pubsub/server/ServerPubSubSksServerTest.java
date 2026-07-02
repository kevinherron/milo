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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfigValidationException;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.server.AccessContext;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.methods.MethodInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@link ServerPubSub} lifecycle integration of the opt-in SKS server face (K15): the {@code
 * GetSecurityKeys} handler on ns0 {@code i=15215} is bound by startup and restored to {@code
 * Bad_NotImplemented} by shutdown, only when {@link ServerPubSubOptions.Builder#sksServerEnabled}
 * is set; SecurityGroup validation fails attach fast.
 */
class ServerPubSubSksServerTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private static TestPubSubServer testServer;

  @BeforeAll
  static void startServer() {
    testServer = TestPubSubServer.create();
  }

  @AfterAll
  static void stopServer() {
    testServer.close();
  }

  private static UaMethodNode getSecurityKeysNode() {
    return (UaMethodNode)
        testServer
            .getServer()
            .getAddressSpaceManager()
            .getManagedNode(NodeIds.PublishSubscribe_GetSecurityKeys)
            .orElseThrow();
  }

  private static PubSubConfig sksConfig() {
    return PubSubConfig.builder()
        .securityGroup(
            SecurityGroupConfig.builder("LifecycleGroup")
                .securityPolicyUri(PubSubSecurityPolicy.Aes128Ctr.getUri())
                .keyLifeTime(Duration.ofHours(1))
                .maxFutureKeyCount(uint(3))
                .build())
        .build();
  }

  @Test
  void sksDisabledByDefaultLeavesMethodNotImplemented() throws Exception {
    ServerPubSub serverPubSub = ServerPubSub.attach(testServer.getServer(), sksConfig());
    try {
      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

      assertSame(
          MethodInvocationHandler.NOT_IMPLEMENTED, getSecurityKeysNode().getInvocationHandler());
    } finally {
      serverPubSub.close();
    }
  }

  @Test
  void sksEnabledBindsHandlerOnStartupAndRestoresOnClose() throws Exception {
    ServerPubSubOptions options = ServerPubSubOptions.builder().sksServerEnabled(true).build();

    ServerPubSub serverPubSub = ServerPubSub.attach(testServer.getServer(), sksConfig(), options);
    try {
      // binding happens at startup, not attach
      assertSame(
          MethodInvocationHandler.NOT_IMPLEMENTED, getSecurityKeysNode().getInvocationHandler());

      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

      MethodInvocationHandler handler = getSecurityKeysNode().getInvocationHandler();
      assertInstanceOf(GetSecurityKeysMethodImpl.class, handler);

      // internal invocation serves keys for the attach-time SecurityGroup
      var request =
          new CallMethodRequest(
              NodeIds.PublishSubscribe,
              NodeIds.PublishSubscribe_GetSecurityKeys,
              new Variant[] {
                new Variant("LifecycleGroup"), new Variant(uint(0)), new Variant(uint(1))
              });

      CallMethodResult result = handler.invoke(AccessContext.INTERNAL, request);
      assertTrue(result.getStatusCode().isGood());

      Variant[] outputs = result.getOutputArguments();
      assertNotNull(outputs);
      assertEquals(PubSubSecurityPolicy.Aes128Ctr.getUri(), outputs[0].getValue());
      assertEquals(uint(1), outputs[1].getValue());
      ByteString[] keys = (ByteString[]) outputs[2].getValue();
      assertNotNull(keys);
      assertEquals(2, keys.length);
      assertEquals(52, keys[0].length());
    } finally {
      serverPubSub.close();
    }

    assertSame(
        MethodInvocationHandler.NOT_IMPLEMENTED, getSecurityKeysNode().getInvocationHandler());
  }

  @Test
  void sksEnabledFailsAttachOnUnsupportedSecurityPolicy() {
    PubSubConfig config =
        PubSubConfig.builder()
            .securityGroup(
                SecurityGroupConfig.builder("BadPolicyGroup")
                    .securityPolicyUri(
                        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep")
                    .build())
            .build();

    ServerPubSubOptions options = ServerPubSubOptions.builder().sksServerEnabled(true).build();

    assertThrows(
        PubSubConfigValidationException.class,
        () -> ServerPubSub.attach(testServer.getServer(), config, options));

    // the failed attach must not have touched the ns0 method node
    assertSame(
        MethodInvocationHandler.NOT_IMPLEMENTED, getSecurityKeysNode().getInvocationHandler());
  }

  @Test
  void optionsDefaultsAndToBuilderRoundTrip() {
    ServerPubSubOptions defaults = ServerPubSubOptions.builder().build();

    assertFalse(defaults.isSksServerEnabled());
    assertSame(PubSubMethodAuthorizer.defaultAuthorizer(), defaults.getMethodAuthorizer());

    var customAuthorizer =
        new PubSubMethodAuthorizer() {
          @Override
          public Decision checkConfigure(Session session) {
            return Decision.DENY;
          }

          @Override
          public Decision checkSksAdmin(Session session) {
            return Decision.DENY;
          }

          @Override
          public Decision checkKeyAccess(
              Session session, String securityGroupId, SecurityGroupConfig securityGroup) {
            return Decision.DENY;
          }
        };

    ServerPubSubOptions options =
        ServerPubSubOptions.builder()
            .sksServerEnabled(true)
            .methodAuthorizer(customAuthorizer)
            .build();

    ServerPubSubOptions copy = options.toBuilder().build();

    assertEquals(options, copy);
    assertTrue(copy.isSksServerEnabled());
    assertSame(customAuthorizer, copy.getMethodAuthorizer());
    assertNotEquals(defaults, options);
  }
}
