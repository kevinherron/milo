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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
import org.eclipse.milo.opcua.sdk.pubsub.sks.SksSecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.server.AccessContext;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.methods.MethodInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.security.DefaultClientCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.MemoryTrustListManager;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link SksSecurityKeyProvider} against the embedded SKS server face, end-to-end over real
 * channels through the production {@code DefaultSksClientOperations} path (not the stubbed
 * operations seam its unit tests use): Table 40 §6.2.5.4 resolution — GetEndpoints at the entry's
 * {@code server.discoveryUrls[0]}, applicationUri + SignAndEncrypt filtering, a validating
 * (test-trusting) certificate posture, an Anonymous identity — then {@code GetSecurityKeys} (ns0
 * {@code i=15215}) on the resolved SignAndEncrypt session.
 *
 * <p>Covers the K20/WP-T4 pull rows: a fetch whose {@link SecurityKeySet} matches the server-side
 * {@link SecurityGroupKeyStore} (policy URI, FirstTokenId, key material and sizes,
 * TimeToNextKey/KeyLifetime), session caching across repeated fetches, and re-resolution after a
 * server-side session failure.
 */
class SksPullProviderEndToEndTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(30);

  private static final String GROUP_ID = "PullGroup";
  private static final PubSubSecurityPolicy POLICY = PubSubSecurityPolicy.Aes128Ctr;
  private static final Duration KEY_LIFETIME = Duration.ofHours(1);

  private static TestSksServer sks;
  private static ServerPubSub serverPubSub;
  private static TestSksServer.ClientIdentity clientIdentity;

  @BeforeAll
  static void createFixture() throws Exception {
    sks = TestSksServer.create();

    clientIdentity = TestSksServer.newClientIdentity();
    sks.trustClientCertificate(clientIdentity.certificate());

    // one SecurityGroup with empty RolePermissions: the no-RoleMapper default posture
    // allows any encrypted caller, so the provider's Anonymous identity is sufficient
    PubSubConfig config =
        PubSubConfig.builder()
            .securityGroup(
                SecurityGroupConfig.builder(GROUP_ID)
                    .securityPolicyUri(POLICY.getUri())
                    .keyLifeTime(KEY_LIFETIME)
                    .maxFutureKeyCount(uint(3))
                    .maxPastKeyCount(uint(2))
                    .build())
            .build();

    ServerPubSubOptions options = ServerPubSubOptions.builder().sksServerEnabled(true).build();

    serverPubSub = ServerPubSub.attach(sks.getServer(), config, options);
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
  }

  @AfterAll
  static void destroyFixture() throws Exception {
    if (serverPubSub != null) {
      serverPubSub.close();
    }
    if (sks != null) {
      sks.close();
    }
  }

  @BeforeEach
  void awaitSessionDrain() throws Exception {
    // sessions from a previous test's provider close asynchronously; start from a clean slate
    awaitTrue(
        "previous test sessions drained",
        () -> sks.getServer().getSessionManager().getAllSessions().isEmpty());
  }

  // region fixtures/helpers

  /**
   * A Table 40 identity record for the embedded SKS: {@code EndpointUrl} empty, the server's
   * ApplicationUri, {@code ApplicationType.Server}, and the endpoint URL as the discovery URL.
   */
  private static EndpointDescription table40Entry() {
    var server =
        new ApplicationDescription(
            sks.getApplicationUri(),
            "urn:eclipse:milo:pubsub:sks-test-server",
            LocalizedText.english("embedded sks test server"),
            ApplicationType.Server,
            null,
            null,
            new String[] {sks.getEndpointUrl()});

    return new EndpointDescription(
        null,
        server,
        ByteString.NULL_VALUE,
        MessageSecurityMode.SignAndEncrypt,
        null,
        null,
        null,
        ubyte(0));
  }

  /**
   * A provider over the production client operations: fail-closed default replaced by a validator
   * trusting exactly the embedded server's certificate, client identity supplied via the
   * customizer.
   */
  private static SksSecurityKeyProvider newProvider() {
    var trustListManager = new MemoryTrustListManager();
    trustListManager.addTrustedCertificate(sks.getCertificate());

    var certificateValidator =
        new DefaultClientCertificateValidator(trustListManager, new MemoryCertificateQuarantine());

    return SksSecurityKeyProvider.builder()
        .securityKeyServices(List.of(table40Entry()))
        .securityGroupId(GROUP_ID)
        .certificateValidator(certificateValidator)
        .clientCustomizer(
            b ->
                b.setApplicationUri(clientIdentity.applicationUri())
                    .setCertificate(clientIdentity.certificate())
                    .setCertificateChain(new X509Certificate[] {clientIdentity.certificate()})
                    .setKeyPair(clientIdentity.keyPair()))
        .requestTimeout(TIMEOUT)
        .fetchTimeout(TIMEOUT)
        .build();
  }

  private static List<NodeId> sessionIds() {
    return sks.getServer().getSessionManager().getAllSessions().stream()
        .map(Session::getSessionId)
        .toList();
  }

  private static void awaitTrue(String description, BooleanSupplier condition)
      throws InterruptedException {
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    while (System.nanoTime() < deadline) {
      if (condition.getAsBoolean()) {
        return;
      }
      Thread.sleep(10);
    }
    fail("timed out waiting for: " + description);
  }

  // endregion

  @Test
  void fetchSucceedsAndKeySetMatchesTheStore() throws Exception {
    try (SksSecurityKeyProvider provider = newProvider()) {
      SecurityKeySet keySet =
          provider.getKeys(GROUP_ID, uint(0), uint(2)).get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

      // §8.3.2 out-args mapped verbatim: policy, first token, keys, ttnk, lifetime
      assertEquals(POLICY.getUri(), keySet.securityPolicyUri());
      assertEquals(uint(1), keySet.firstTokenId());
      assertEquals(3, keySet.keys().size()); // starting key + 2 subsequent (store semantics)
      for (ByteString key : keySet.keys()) {
        assertEquals(POLICY.getKeyDataLength(), key.length()); // 52 bytes for Aes128Ctr
      }
      assertEquals(KEY_LIFETIME, keySet.keyLifetime());
      assertTrue(
          !keySet.timeToNextKey().isNegative()
              && keySet.timeToNextKey().compareTo(KEY_LIFETIME) <= 0,
          "TimeToNextKey out of range: " + keySet.timeToNextKey());

      // the same slice read straight from the store (internal invocation of the bound
      // handler) must carry byte-identical key material: what the provider fetched over
      // the SignAndEncrypt channel IS the store's material
      CallMethodResult internal = internalGetSecurityKeys(uint(1), uint(2));
      assertTrue(internal.getStatusCode().isGood());

      Variant[] outputs = internal.getOutputArguments();
      assertNotNull(outputs);
      assertEquals(keySet.securityPolicyUri(), outputs[0].getValue());
      assertEquals(keySet.firstTokenId(), outputs[1].getValue());

      ByteString[] storeKeys = (ByteString[]) outputs[2].getValue();
      assertNotNull(storeKeys);
      assertEquals(keySet.keys().size(), storeKeys.length);
      for (int i = 0; i < storeKeys.length; i++) {
        assertEquals(storeKeys[i], keySet.keys().get(i), "key material differs at token " + i);
      }
    }
  }

  @Test
  void repeatedFetchReusesTheCachedSession() throws Exception {
    try (SksSecurityKeyProvider provider = newProvider()) {
      provider.getKeys(GROUP_ID, uint(0), uint(0)).get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

      List<NodeId> afterFirst = sessionIds();
      assertEquals(1, afterFirst.size(), "expected exactly one provider session");

      provider.getKeys(GROUP_ID, uint(0), uint(0)).get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

      List<NodeId> afterSecond = sessionIds();
      assertEquals(
          afterFirst,
          afterSecond,
          "a repeated fetch must reuse the cached session (Part 4 §6.1.4)");
    }
  }

  @Test
  void fetchAfterServerSideSessionFailureReResolves() throws Exception {
    try (SksSecurityKeyProvider provider = newProvider()) {
      SecurityKeySet first =
          provider.getKeys(GROUP_ID, uint(0), uint(0)).get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      assertEquals(POLICY.getUri(), first.securityPolicyUri());

      List<NodeId> sessions = sessionIds();
      assertEquals(1, sessions.size());
      NodeId killedSessionId = sessions.get(0);

      // simulate SKS restart/failure: the provider's cached session dies server-side
      sks.getServer().getSessionManager().killSession(killedSessionId, true);

      // the next fetch must recover — cached-session failure invalidates and re-resolves
      // through discovery — and serve the same store-backed material
      SecurityKeySet second =
          provider.getKeys(GROUP_ID, uint(0), uint(0)).get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      assertEquals(POLICY.getUri(), second.securityPolicyUri());
      assertEquals(first.firstTokenId(), second.firstTokenId());
      assertEquals(first.keys().get(0), second.keys().get(0), "store key material must match");

      // the replacement session is a new one; the killed session is gone
      awaitTrue(
          "a new session replaces the killed one",
          () -> {
            List<NodeId> current = sessionIds();
            return !current.isEmpty() && !current.contains(killedSessionId);
          });
    }
  }

  private static CallMethodResult internalGetSecurityKeys(
      UInteger startingTokenId, UInteger requestedKeyCount) {

    UaMethodNode methodNode =
        (UaMethodNode)
            sks.getServer()
                .getAddressSpaceManager()
                .getManagedNode(NodeIds.PublishSubscribe_GetSecurityKeys)
                .orElseThrow();

    MethodInvocationHandler handler = methodNode.getInvocationHandler();

    var request =
        new CallMethodRequest(
            NodeIds.PublishSubscribe,
            NodeIds.PublishSubscribe_GetSecurityKeys,
            new Variant[] {
              new Variant(GROUP_ID), new Variant(startingTokenId), new Variant(requestedKeyCount)
            });

    return handler.invoke(AccessContext.INTERNAL, request);
  }
}
