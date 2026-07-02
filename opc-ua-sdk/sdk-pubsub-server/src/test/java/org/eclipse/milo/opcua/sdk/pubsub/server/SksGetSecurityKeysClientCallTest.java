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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.client.DiscoveryClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfigBuilder;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.PermissionType;
import org.eclipse.milo.opcua.stack.core.types.structured.RolePermissionType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The client-driven {@code GetSecurityKeys} authorization matrix (K17, Part 14 §8.3.2 / §9.1.3.3):
 * every row is a REAL {@code Call} from a connected {@link OpcUaClient} over a real secure channel,
 * not a directly constructed session, so the full server-side chain runs — ns0 {@code i=15215}
 * {@code AccessRestrictions(3)} enforcement in the access controller (the K17.1 status-propagation
 * fix) ahead of the handler's own channel-mode and {@link PubSubMethodAuthorizer} checks.
 *
 * <p>The channel-mode rows pin the status code observed on the wire: over {@code None} and {@code
 * Sign} channels the controller's AccessRestrictions denial fires first and, per K17.1, must
 * surface as {@code Bad_SecurityModeInsufficient} (not collapse to {@code Bad_UserAccessDenied});
 * the handler's belt-and-suspenders re-check yields the same code and is unit-covered in {@link
 * GetSecurityKeysMethodImplTest}.
 *
 * <p>Two started fixture servers cover the default-posture split: no {@code RoleMapper} configured
 * (empty group RolePermissions ⇒ allow encrypted callers, non-empty ⇒ fail closed) vs {@link
 * TestRoleMapper} (well-known {@code SecurityKeyServerAccess} role required). Each test attaches
 * its own {@link ServerPubSub} so the exclusive ns0 handler binding never leaks across tests.
 */
class SksGetSecurityKeysClientCallTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(30);

  private static final NodeId CUSTOM_ROLE = new NodeId(2, "CustomRole");

  private static TestSksServer plainSks;
  private static TestSksServer roleMappedSks;
  private static TestRoleMapper roleMapper;
  private static TestSksServer.ClientIdentity clientIdentity;

  @BeforeAll
  static void createFixture() throws Exception {
    plainSks = TestSksServer.create();
    roleMapper = new TestRoleMapper();
    roleMappedSks = TestSksServer.create(roleMapper);

    clientIdentity = TestSksServer.newClientIdentity();
    plainSks.trustClientCertificate(clientIdentity.certificate());
    roleMappedSks.trustClientCertificate(clientIdentity.certificate());
  }

  @AfterAll
  static void destroyFixture() throws Exception {
    if (plainSks != null) {
      plainSks.close();
    }
    if (roleMappedSks != null) {
      roleMappedSks.close();
    }
  }

  // region fixtures

  /** "GroupA" has empty RolePermissions; "Restricted" is governed by {@link #CUSTOM_ROLE}. */
  private static PubSubConfig groupsConfig() {
    return PubSubConfig.builder()
        .securityGroup(
            SecurityGroupConfig.builder("GroupA")
                .securityPolicyUri(PubSubSecurityPolicy.Aes128Ctr.getUri())
                .keyLifeTime(Duration.ofHours(1))
                .maxFutureKeyCount(uint(3))
                .build())
        .securityGroup(
            SecurityGroupConfig.builder("Restricted")
                .securityPolicyUri(PubSubSecurityPolicy.Aes256Ctr.getUri())
                .keyLifeTime(Duration.ofHours(1))
                .rolePermissions(
                    List.of(
                        new RolePermissionType(
                            CUSTOM_ROLE, PermissionType.of(PermissionType.Field.Call))))
                .build())
        .build();
  }

  /** Attach and start an SKS-enabled {@link ServerPubSub} serving {@link #groupsConfig()}. */
  private static ServerPubSub attachSks(TestSksServer sks) throws Exception {
    ServerPubSubOptions options = ServerPubSubOptions.builder().sksServerEnabled(true).build();

    ServerPubSub serverPubSub = ServerPubSub.attach(sks.getServer(), groupsConfig(), options);
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    return serverPubSub;
  }

  /**
   * Connect a real {@link OpcUaClient} to the fixture endpoint with the requested channel security
   * mode, discovering the endpoint like any client would.
   */
  private static OpcUaClient connectClient(TestSksServer sks, MessageSecurityMode securityMode)
      throws Exception {

    List<EndpointDescription> endpoints =
        DiscoveryClient.getEndpoints(sks.getEndpointUrl())
            .get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    EndpointDescription endpoint =
        endpoints.stream()
            .filter(e -> e.getSecurityMode() == securityMode)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("no endpoint with mode " + securityMode));

    OpcUaClientConfigBuilder configBuilder = OpcUaClientConfig.builder();
    configBuilder.setEndpoint(endpoint);
    configBuilder.setApplicationName(LocalizedText.english("sks matrix test client"));
    configBuilder.setApplicationUri(clientIdentity.applicationUri());
    configBuilder.setCertificate(clientIdentity.certificate());
    configBuilder.setCertificateChain(new X509Certificate[] {clientIdentity.certificate()});
    configBuilder.setKeyPair(clientIdentity.keyPair());
    configBuilder.setRequestTimeout(uint(TIMEOUT.toMillis()));

    OpcUaClient client = OpcUaClient.create(configBuilder.build());
    client.connect();
    return client;
  }

  /** Call ns0 GetSecurityKeys (i=15215 on i=14443) through the Call service. */
  private static CallMethodResult callGetSecurityKeys(OpcUaClient client, String securityGroupId)
      throws Exception {

    var request =
        new CallMethodRequest(
            NodeIds.PublishSubscribe,
            NodeIds.PublishSubscribe_GetSecurityKeys,
            new Variant[] {
              new Variant(securityGroupId), new Variant(uint(0)), new Variant(uint(0))
            });

    CallMethodResult[] results = client.call(List.of(request)).getResults();
    assertNotNull(results);
    assertEquals(1, results.length);
    return results[0];
  }

  // endregion

  // region no RoleMapper: channel-mode and fail-closed rows

  @Test
  void callOverNoneChannelIsSecurityModeInsufficient() throws Exception {
    try (ServerPubSub ignored = attachSks(plainSks)) {
      OpcUaClient client = connectClient(plainSks, MessageSecurityMode.None);
      try {
        CallMethodResult result = callGetSecurityKeys(client, "GroupA");

        // the pinned code, not a collapsed Bad_UserAccessDenied (K17.1)
        assertEquals(StatusCodes.Bad_SecurityModeInsufficient, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void callOverSignChannelIsSecurityModeInsufficient() throws Exception {
    try (ServerPubSub ignored = attachSks(plainSks)) {
      OpcUaClient client = connectClient(plainSks, MessageSecurityMode.Sign);
      try {
        CallMethodResult result = callGetSecurityKeys(client, "GroupA");

        // AccessRestrictions(3) = SigningRequired | EncryptionRequired: Sign is not enough
        assertEquals(StatusCodes.Bad_SecurityModeInsufficient, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void encryptedCallWithoutRoleMapperServesKeysForUnrestrictedGroup() throws Exception {
    try (ServerPubSub ignored = attachSks(plainSks)) {
      OpcUaClient client = connectClient(plainSks, MessageSecurityMode.SignAndEncrypt);
      try {
        CallMethodResult result = callGetSecurityKeys(client, "GroupA");

        assertTrue(result.getStatusCode().isGood(), "unexpected status: " + result.getStatusCode());

        // §8.3.2 out-args: SecurityPolicyUri, FirstTokenId, Keys, TimeToNextKey, KeyLifetime
        Variant[] outputs = result.getOutputArguments();
        assertNotNull(outputs);
        assertEquals(5, outputs.length);
        assertEquals(PubSubSecurityPolicy.Aes128Ctr.getUri(), outputs[0].getValue());
        assertEquals(uint(1), outputs[1].getValue());

        ByteString[] keys = (ByteString[]) outputs[2].getValue();
        assertNotNull(keys);
        assertEquals(1, keys.length); // RequestedKeyCount 0 => the starting key only
        assertEquals(
            PubSubSecurityPolicy.Aes128Ctr.getKeyDataLength(), keys[0].length()); // 52 bytes

        double timeToNextKey = (Double) outputs[3].getValue();
        double keyLifetime = (Double) outputs[4].getValue();
        assertEquals(Duration.ofHours(1).toMillis(), keyLifetime);
        assertTrue(
            timeToNextKey > 0 && timeToNextKey <= keyLifetime,
            "TimeToNextKey out of range: " + timeToNextKey);
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void encryptedCallWithoutRoleMapperIsDeniedRestrictedGroup() throws Exception {
    try (ServerPubSub ignored = attachSks(plainSks)) {
      OpcUaClient client = connectClient(plainSks, MessageSecurityMode.SignAndEncrypt);
      try {
        // non-empty RolePermissions cannot be evaluated without a RoleMapper: fail closed
        CallMethodResult result = callGetSecurityKeys(client, "Restricted");

        assertEquals(StatusCodes.Bad_UserAccessDenied, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void encryptedCallForUnknownSecurityGroupIdIsNotFound() throws Exception {
    try (ServerPubSub ignored = attachSks(plainSks)) {
      OpcUaClient client = connectClient(plainSks, MessageSecurityMode.SignAndEncrypt);
      try {
        CallMethodResult result = callGetSecurityKeys(client, "NoSuchGroup");

        assertEquals(StatusCodes.Bad_NotFound, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void sksDisabledLeavesMethodNotImplementedOnTheWire() throws Exception {
    // default options: sksServerEnabled=false, so the ns0 skeleton handler still answers
    ServerPubSub serverPubSub = ServerPubSub.attach(plainSks.getServer(), groupsConfig());
    try {
      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

      // over SignAndEncrypt so the AccessRestrictions gate cannot mask the handler's answer
      OpcUaClient client = connectClient(plainSks, MessageSecurityMode.SignAndEncrypt);
      try {
        CallMethodResult result = callGetSecurityKeys(client, "GroupA");

        assertEquals(StatusCodes.Bad_NotImplemented, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    } finally {
      serverPubSub.close();
    }
  }

  // endregion

  // region TestRoleMapper: well-known-role rows

  @Test
  void roleMappedCallerWithAccessRoleGetsKeys() throws Exception {
    try (ServerPubSub ignored = attachSks(roleMappedSks)) {
      roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAccess));

      OpcUaClient client = connectClient(roleMappedSks, MessageSecurityMode.SignAndEncrypt);
      try {
        CallMethodResult result = callGetSecurityKeys(client, "GroupA");

        assertTrue(result.getStatusCode().isGood(), "unexpected status: " + result.getStatusCode());

        Variant[] outputs = result.getOutputArguments();
        assertNotNull(outputs);
        assertEquals(PubSubSecurityPolicy.Aes128Ctr.getUri(), outputs[0].getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void roleMappedCallerWithoutAccessRoleIsDenied() throws Exception {
    try (ServerPubSub ignored = attachSks(roleMappedSks)) {
      roleMapper.setRoleIds(List.of());

      OpcUaClient client = connectClient(roleMappedSks, MessageSecurityMode.SignAndEncrypt);
      try {
        CallMethodResult result = callGetSecurityKeys(client, "GroupA");

        assertEquals(StatusCodes.Bad_UserAccessDenied, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  // endregion
}
