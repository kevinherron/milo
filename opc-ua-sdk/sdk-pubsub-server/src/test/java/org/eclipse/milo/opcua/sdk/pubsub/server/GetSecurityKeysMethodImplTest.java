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

import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.server.AccessContext;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.SecurityConfiguration;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
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
import org.eclipse.milo.opcua.stack.core.types.structured.PermissionType;
import org.eclipse.milo.opcua.stack.core.types.structured.RolePermissionType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@link GetSecurityKeysMethodImpl} check order and result codes (Part 14 §8.3.2, K17): channel
 * mode before authorization before existence, exercised through the public {@code
 * AbstractMethodInvocationHandler.invoke(AccessContext, CallMethodRequest)} entry so argument
 * validation and status-code mapping run exactly as they do for a client Call.
 *
 * <p>The client-driven end-to-end (a real Call over a SignAndEncrypt channel) is WP-T4 scope; these
 * tests bind sessions directly.
 */
class GetSecurityKeysMethodImplTest {

  private static final NodeId CUSTOM_ROLE = new NodeId(2, "CustomRole");
  private static final Instant T0 = Instant.parse("2026-07-01T00:00:00Z");

  private static TestPubSubServer plainServer;
  private static TestPubSubServer roleMappedServer;
  private static TestRoleMapper roleMapper;
  private static ScheduledExecutorService scheduler;
  private static GetSecurityKeysMethodImpl handler;

  @BeforeAll
  static void createFixture() {
    plainServer = TestPubSubServer.create();
    roleMapper = new TestRoleMapper();
    roleMappedServer = TestPubSubServer.create(roleMapper);
    scheduler = Executors.newSingleThreadScheduledExecutor();

    SecurityGroupConfig groupA =
        SecurityGroupConfig.builder("GroupA")
            .securityPolicyUri(PubSubSecurityPolicy.Aes128Ctr.getUri())
            .keyLifeTime(Duration.ofHours(1))
            .maxFutureKeyCount(uint(3))
            .maxPastKeyCount(uint(2))
            .build();

    SecurityGroupConfig restricted =
        SecurityGroupConfig.builder("Restricted")
            .securityPolicyUri(PubSubSecurityPolicy.Aes256Ctr.getUri())
            .rolePermissions(
                List.of(
                    new RolePermissionType(
                        CUSTOM_ROLE, PermissionType.of(PermissionType.Field.Call))))
            .build();

    var keyStore =
        new SecurityGroupKeyStore(List.of(groupA, restricted), scheduler, InstantSource.fixed(T0));

    UaMethodNode methodNode =
        (UaMethodNode)
            plainServer
                .getServer()
                .getAddressSpaceManager()
                .getManagedNode(NodeIds.PublishSubscribe_GetSecurityKeys)
                .orElseThrow();

    handler =
        new GetSecurityKeysMethodImpl(
            methodNode, keyStore, PubSubMethodAuthorizer.defaultAuthorizer());
  }

  @AfterAll
  static void destroyFixture() {
    scheduler.shutdownNow();
    plainServer.close();
    roleMappedServer.close();
  }

  private static Session newSession(OpcUaServer server, MessageSecurityMode securityMode) {
    var applicationDescription =
        new ApplicationDescription(
            "urn:eclipse:milo:pubsub:test-client",
            "urn:eclipse:milo:pubsub:test-client",
            LocalizedText.english("test client"),
            ApplicationType.Client,
            null,
            null,
            null);

    SecurityPolicy securityPolicy =
        securityMode == MessageSecurityMode.None
            ? SecurityPolicy.None
            : SecurityPolicy.Basic256Sha256;

    var endpoint =
        new EndpointDescription(
            "opc.tcp://localhost:0",
            applicationDescription,
            ByteString.NULL_VALUE,
            securityMode,
            securityPolicy.getUri(),
            null,
            null,
            ubyte(0));

    var securityConfiguration =
        new SecurityConfiguration(securityPolicy, securityMode, null, null, null, null, null);

    return new Session(
        server,
        new NodeId(1, "sks-test-session-" + System.nanoTime()),
        "sks-test-session",
        Duration.ofMinutes(5),
        applicationDescription,
        "urn:eclipse:milo:pubsub:test-server",
        uint(0),
        endpoint,
        1L,
        securityConfiguration);
  }

  private static CallMethodResult call(
      AccessContext accessContext,
      Variant securityGroupId,
      UInteger startingTokenId,
      UInteger requestedKeyCount) {

    var request =
        new CallMethodRequest(
            NodeIds.PublishSubscribe,
            NodeIds.PublishSubscribe_GetSecurityKeys,
            new Variant[] {
              securityGroupId, new Variant(startingTokenId), new Variant(requestedKeyCount)
            });

    return handler.invoke(accessContext, request);
  }

  private static CallMethodResult call(Session session, String securityGroupId) {
    return call(() -> Optional.of(session), new Variant(securityGroupId), uint(0), uint(0));
  }

  @Test
  void channelModeNoneIsSecurityModeInsufficient() {
    Session session = newSession(plainServer.getServer(), MessageSecurityMode.None);

    CallMethodResult result = call(session, "GroupA");

    assertEquals(StatusCodes.Bad_SecurityModeInsufficient, result.getStatusCode().getValue());
  }

  @Test
  void channelModeSignIsSecurityModeInsufficient() {
    Session session = newSession(plainServer.getServer(), MessageSecurityMode.Sign);

    CallMethodResult result = call(session, "GroupA");

    assertEquals(StatusCodes.Bad_SecurityModeInsufficient, result.getStatusCode().getValue());
  }

  @Test
  void encryptedCallerWithoutRoleMapperGetsKeysOfUnrestrictedGroup() {
    Session session = newSession(plainServer.getServer(), MessageSecurityMode.SignAndEncrypt);

    CallMethodResult result =
        call(() -> Optional.of(session), new Variant("GroupA"), uint(0), uint(2));

    assertTrue(result.getStatusCode().isGood());

    Variant[] outputs = result.getOutputArguments();
    assertNotNull(outputs);
    assertEquals(5, outputs.length);
    assertEquals(PubSubSecurityPolicy.Aes128Ctr.getUri(), outputs[0].getValue());
    assertEquals(uint(1), outputs[1].getValue());

    ByteString[] keys = (ByteString[]) outputs[2].getValue();
    assertNotNull(keys);
    assertEquals(3, keys.length);
    for (ByteString key : keys) {
      assertEquals(52, key.length());
    }

    // at the fixed clock instant the full first lifetime remains
    assertEquals(3_600_000.0, outputs[3].getValue());
    assertEquals(3_600_000.0, outputs[4].getValue());
  }

  @Test
  void encryptedCallerWithoutRoleMapperIsDeniedRestrictedGroup() {
    // explicit RolePermissions cannot be evaluated without a RoleMapper: fail closed
    Session session = newSession(plainServer.getServer(), MessageSecurityMode.SignAndEncrypt);

    CallMethodResult result = call(session, "Restricted");

    assertEquals(StatusCodes.Bad_UserAccessDenied, result.getStatusCode().getValue());
  }

  @Test
  void unknownSecurityGroupIdIsNotFound() {
    Session session = newSession(plainServer.getServer(), MessageSecurityMode.SignAndEncrypt);

    CallMethodResult result = call(session, "NoSuchGroup");

    assertEquals(StatusCodes.Bad_NotFound, result.getStatusCode().getValue());
  }

  @Test
  void nullSecurityGroupIdIsNotFound() {
    Session session = newSession(plainServer.getServer(), MessageSecurityMode.SignAndEncrypt);

    CallMethodResult result =
        call(() -> Optional.of(session), Variant.NULL_VALUE, uint(0), uint(0));

    assertEquals(StatusCodes.Bad_NotFound, result.getStatusCode().getValue());
  }

  @Test
  void roleMappedCallerWithAccessRoleGetsKeys() {
    Session session = newSession(roleMappedServer.getServer(), MessageSecurityMode.SignAndEncrypt);

    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAccess));
    CallMethodResult result = call(session, "GroupA");

    assertTrue(result.getStatusCode().isGood());
  }

  @Test
  void roleMappedCallerWithoutRolesIsDenied() {
    Session session = newSession(roleMappedServer.getServer(), MessageSecurityMode.SignAndEncrypt);

    roleMapper.setRoleIds(List.of());
    CallMethodResult result = call(session, "GroupA");

    assertEquals(StatusCodes.Bad_UserAccessDenied, result.getStatusCode().getValue());
  }

  @Test
  void authorizationRunsBeforeExistence() {
    Session session = newSession(roleMappedServer.getServer(), MessageSecurityMode.SignAndEncrypt);

    // an unauthorized caller probing an unknown group id learns nothing about existence
    roleMapper.setRoleIds(List.of());
    CallMethodResult denied = call(session, "NoSuchGroup");
    assertEquals(StatusCodes.Bad_UserAccessDenied, denied.getStatusCode().getValue());

    // an authorized caller gets the existence answer
    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAccess));
    CallMethodResult notFound = call(session, "NoSuchGroup");
    assertEquals(StatusCodes.Bad_NotFound, notFound.getStatusCode().getValue());
  }

  @Test
  void perGroupRolePermissionsGovernRestrictedGroup() {
    Session session = newSession(roleMappedServer.getServer(), MessageSecurityMode.SignAndEncrypt);

    roleMapper.setRoleIds(List.of(CUSTOM_ROLE));
    CallMethodResult granted = call(session, "Restricted");
    assertTrue(granted.getStatusCode().isGood());

    // the default pull role does not bypass the explicit per-group list (§8.3.2)
    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAccess));
    CallMethodResult denied = call(session, "Restricted");
    assertEquals(StatusCodes.Bad_UserAccessDenied, denied.getStatusCode().getValue());
  }

  @Test
  void internalInvocationBypassesChannelAndAuthorizationChecks() {
    CallMethodResult result =
        call(AccessContext.INTERNAL, new Variant("Restricted"), uint(0), uint(0));

    assertTrue(result.getStatusCode().isGood());
  }
}
