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

import java.time.Duration;
import java.util.List;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.server.PubSubMethodAuthorizer.Decision;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.SecurityConfiguration;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.PermissionType;
import org.eclipse.milo.opcua.stack.core.types.structured.RolePermissionType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@link DefaultPubSubMethodAuthorizer} posture matrix (K17.3): well-known roles when a RoleMapper
 * is configured, allow-when-unconfigured otherwise, fail-closed on per-group RolePermissions that
 * cannot be evaluated.
 *
 * <p>Role presence flows through the real {@code Session.getRoleIds()} path: one fixture server has
 * no RoleMapper, the other is configured with a {@link TestRoleMapper} whose role list is set per
 * test.
 */
class DefaultPubSubMethodAuthorizerTest {

  private static final NodeId CUSTOM_ROLE = new NodeId(2, "CustomRole");

  private static final PubSubMethodAuthorizer AUTHORIZER =
      PubSubMethodAuthorizer.defaultAuthorizer();

  private static TestPubSubServer plainServer;
  private static TestPubSubServer roleMappedServer;
  private static TestRoleMapper roleMapper;

  @BeforeAll
  static void startServers() {
    plainServer = TestPubSubServer.create();
    roleMapper = new TestRoleMapper();
    roleMappedServer = TestPubSubServer.create(roleMapper);
  }

  @AfterAll
  static void stopServers() {
    plainServer.close();
    roleMappedServer.close();
  }

  private static Session newSession(OpcUaServer server) {
    var applicationDescription =
        new ApplicationDescription(
            "urn:eclipse:milo:pubsub:test-client",
            "urn:eclipse:milo:pubsub:test-client",
            LocalizedText.english("test client"),
            ApplicationType.Client,
            null,
            null,
            null);

    var endpoint =
        new EndpointDescription(
            "opc.tcp://localhost:0",
            applicationDescription,
            ByteString.NULL_VALUE,
            MessageSecurityMode.SignAndEncrypt,
            SecurityPolicy.Basic256Sha256.getUri(),
            null,
            null,
            ubyte(0));

    var securityConfiguration =
        new SecurityConfiguration(
            SecurityPolicy.Basic256Sha256,
            MessageSecurityMode.SignAndEncrypt,
            null,
            null,
            null,
            null,
            null);

    return new Session(
        server,
        new NodeId(1, "authorizer-test-session-" + System.nanoTime()),
        "authorizer-test-session",
        Duration.ofMinutes(5),
        applicationDescription,
        "urn:eclipse:milo:pubsub:test-server",
        uint(0),
        endpoint,
        1L,
        securityConfiguration);
  }

  private static SecurityGroupConfig unrestrictedGroup() {
    return SecurityGroupConfig.builder("Unrestricted").build();
  }

  private static SecurityGroupConfig restrictedGroup(RolePermissionType... rolePermissions) {
    return SecurityGroupConfig.builder("Restricted")
        .rolePermissions(List.of(rolePermissions))
        .build();
  }

  private static RolePermissionType callPermission(NodeId roleId) {
    return new RolePermissionType(roleId, PermissionType.of(PermissionType.Field.Call));
  }

  @Test
  void noRoleMapperConfigureAndSksAdminAllow() {
    Session session = newSession(plainServer.getServer());

    assertEquals(Decision.ALLOW, AUTHORIZER.checkConfigure(session));
    assertEquals(Decision.ALLOW, AUTHORIZER.checkSksAdmin(session));
  }

  @Test
  void noRoleMapperKeyAccessAllowsWhenGroupUnrestricted() {
    Session session = newSession(plainServer.getServer());

    assertEquals(
        Decision.ALLOW, AUTHORIZER.checkKeyAccess(session, "Unrestricted", unrestrictedGroup()));
  }

  @Test
  void noRoleMapperKeyAccessFailsClosedOnExplicitRolePermissions() {
    Session session = newSession(plainServer.getServer());

    assertEquals(
        Decision.DENY,
        AUTHORIZER.checkKeyAccess(
            session, "Restricted", restrictedGroup(callPermission(CUSTOM_ROLE))));
  }

  @Test
  void noRoleMapperKeyAccessAllowsForUnknownGroup() {
    // an unknown group has no explicit restrictions; the handler surfaces Bad_NotFound after
    Session session = newSession(plainServer.getServer());

    assertEquals(Decision.ALLOW, AUTHORIZER.checkKeyAccess(session, "NoSuchGroup", null));
  }

  @Test
  void roleMapperConfigureRequiresConfigureAdmin() {
    Session session = newSession(roleMappedServer.getServer());

    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_ConfigureAdmin));
    assertEquals(Decision.ALLOW, AUTHORIZER.checkConfigure(session));

    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAdmin));
    assertEquals(Decision.DENY, AUTHORIZER.checkConfigure(session));

    roleMapper.setRoleIds(List.of());
    assertEquals(Decision.DENY, AUTHORIZER.checkConfigure(session));
  }

  @Test
  void roleMapperSksAdminRequiresSecurityKeyServerAdmin() {
    Session session = newSession(roleMappedServer.getServer());

    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAdmin));
    assertEquals(Decision.ALLOW, AUTHORIZER.checkSksAdmin(session));

    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_ConfigureAdmin));
    assertEquals(Decision.DENY, AUTHORIZER.checkSksAdmin(session));
  }

  @Test
  void roleMapperKeyAccessDefaultsToSecurityKeyServerAccess() {
    Session session = newSession(roleMappedServer.getServer());
    SecurityGroupConfig group = unrestrictedGroup();

    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAccess));
    assertEquals(Decision.ALLOW, AUTHORIZER.checkKeyAccess(session, "Unrestricted", group));

    // an empty mapped-role list is not the same as no RoleMapper: the check runs and denies
    roleMapper.setRoleIds(List.of());
    assertEquals(Decision.DENY, AUTHORIZER.checkKeyAccess(session, "Unrestricted", group));

    // the admin role manages groups; it is not the default pull role
    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAdmin));
    assertEquals(Decision.DENY, AUTHORIZER.checkKeyAccess(session, "Unrestricted", group));
  }

  @Test
  void roleMapperExplicitRolePermissionsGovernExclusively() {
    Session session = newSession(roleMappedServer.getServer());
    SecurityGroupConfig group = restrictedGroup(callPermission(CUSTOM_ROLE));

    roleMapper.setRoleIds(List.of(CUSTOM_ROLE));
    assertEquals(Decision.ALLOW, AUTHORIZER.checkKeyAccess(session, "Restricted", group));

    roleMapper.setRoleIds(List.of(new NodeId(2, "OtherRole")));
    assertEquals(Decision.DENY, AUTHORIZER.checkKeyAccess(session, "Restricted", group));

    // the default pull role does not bypass an explicit per-group list (§8.3.2)
    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAccess));
    assertEquals(Decision.DENY, AUTHORIZER.checkKeyAccess(session, "Restricted", group));
  }

  @Test
  void roleMapperRolePermissionsEntryWithoutCallBitDenies() {
    Session session = newSession(roleMappedServer.getServer());
    SecurityGroupConfig group =
        restrictedGroup(
            new RolePermissionType(CUSTOM_ROLE, PermissionType.of(PermissionType.Field.Browse)));

    roleMapper.setRoleIds(List.of(CUSTOM_ROLE));
    assertEquals(Decision.DENY, AUTHORIZER.checkKeyAccess(session, "Restricted", group));
  }

  @Test
  void roleMapperUnknownGroupIsDecidedByDefaultRole() {
    Session session = newSession(roleMappedServer.getServer());

    roleMapper.setRoleIds(List.of());
    assertEquals(Decision.DENY, AUTHORIZER.checkKeyAccess(session, "NoSuchGroup", null));

    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_SecurityKeyServerAccess));
    assertEquals(Decision.ALLOW, AUTHORIZER.checkKeyAccess(session, "NoSuchGroup", null));
  }
}
