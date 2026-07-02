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

import java.util.List;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.structured.PermissionType;
import org.eclipse.milo.opcua.stack.core.types.structured.RolePermissionType;
import org.jspecify.annotations.Nullable;

/**
 * The default {@link PubSubMethodAuthorizer}: well-known roles when the server has a {@code
 * RoleMapper} configured, the core Milo allow-when-unconfigured posture otherwise, and fail-closed
 * on per-SecurityGroup RolePermissions that cannot be evaluated.
 *
 * <p>See {@link PubSubMethodAuthorizer} for the full posture description. Role NodeIds are compared
 * by plain equality against the well-known role ids of OPC UA Part 3 §4.9.2 / Part 14 §8.8; they
 * are never resolved against the address space, so enforcement works without a RoleSet.
 */
final class DefaultPubSubMethodAuthorizer implements PubSubMethodAuthorizer {

  static final DefaultPubSubMethodAuthorizer INSTANCE = new DefaultPubSubMethodAuthorizer();

  private DefaultPubSubMethodAuthorizer() {}

  @Override
  public Decision checkConfigure(Session session) {
    return checkWellKnownRole(session, NodeIds.WellKnownRole_ConfigureAdmin);
  }

  @Override
  public Decision checkSksAdmin(Session session) {
    return checkWellKnownRole(session, NodeIds.WellKnownRole_SecurityKeyServerAdmin);
  }

  @Override
  public Decision checkKeyAccess(
      Session session,
      @Nullable String securityGroupId,
      @Nullable SecurityGroupConfig securityGroup) {

    List<RolePermissionType> rolePermissions =
        securityGroup != null ? securityGroup.getRolePermissions() : List.of();

    return session
        .getRoleIds()
        .map(roleIds -> checkKeyAccessWithRoles(roleIds, rolePermissions))
        .orElseGet(
            () -> {
              // no RoleMapper: allow any caller when the group carries no explicit
              // restrictions (the handler has already enforced the encrypted channel);
              // an explicit RolePermissions list that cannot be evaluated fails closed
              return rolePermissions.isEmpty() ? Decision.ALLOW : Decision.DENY;
            });
  }

  /**
   * The role-mapped key access rule: a non-empty per-group RolePermissions list governs exclusively
   * (Part 14 §8.3.2 — a mapped role must carry the Call permission bit); an empty list falls back
   * to the well-known default pull role SecurityKeyServerAccess (§8.8).
   */
  private static Decision checkKeyAccessWithRoles(
      List<NodeId> roleIds, List<RolePermissionType> rolePermissions) {

    if (rolePermissions.isEmpty()) {
      return roleIds.contains(NodeIds.WellKnownRole_SecurityKeyServerAccess)
          ? Decision.ALLOW
          : Decision.DENY;
    }

    for (RolePermissionType entry : rolePermissions) {
      PermissionType permissions = entry.getPermissions();

      if (permissions != null && permissions.getCall() && roleIds.contains(entry.getRoleId())) {
        return Decision.ALLOW;
      }
    }

    return Decision.DENY;
  }

  /**
   * Allow when no RoleMapper is configured (the guarded surfaces are themselves opt-in); with a
   * RoleMapper, require {@code roleId} among the session's mapped roles.
   */
  private static Decision checkWellKnownRole(Session session, NodeId roleId) {
    return session
        .getRoleIds()
        .map(roleIds -> roleIds.contains(roleId) ? Decision.ALLOW : Decision.DENY)
        .orElse(Decision.ALLOW);
  }
}
