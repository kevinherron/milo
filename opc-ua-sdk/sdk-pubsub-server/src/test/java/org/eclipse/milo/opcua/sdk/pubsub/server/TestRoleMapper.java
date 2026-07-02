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
import org.eclipse.milo.opcua.sdk.server.RoleMapper;
import org.eclipse.milo.opcua.sdk.server.identity.Identity;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;

/**
 * Minimal {@code RoleMapper} test fixture: maps every identity to a settable static role list.
 *
 * <p>Deliberately a test fixture and not shipped API: Milo ships no {@code RoleMapper}
 * implementation, and the PubSub authorization default posture only needs the
 * configured-vs-unconfigured distinction plus the mapped role ids, both of which this fixture
 * exercises through the real {@code Session.getRoleIds()} path.
 */
final class TestRoleMapper implements RoleMapper {

  private volatile List<NodeId> roleIds = List.of();

  /** Set the roles subsequently mapped to every session. */
  void setRoleIds(List<NodeId> roleIds) {
    this.roleIds = List.copyOf(roleIds);
  }

  @Override
  public List<NodeId> getRoleIds(Identity identity) {
    return roleIds;
  }
}
