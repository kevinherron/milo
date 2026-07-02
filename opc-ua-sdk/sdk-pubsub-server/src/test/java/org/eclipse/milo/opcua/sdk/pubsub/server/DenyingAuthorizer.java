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

import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.jspecify.annotations.Nullable;

/**
 * A {@link PubSubMethodAuthorizer} that denies every check, letting the client-driven remote-config
 * tests exercise the handler-level {@code Bad_UserAccessDenied} path (pin R9) independently of the
 * server's access-control role machinery: with no {@code RoleMapper} configured the access
 * controller allows the {@code Call}, so the denial that reaches the wire is the one this
 * authorizer returns from inside the handler.
 */
final class DenyingAuthorizer implements PubSubMethodAuthorizer {

  static final DenyingAuthorizer INSTANCE = new DenyingAuthorizer();

  private DenyingAuthorizer() {}

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
      Session session,
      @Nullable String securityGroupId,
      @Nullable SecurityGroupConfig securityGroup) {
    return Decision.DENY;
  }
}
