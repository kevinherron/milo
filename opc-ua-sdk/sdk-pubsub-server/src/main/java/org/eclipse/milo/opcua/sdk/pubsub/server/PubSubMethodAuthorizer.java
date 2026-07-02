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
 * Authorization seam consulted by every PubSub method handler {@link ServerPubSub} installs: one
 * check per Part 14 authorization category, each answering only the <em>user-authorization</em>
 * question for the calling {@link Session}.
 *
 * <p>Channel-mode requirements are deliberately not part of this SPI — the handlers enforce them
 * separately, before consulting the authorizer, and map violations to {@code
 * Bad_SecurityModeInsufficient} (key transfer requires an encrypted channel per §8.3.2/§9.1.3.3;
 * SKS management requires at least a signed channel per §8.4-§8.7). A {@link Decision#DENY} from
 * any check is mapped by the handlers to {@code Bad_UserAccessDenied}.
 *
 * <p>Set a custom implementation via {@link ServerPubSubOptions.Builder#methodAuthorizer}; when
 * none is set, {@link #defaultAuthorizer()} applies. The default posture (Part 3 §4.9.2 well-known
 * roles when role mapping is available, the core Milo allow-when-unconfigured posture otherwise):
 *
 * <ul>
 *   <li>If the server has a {@code RoleMapper} configured ({@link Session#getRoleIds()} present),
 *       the well-known roles govern: {@code ConfigureAdmin} ({@code i=15716}) for {@link
 *       #checkConfigure}, {@code SecurityKeyServerAdmin} ({@code i=25565}) for {@link
 *       #checkSksAdmin}, and {@code SecurityKeyServerAccess} ({@code i=25603}) for {@link
 *       #checkKeyAccess} — except that a SecurityGroup with a non-empty {@link
 *       SecurityGroupConfig#getRolePermissions() RolePermissions} list is governed exclusively by
 *       that list (Part 14 §8.3.2: an entry whose role is mapped to the session must carry the
 *       {@code Call} permission bit).
 *   <li>If no {@code RoleMapper} is configured: {@link #checkConfigure} and {@link #checkSksAdmin}
 *       allow (matching the core SDK's allow-when-unconfigured posture — the surfaces they guard
 *       are themselves opt-in), and {@link #checkKeyAccess} allows any caller when the group's
 *       RolePermissions list is empty but <b>denies</b> when it is non-empty: an explicit
 *       restriction that cannot be evaluated fails closed.
 * </ul>
 *
 * <p>{@link #checkKeyAccess} is consulted by the {@code GetSecurityKeys} handler installed when
 * {@link ServerPubSubOptions.Builder#sksServerEnabled} is set. {@link #checkConfigure} (remote
 * configuration) and {@link #checkSksAdmin} (SecurityGroup/push-target management) are not yet
 * consulted by any handler shipped in this version; they are part of the SPI so implementations
 * written today remain valid when those surfaces arrive.
 */
public interface PubSubMethodAuthorizer {

  /** The result of an authorization check. */
  enum Decision {
    /** The caller is authorized; the handler proceeds. */
    ALLOW,
    /** The caller is not authorized; the handler fails with {@code Bad_UserAccessDenied}. */
    DENY
  }

  /**
   * Check whether {@code session} is authorized to modify the PubSub configuration (Part 14
   * §9.1.4-§9.1.11: "The Client shall be authorized to modify the configuration for the PubSub
   * functionality").
   *
   * @param session the calling {@link Session}.
   * @return the {@link Decision}.
   */
  Decision checkConfigure(Session session);

  /**
   * Check whether {@code session} is authorized to modify the configuration for the Security Key
   * Service functionality (Part 14 §8.4-§8.7: SecurityGroup and push-target management).
   *
   * <p>Handlers consulting this check additionally require at least a signed communication channel
   * ({@code Bad_SecurityModeInsufficient} otherwise); that check is not this SPI's.
   *
   * @param session the calling {@link Session}.
   * @return the {@link Decision}.
   */
  Decision checkSksAdmin(Session session);

  /**
   * Check whether {@code session} is authorized to access the security keys of a SecurityGroup
   * through {@code GetSecurityKeys} (Part 14 §8.3.2).
   *
   * <p>This check runs <em>before</em> the handler's existence check, so an unauthorized caller
   * cannot probe SecurityGroupIds: {@code securityGroup} is {@code null} when the id names no
   * SecurityGroup known to the server, and a {@link Decision#DENY} for an unknown group yields
   * {@code Bad_UserAccessDenied} rather than {@code Bad_NotFound}.
   *
   * @param session the calling {@link Session}.
   * @param securityGroupId the SecurityGroupId method argument; possibly {@code null} if the caller
   *     passed a null value.
   * @param securityGroup the resolved {@link SecurityGroupConfig}, or {@code null} if {@code
   *     securityGroupId} is unknown.
   * @return the {@link Decision}.
   */
  Decision checkKeyAccess(
      Session session,
      @Nullable String securityGroupId,
      @Nullable SecurityGroupConfig securityGroup);

  /**
   * Get the default {@link PubSubMethodAuthorizer}, implementing the posture described in the class
   * documentation.
   *
   * @return the default {@link PubSubMethodAuthorizer}.
   */
  static PubSubMethodAuthorizer defaultAuthorizer() {
    return DefaultPubSubMethodAuthorizer.INSTANCE;
  }
}
