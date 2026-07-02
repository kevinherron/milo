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

import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.OPEN;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.TIMEOUT;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.call;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.connect;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.server.RoleMapper;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.junit.jupiter.api.Test;

/**
 * Client-driven authorization posture for the remote-configuration file model: {@link
 * PubSubMethodAuthorizer#checkConfigure} governs every FileType method, mapping a {@code DENY} to
 * {@code Bad_UserAccessDenied} on the wire.
 *
 * <p>Each test starts its own {@link TestSksServer} because the {@code RoleMapper} is a server-wide
 * setting: the fixtures differ in whether a {@link RoleMapper} is configured (well-known {@code
 * ConfigureAdmin} governs) or not (the allow-when-unconfigured default posture applies unless a
 * custom authorizer overrides it).
 */
class RemoteConfigurationAuthorizationClientTest {

  private static final int MODE_READ = 0x01;

  @Test
  void defaultPostureWithoutARoleMapperAllowsConfiguration() throws Exception {
    try (TestSksServer sks = TestSksServer.create()) {
      ServerPubSub serverPubSub =
          ServerPubSub.attach(
              sks.getServer(),
              PubSubConfig.builder().build(),
              ServerPubSubOptions.builder().allowRemoteConfiguration(true).build());
      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      try {
        OpcUaClient client = connect(sks);
        try {
          // no RoleMapper + explicitly enabled remote config: checkConfigure allows
          CallMethodResult result = call(client, OPEN, new Variant(ubyte(MODE_READ)));
          assertTrue(result.getStatusCode().isGood(), result.toString());
        } finally {
          client.disconnect();
        }
      } finally {
        serverPubSub.close();
      }
    }
  }

  @Test
  void aDenyingAuthorizerRejectsFileMethodsWithUserAccessDenied() throws Exception {
    try (TestSksServer sks = TestSksServer.create()) {
      ServerPubSubOptions options =
          ServerPubSubOptions.builder()
              .allowRemoteConfiguration(true)
              .methodAuthorizer(DenyingAuthorizer.INSTANCE)
              .build();
      ServerPubSub serverPubSub =
          ServerPubSub.attach(sks.getServer(), PubSubConfig.builder().build(), options);
      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      try {
        OpcUaClient client = connect(sks);
        try {
          CallMethodResult result = call(client, OPEN, new Variant(ubyte(MODE_READ)));
          assertEquals(StatusCodes.Bad_UserAccessDenied, result.getStatusCode().getValue());
        } finally {
          client.disconnect();
        }
      } finally {
        serverPubSub.close();
      }
    }
  }

  @Test
  void aRoleMappedSessionWithoutConfigureAdminIsDenied() throws Exception {
    var roleMapper = new TestRoleMapper();
    roleMapper.setRoleIds(List.of()); // no roles: not ConfigureAdmin

    try (TestSksServer sks = TestSksServer.create(roleMapper)) {
      ServerPubSub serverPubSub =
          ServerPubSub.attach(
              sks.getServer(),
              PubSubConfig.builder().build(),
              ServerPubSubOptions.builder().allowRemoteConfiguration(true).build());
      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      try {
        OpcUaClient client = connect(sks);
        try {
          CallMethodResult result = call(client, OPEN, new Variant(ubyte(MODE_READ)));
          assertEquals(StatusCodes.Bad_UserAccessDenied, result.getStatusCode().getValue());
        } finally {
          client.disconnect();
        }
      } finally {
        serverPubSub.close();
      }
    }
  }

  @Test
  void aRoleMappedSessionWithConfigureAdminIsAllowed() throws Exception {
    var roleMapper = new TestRoleMapper();
    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_ConfigureAdmin));

    try (TestSksServer sks = TestSksServer.create(roleMapper)) {
      ServerPubSub serverPubSub =
          ServerPubSub.attach(
              sks.getServer(),
              PubSubConfig.builder().build(),
              ServerPubSubOptions.builder().allowRemoteConfiguration(true).build());
      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      try {
        OpcUaClient client = connect(sks);
        try {
          CallMethodResult result = call(client, OPEN, new Variant(ubyte(MODE_READ)));
          assertTrue(result.getStatusCode().isGood(), result.toString());
        } finally {
          client.disconnect();
        }
      } finally {
        serverPubSub.close();
      }
    }
  }
}
