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

import java.util.List;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupRef;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.structured.SecurityGroupDataType;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link RemoteConfigurationServer#securityGroupsToInvalidate} (Part 14 §6.2.12.2):
 * only a {@code SecurityPolicyUri} or {@code KeyLifetime} change invalidates a SecurityGroup's
 * keys, and only for a group present before and after the change.
 */
class SecurityGroupInvalidationTest {

  private static final Double LIFETIME_1H = 3_600_000.0;
  private static final Double LIFETIME_30M = 1_800_000.0;
  private static final String AES256 =
      "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR";
  private static final String AES128 =
      "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR";

  /** A SecurityGroup with the security-relevant fields set and a settable MaxPastKeyCount. */
  private static SecurityGroupDataType sg(
      String name, Double keyLifetime, String policyUri, UInteger maxPastKeyCount) {
    return new SecurityGroupDataType(
        name, null, keyLifetime, policyUri, uint(10), maxPastKeyCount, name, null, null);
  }

  @Test
  void securityPolicyUriChangeInvalidates() {
    var old = new SecurityGroupDataType[] {sg("sg", LIFETIME_1H, AES256, uint(0))};
    var updated = new SecurityGroupDataType[] {sg("sg", LIFETIME_1H, AES128, uint(0))};

    assertEquals(
        List.of(new SecurityGroupRef("sg")),
        RemoteConfigurationServer.securityGroupsToInvalidate(old, updated));
  }

  @Test
  void keyLifetimeChangeInvalidates() {
    var old = new SecurityGroupDataType[] {sg("sg", LIFETIME_1H, AES256, uint(0))};
    var updated = new SecurityGroupDataType[] {sg("sg", LIFETIME_30M, AES256, uint(0))};

    assertEquals(
        List.of(new SecurityGroupRef("sg")),
        RemoteConfigurationServer.securityGroupsToInvalidate(old, updated));
  }

  @Test
  void unrelatedFieldChangeDoesNotInvalidate() {
    // only MaxPastKeyCount changes: policy and lifetime are untouched, so the keys stay valid
    var old = new SecurityGroupDataType[] {sg("sg", LIFETIME_1H, AES256, uint(0))};
    var updated = new SecurityGroupDataType[] {sg("sg", LIFETIME_1H, AES256, uint(5))};

    assertEquals(List.of(), RemoteConfigurationServer.securityGroupsToInvalidate(old, updated));
  }

  @Test
  void identicalGroupsDoNotInvalidate() {
    var old = new SecurityGroupDataType[] {sg("sg", LIFETIME_1H, AES256, uint(0))};
    var updated = new SecurityGroupDataType[] {sg("sg", LIFETIME_1H, AES256, uint(0))};

    assertEquals(List.of(), RemoteConfigurationServer.securityGroupsToInvalidate(old, updated));
  }

  @Test
  void addedAndRemovedGroupsAreNotInvalidated() {
    // "removed" is only in old (its consumers unregister via the reconfigure); "added" is only in
    // new (no prior keys). Neither is a modification of an existing group.
    var old = new SecurityGroupDataType[] {sg("removed", LIFETIME_1H, AES256, uint(0))};
    var updated = new SecurityGroupDataType[] {sg("added", LIFETIME_1H, AES256, uint(0))};

    assertEquals(List.of(), RemoteConfigurationServer.securityGroupsToInvalidate(old, updated));
  }

  @Test
  void nullArraysYieldNothing() {
    assertEquals(List.of(), RemoteConfigurationServer.securityGroupsToInvalidate(null, null));
    assertEquals(
        List.of(),
        RemoteConfigurationServer.securityGroupsToInvalidate(
            null, new SecurityGroupDataType[] {sg("sg", LIFETIME_1H, AES256, uint(0))}));
  }
}
