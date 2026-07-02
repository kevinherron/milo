/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.eclipse.milo.opcua.stack.core.security.SecurityAlgorithm;
import org.junit.jupiter.api.Test;

/**
 * {@link PubSubSecurityPolicy}: the Part 14 §7.2.4.4.3 parameter table asserted literally — URIs,
 * key part lengths (Table 155), nonce lengths (Tables 156/157), and signature length — so any
 * regression against the pinned K1 table fails here byte-count by byte-count.
 */
class PubSubSecurityPolicyTest {

  @Test
  void aes128CtrParameterTable() {
    PubSubSecurityPolicy policy = PubSubSecurityPolicy.Aes128Ctr;

    assertEquals("http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR", policy.getUri());
    assertEquals(SecurityAlgorithm.HmacSha256, policy.getSymmetricSignatureAlgorithm());
    assertEquals(SecurityAlgorithm.Aes128Ctr, policy.getSymmetricEncryptionAlgorithm());
    assertEquals(32, policy.getSigningKeyLength());
    assertEquals(16, policy.getEncryptingKeyLength());
    assertEquals(4, policy.getKeyNonceLength());
    assertEquals(52, policy.getKeyDataLength());
    assertEquals(8, policy.getMessageNonceLength());
    assertEquals(32, policy.getSignatureLength());
  }

  @Test
  void aes256CtrParameterTable() {
    PubSubSecurityPolicy policy = PubSubSecurityPolicy.Aes256Ctr;

    assertEquals("http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR", policy.getUri());
    assertEquals(SecurityAlgorithm.HmacSha256, policy.getSymmetricSignatureAlgorithm());
    assertEquals(SecurityAlgorithm.Aes256Ctr, policy.getSymmetricEncryptionAlgorithm());
    assertEquals(32, policy.getSigningKeyLength());
    assertEquals(32, policy.getEncryptingKeyLength());
    assertEquals(4, policy.getKeyNonceLength());
    assertEquals(68, policy.getKeyDataLength());
    assertEquals(8, policy.getMessageNonceLength());
    assertEquals(32, policy.getSignatureLength());
  }

  @Test
  void encryptionAlgorithmsResolveToAesCtrTransformations() {
    // The K1 pin includes the stack-core SecurityAlgorithm additions the table points at.
    assertEquals(
        "http://opcfoundation.org/UA/security/aes128-ctr", SecurityAlgorithm.Aes128Ctr.getUri());
    assertEquals(
        "http://opcfoundation.org/UA/security/aes256-ctr", SecurityAlgorithm.Aes256Ctr.getUri());
    assertEquals("AES/CTR/NoPadding", SecurityAlgorithm.Aes128Ctr.getTransformation());
    assertEquals("AES/CTR/NoPadding", SecurityAlgorithm.Aes256Ctr.getTransformation());
    assertEquals("HmacSHA256", SecurityAlgorithm.HmacSha256.getTransformation());
  }

  @Test
  void fromUriRoundTripsBothPolicies() {
    for (PubSubSecurityPolicy policy : PubSubSecurityPolicy.values()) {
      assertEquals(Optional.of(policy), PubSubSecurityPolicy.fromUri(policy.getUri()));
    }
  }

  @Test
  void fromUriIsEmptyForUnsupportedUris() {
    // Non-exceptional miss (the K8 fetch-failure path), including client/server policies.
    assertTrue(
        PubSubSecurityPolicy.fromUri("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
            .isEmpty());
    assertTrue(
        PubSubSecurityPolicy.fromUri("http://opcfoundation.org/UA/SecurityPolicy#None").isEmpty());
    assertTrue(
        PubSubSecurityPolicy.fromUri("http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-ctr")
            .isEmpty()); // case-sensitive
    assertTrue(PubSubSecurityPolicy.fromUri("").isEmpty());
  }

  @Test
  void exactlyTheTwoK2PoliciesAreDefined() {
    // K2 ships the full subset: both policies, nothing else. A new constant must revisit the
    // parameter-table assumptions pinned across the security tests.
    assertEquals(2, PubSubSecurityPolicy.values().length);
  }
}
