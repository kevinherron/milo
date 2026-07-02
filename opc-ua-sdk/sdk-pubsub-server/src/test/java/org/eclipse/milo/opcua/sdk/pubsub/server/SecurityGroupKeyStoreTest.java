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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfigValidationException;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@link SecurityGroupKeyStore} rotation, window, and slice semantics (Part 14 §8.3.2), driven
 * through the {@link InstantSource} test seam so no test waits on real time.
 *
 * <p>The canonical fixture group uses KeyLifetime PT1H, MaxFutureKeyCount 3, MaxPastKeyCount 2,
 * PubSub-Aes128-CTR (52-byte key data).
 */
class SecurityGroupKeyStoreTest {

  private static final Instant T0 = Instant.parse("2026-07-01T00:00:00Z");
  private static final Duration LIFETIME = Duration.ofHours(1);

  private static ScheduledExecutorService scheduler;

  @BeforeAll
  static void createScheduler() {
    scheduler = Executors.newSingleThreadScheduledExecutor();
  }

  @AfterAll
  static void shutdownScheduler() {
    scheduler.shutdownNow();
  }

  /** A settable {@link InstantSource}. */
  private static final class TestClock implements InstantSource {

    private volatile Instant now = T0;

    @Override
    public Instant instant() {
      return now;
    }

    void advance(Duration duration) {
      now = now.plus(duration);
    }
  }

  private static SecurityGroupConfig canonicalGroup() {
    return SecurityGroupConfig.builder("TestGroup")
        .securityPolicyUri(PubSubSecurityPolicy.Aes128Ctr.getUri())
        .keyLifeTime(LIFETIME)
        .maxFutureKeyCount(uint(3))
        .maxPastKeyCount(uint(2))
        .build();
  }

  private static SecurityGroupKeyStore newStore(TestClock clock, SecurityGroupConfig... groups) {
    return new SecurityGroupKeyStore(List.of(groups), scheduler, clock);
  }

  @Test
  void currentSliceAtCreation() {
    var store = newStore(new TestClock(), canonicalGroup());

    SecurityKeySet keySet = store.getSecurityKeys("TestGroup", uint(0), uint(0));

    assertNotNull(keySet);
    assertEquals(PubSubSecurityPolicy.Aes128Ctr.getUri(), keySet.securityPolicyUri());
    assertEquals(uint(1), keySet.firstTokenId());
    assertEquals(1, keySet.keys().size());
    assertEquals(52, keySet.keys().get(0).length());
    assertEquals(LIFETIME, keySet.timeToNextKey());
    assertEquals(LIFETIME, keySet.keyLifetime());
  }

  @Test
  void requestedFutureKeysAreReturnedAndClampedToWindow() {
    var store = newStore(new TestClock(), canonicalGroup());

    SecurityKeySet twoFutures = store.getSecurityKeys("TestGroup", uint(0), uint(2));
    assertNotNull(twoFutures);
    assertEquals(uint(1), twoFutures.firstTokenId());
    assertEquals(3, twoFutures.keys().size());

    // MaxFutureKeyCount 3 clamps a larger request to current + 3 future keys
    SecurityKeySet clamped = store.getSecurityKeys("TestGroup", uint(0), uint(10));
    assertNotNull(clamped);
    assertEquals(uint(1), clamped.firstTokenId());
    assertEquals(4, clamped.keys().size());
  }

  @Test
  void tokenIdAdvancesWithTimeAndTimeToNextKeyShrinks() {
    var clock = new TestClock();
    var store = newStore(clock, canonicalGroup());

    clock.advance(Duration.ofMinutes(90));

    SecurityKeySet keySet = store.getSecurityKeys("TestGroup", uint(0), uint(0));

    assertNotNull(keySet);
    assertEquals(uint(2), keySet.firstTokenId());
    assertEquals(Duration.ofMinutes(30), keySet.timeToNextKey());
    assertEquals(LIFETIME, keySet.keyLifetime());
  }

  @Test
  void keysAreStableAcrossCallsAndRotation() {
    var clock = new TestClock();
    var store = newStore(clock, canonicalGroup());

    SecurityKeySet initial = store.getSecurityKeys("TestGroup", uint(0), uint(3));
    assertNotNull(initial);
    ByteString token2Key = initial.keys().get(1);

    // the same token yields the same key on a repeated call...
    SecurityKeySet repeat = store.getSecurityKeys("TestGroup", uint(0), uint(3));
    assertNotNull(repeat);
    assertEquals(initial.keys(), repeat.keys());

    // ...and after rotation the previously-announced future key becomes current
    clock.advance(LIFETIME);
    SecurityKeySet rotated = store.getSecurityKeys("TestGroup", uint(0), uint(0));
    assertNotNull(rotated);
    assertEquals(uint(2), rotated.firstTokenId());
    assertEquals(token2Key, rotated.keys().get(0));
  }

  @Test
  void pastKeysAreServedWithinMaxPastKeyCountAndClampedBelowIt() {
    var clock = new TestClock();
    var store = newStore(clock, canonicalGroup());

    // materialize token 4's key while it is a future key, so history can be compared
    SecurityKeySet early = store.getSecurityKeys("TestGroup", uint(0), uint(3));
    assertNotNull(early);
    ByteString token4Key = early.keys().get(3);

    clock.advance(Duration.ofHours(5)); // current token = 6, retained history = {4, 5}

    SecurityKeySet past = store.getSecurityKeys("TestGroup", uint(4), uint(1));
    assertNotNull(past);
    assertEquals(uint(4), past.firstTokenId());
    assertEquals(2, past.keys().size());
    assertEquals(token4Key, past.keys().get(0));

    // a starting token older than the retained history clamps up to the oldest retained
    SecurityKeySet clamped = store.getSecurityKeys("TestGroup", uint(1), uint(0));
    assertNotNull(clamped);
    assertEquals(uint(4), clamped.firstTokenId());
    assertEquals(1, clamped.keys().size());
  }

  @Test
  void futureStartingTokenIdClampsToWindowEdge() {
    var clock = new TestClock();
    var store = newStore(clock, canonicalGroup());

    clock.advance(Duration.ofHours(5)); // current token = 6, future edge = 9

    SecurityKeySet keySet = store.getSecurityKeys("TestGroup", uint(100), uint(5));

    assertNotNull(keySet);
    assertEquals(uint(9), keySet.firstTokenId());
    assertEquals(1, keySet.keys().size());
  }

  @Test
  void maxPastKeyCountZeroRetainsNoHistory() {
    var clock = new TestClock();
    var group =
        SecurityGroupConfig.builder("NoHistory")
            .securityPolicyUri(PubSubSecurityPolicy.Aes128Ctr.getUri())
            .keyLifeTime(LIFETIME)
            .maxFutureKeyCount(uint(3))
            .maxPastKeyCount(uint(0))
            .build();
    var store = newStore(clock, group);

    clock.advance(LIFETIME); // current token = 2

    SecurityKeySet keySet = store.getSecurityKeys("NoHistory", uint(1), uint(0));

    assertNotNull(keySet);
    assertEquals(uint(2), keySet.firstTokenId());
  }

  @Test
  void tokenIdsAreMonotonicAcrossRotations() {
    var clock = new TestClock();
    var store = newStore(clock, canonicalGroup());

    long previous = 0;
    for (int i = 0; i < 5; i++) {
      SecurityKeySet keySet = store.getSecurityKeys("TestGroup", uint(0), uint(0));
      assertNotNull(keySet);

      long current = keySet.firstTokenId().longValue();
      assertTrue(current > previous, "token ids must be monotonically increasing");
      previous = current;

      clock.advance(LIFETIME);
    }
  }

  @Test
  void unknownSecurityGroupIdReturnsNull() {
    var store = newStore(new TestClock(), canonicalGroup());

    assertNull(store.getSecurityKeys("NoSuchGroup", uint(0), uint(0)));
    assertNull(store.getGroup("NoSuchGroup"));
    assertNotNull(store.getGroup("TestGroup"));
  }

  @Test
  void nullPolicyUriDefaultsToAes256Ctr() {
    var group = SecurityGroupConfig.builder("Defaults").keyLifeTime(LIFETIME).build();
    var store = newStore(new TestClock(), group);

    SecurityKeySet keySet = store.getSecurityKeys("Defaults", uint(0), uint(0));

    assertNotNull(keySet);
    assertEquals(PubSubSecurityPolicy.Aes256Ctr.getUri(), keySet.securityPolicyUri());
    assertEquals(68, keySet.keys().get(0).length());
  }

  @Test
  void zeroKeyLifetimeDefaultsToOneHour() {
    var group = SecurityGroupConfig.builder("ZeroLifetime").keyLifeTime(Duration.ZERO).build();
    var store = newStore(new TestClock(), group);

    SecurityKeySet keySet = store.getSecurityKeys("ZeroLifetime", uint(0), uint(0));

    assertNotNull(keySet);
    assertEquals(Duration.ofHours(1), keySet.keyLifetime());
  }

  @Test
  void zeroMaxFutureKeyCountUsesDefaultOfTen() {
    var group =
        SecurityGroupConfig.builder("DefaultWindow")
            .securityPolicyUri(PubSubSecurityPolicy.Aes128Ctr.getUri())
            .keyLifeTime(LIFETIME)
            .build();
    var store = newStore(new TestClock(), group);

    SecurityKeySet keySet = store.getSecurityKeys("DefaultWindow", uint(0), uint(100));

    assertNotNull(keySet);
    assertEquals(11, keySet.keys().size());
  }

  @Test
  void unsupportedPolicyUriFailsConstruction() {
    var group =
        SecurityGroupConfig.builder("BadPolicy")
            .securityPolicyUri("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
            .build();

    assertThrows(PubSubConfigValidationException.class, () -> newStore(new TestClock(), group));
  }

  @Test
  void duplicateSecurityGroupIdFailsConstruction() {
    var group1 = SecurityGroupConfig.builder("GroupOne").securityGroupId("dup").build();
    var group2 = SecurityGroupConfig.builder("GroupTwo").securityGroupId("dup").build();

    assertThrows(
        PubSubConfigValidationException.class, () -> newStore(new TestClock(), group1, group2));
  }

  @Test
  void startupAndShutdownAreIdempotentAndStoreRemainsReadable() {
    var store = newStore(new TestClock(), canonicalGroup());

    store.startup();
    store.startup();
    store.shutdown();
    store.shutdown();

    assertNotNull(store.getSecurityKeys("TestGroup", uint(0), uint(0)));
  }
}
