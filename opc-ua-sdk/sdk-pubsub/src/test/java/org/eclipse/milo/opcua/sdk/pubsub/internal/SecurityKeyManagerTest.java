/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.internal;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.ComponentType;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupRef;
import org.eclipse.milo.opcua.sdk.pubsub.security.MessageSecurityContext;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyMaterial;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SecurityKeyManager}: fetch/startup wiring, the Part 14 §8.3.2 token switch
 * schedule and FirstTokenId dedup/discard rules, the §6.2.12.2 2x-KeyLifetime staleness rules on
 * both sides, the static-key form, the K8 policy precedence gate, and the K6 unknown-token
 * single-flight refresh. Time is driven through an injected nano clock, so no test waits on key
 * lifetimes; provider fetches run on a real single-thread scheduler and are awaited by polling.
 */
class SecurityKeyManagerTest {

  private static final SecurityGroupRef REF = new SecurityGroupRef("SG");
  private static final SecurityGroupRef REF2 = new SecurityGroupRef("SG2");

  private static final Duration TTNK = Duration.ofSeconds(10);
  private static final Duration LIFETIME = Duration.ofSeconds(20);

  /** The wire-trigger cooldown for LIFETIME: min(max(1s, LIFETIME/2), 10s). */
  private static final Duration WIRE_TRIGGER_COOLDOWN = Duration.ofSeconds(10);

  /** Fixed 4-byte random part so nonces are fully deterministic. */
  private static final byte[] NONCE_RANDOM = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};

  private final AtomicLong nanoTime = new AtomicLong(0);

  private final List<Transition> transitions = new ArrayList<>();
  private final Object engineLock = new Object();

  private final PubSubStateMachine stateMachine =
      new PubSubStateMachine(
          engineLock,
          (component, oldState, newState, statusCode) ->
              transitions.add(new Transition(component.path(), oldState, newState)));

  private final ExecutorService eventExecutor = Executors.newSingleThreadExecutor();
  private final DiagnosticsCollector diagnostics =
      new DiagnosticsCollector(new EventDispatcher(eventExecutor));

  private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

  private final AtomicReference<SecurityKeyProvider> provider = new AtomicReference<>();
  private final AtomicReference<SecurityKeyProvider> provider2 = new AtomicReference<>();

  private final SecurityKeyManager manager =
      new SecurityKeyManager(
          stateMachine,
          diagnostics,
          scheduler,
          ref -> REF.equals(ref) ? provider.get() : REF2.equals(ref) ? provider2.get() : null,
          () -> NONCE_RANDOM.clone(),
          nanoTime::get);

  @AfterEach
  void shutdownExecutors() throws Exception {
    manager.shutdown();
    // shutdownNow: retirement/retry tasks are scheduled seconds out and need not run in tests
    scheduler.shutdownNow();
    eventExecutor.shutdown();
    assertTrue(scheduler.awaitTermination(10, TimeUnit.SECONDS));
    assertTrue(eventExecutor.awaitTermination(10, TimeUnit.SECONDS));
  }

  private record Transition(String path, PubSubState from, PubSubState to) {}

  /** A component that stays PreOperational until an external actor completes its startup. */
  private static final class TestComponent extends AbstractComponentRuntime {

    TestComponent(String path) {
      super(ComponentType.WRITER_GROUP, path, null, true);
    }

    @Override
    List<? extends AbstractComponentRuntime> children() {
      return List.of();
    }

    @Override
    boolean startupCompletesImmediately() {
      return false;
    }
  }

  private TestComponent activeComponent(String path) {
    var component = new TestComponent(path);
    diagnostics.register(path);
    stateMachine.setRootOperational(true, List.of(component));
    assertEquals(PubSubState.PreOperational, component.state());
    return component;
  }

  private static SecurityGroupConfig groupConfig() {
    return SecurityGroupConfig.builder("SG").keyLifeTime(LIFETIME).build();
  }

  private static SecurityGroupConfig groupConfig2() {
    return SecurityGroupConfig.builder("SG2").keyLifeTime(LIFETIME).build();
  }

  private static ByteString keyData(PubSubSecurityPolicy policy, int seed) {
    byte[] bytes = new byte[policy.getKeyDataLength()];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) (seed + i);
    }
    return ByteString.of(bytes);
  }

  private static SecurityKeySet keySet(long firstTokenId, int keyCount) {
    return keySet(PubSubSecurityPolicy.Aes256Ctr, firstTokenId, keyCount, TTNK, LIFETIME);
  }

  /** Like {@link #keySet(long, int)} but with key bytes from a DIFFERENT deterministic stream. */
  private static SecurityKeySet keySet(long firstTokenId, int keyCount, int seedOffset) {
    var policy = PubSubSecurityPolicy.Aes256Ctr;
    var keys = new ArrayList<ByteString>(keyCount);
    for (int i = 0; i < keyCount; i++) {
      keys.add(keyData(policy, (int) (firstTokenId + i + seedOffset)));
    }
    return new SecurityKeySet(policy.getUri(), uint(firstTokenId), keys, TTNK, LIFETIME);
  }

  private static SecurityKeySet keySet(
      PubSubSecurityPolicy policy,
      long firstTokenId,
      int keyCount,
      Duration timeToNextKey,
      Duration keyLifetime) {

    var keys = new ArrayList<ByteString>(keyCount);
    for (int i = 0; i < keyCount; i++) {
      keys.add(keyData(policy, (int) (firstTokenId + i)));
    }
    return new SecurityKeySet(
        policy.getUri(), uint(firstTokenId), keys, timeToNextKey, keyLifetime);
  }

  /** A provider serving a settable key set and counting fetches. */
  private static final class TestProvider implements SecurityKeyProvider {

    final AtomicInteger fetchCount = new AtomicInteger();
    final AtomicReference<CompletableFuture<SecurityKeySet>> next = new AtomicReference<>();

    TestProvider(SecurityKeySet keySet) {
      next.set(CompletableFuture.completedFuture(keySet));
    }

    @Override
    public CompletableFuture<SecurityKeySet> getKeys(
        String securityGroupId, UInteger startingTokenId, UInteger requestedKeyCount) {
      fetchCount.incrementAndGet();
      return next.get();
    }
  }

  private TestProvider installProvider(SecurityKeySet keySet) {
    var testProvider = new TestProvider(keySet);
    provider.set(testProvider);
    return testProvider;
  }

  private static void awaitTrue(String description, BooleanSupplier condition)
      throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (System.nanoTime() < deadline) {
      if (condition.getAsBoolean()) {
        return;
      }
      Thread.sleep(5);
    }
    fail("timed out waiting for: " + description);
  }

  private TestComponent registerAndAwaitKeys() throws Exception {
    TestComponent component = activeComponent("conn/WG");
    manager.register(groupConfig(), REF, component, null);
    awaitTrue("first fetch completes startup", () -> component.state() == PubSubState.Operational);
    return component;
  }

  // region startup + fetch wiring

  @Test
  void firstSuccessfulFetchCompletesStartup() throws Exception {
    installProvider(keySet(1, 2));
    TestComponent component = registerAndAwaitKeys();

    assertTrue(manager.allKeysAvailable(component));

    MessageSecurityContext context = manager.publishContext(REF, MessageSecurityMode.Sign);
    assertNotNull(context);
    assertEquals(uint(1), context.securityTokenId());
    assertEquals(PubSubSecurityPolicy.Aes256Ctr, context.policy());
  }

  @Test
  void registerWithoutBoundProviderThrows() {
    TestComponent component = activeComponent("conn/WG");
    var unbound = new SecurityGroupRef("other");

    assertThrows(
        UaException.class, () -> manager.register(groupConfig(), unbound, component, null));
  }

  @Test
  void failedInitialFetchLeavesComponentPreOperational() throws Exception {
    var testProvider = new TestProvider(keySet(1, 1));
    testProvider.next.set(CompletableFuture.failedFuture(new RuntimeException("SKS down")));
    provider.set(testProvider);

    TestComponent component = activeComponent("conn/WG");
    manager.register(groupConfig(), REF, component, null);

    awaitTrue("initial fetch attempted", () -> testProvider.fetchCount.get() >= 1);
    // §5.4.5.3: initial failure => stay PreOperational; the retry cadence is scheduled
    assertEquals(PubSubState.PreOperational, component.state());
    assertFalse(manager.allKeysAvailable(component));
    assertNull(manager.publishContext(REF, MessageSecurityMode.Sign));
  }

  @Test
  void refreshCadenceIsHalfTheKeyLifetime() throws Exception {
    installProvider(keySet(1, 2));
    registerAndAwaitKeys();

    Long delay = manager.scheduledRefreshDelayNanos(REF);
    assertNotNull(delay);
    assertEquals(LIFETIME.toNanos() / 2, delay);
  }

  // endregion

  // region token switch schedule + nonces

  @Test
  void activeTokenSwitchesAtTimeToNextKeyThenEveryKeyLifetime() throws Exception {
    installProvider(keySet(1, 3));
    registerAndAwaitKeys();

    assertEquals(uint(1), tokenOfPublishContext());

    nanoTime.set(TTNK.toNanos() - 1);
    assertEquals(uint(1), tokenOfPublishContext());

    nanoTime.set(TTNK.toNanos());
    assertEquals(uint(2), tokenOfPublishContext());

    nanoTime.set(TTNK.plus(LIFETIME).toNanos());
    assertEquals(uint(3), tokenOfPublishContext());
  }

  @Test
  void activeTokenClampsToLastAvailableKeyAfterExpiry() throws Exception {
    installProvider(keySet(1, 2));
    registerAndAwaitKeys();

    // past the last key's scheduled replacement but inside the 2x-KeyLifetime allowance the
    // publisher keeps using the last available (expired) key (§6.2.12.2)
    nanoTime.set(TTNK.plus(LIFETIME).plus(LIFETIME).toNanos());
    assertEquals(uint(2), tokenOfPublishContext());
  }

  @Test
  void nonceCounterStartsAtOneAndResetsOnTokenSwitch() throws Exception {
    installProvider(keySet(1, 2));
    registerAndAwaitKeys();

    MessageSecurityContext context1 = manager.publishContext(REF, MessageSecurityMode.Sign);
    assertNotNull(context1);
    assertArrayEquals(nonce(1), context1.nonceSupplier().nextNonce());
    assertArrayEquals(nonce(2), context1.nonceSupplier().nextNonce());

    nanoTime.set(TTNK.toNanos());
    MessageSecurityContext context2 = manager.publishContext(REF, MessageSecurityMode.Sign);
    assertNotNull(context2);
    assertEquals(uint(2), context2.securityTokenId());
    // Table 156: the nonce sequence number resets to 1 when the key/token is updated
    assertArrayEquals(nonce(1), context2.nonceSupplier().nextNonce());

    // the context resolved for the OLD token keeps drawing from the old token's counter: one
    // coherent (token, material, nonce-counter) triple per cycle even across a switch
    assertArrayEquals(nonce(3), context1.nonceSupplier().nextNonce());
  }

  private static byte[] nonce(long sequenceNumber) {
    return new byte[] {
      NONCE_RANDOM[0],
      NONCE_RANDOM[1],
      NONCE_RANDOM[2],
      NONCE_RANDOM[3],
      (byte) sequenceNumber,
      (byte) (sequenceNumber >>> 8),
      (byte) (sequenceNumber >>> 16),
      (byte) (sequenceNumber >>> 24)
    };
  }

  private UInteger tokenOfPublishContext() {
    MessageSecurityContext context = manager.publishContext(REF, MessageSecurityMode.Sign);
    assertNotNull(context);
    return context.securityTokenId();
  }

  // endregion

  // region staleness (§6.2.12.2)

  @Test
  void keysExpiredBeyondTwiceLifetimeFailComponentAndStopPublishing() throws Exception {
    installProvider(keySet(1, 2));
    TestComponent component = registerAndAwaitKeys();

    // last key expiry = ttnk + 1*lifetime; stale strictly after expiry + 2*lifetime
    long staleAt = TTNK.plus(LIFETIME).plus(LIFETIME.multipliedBy(2)).toNanos() + 1;
    nanoTime.set(staleAt);

    assertNull(manager.publishContext(REF, MessageSecurityMode.Sign));
    assertEquals(PubSubState.Error, component.state());
  }

  @Test
  void successfulFetchAfterStalenessRecoversComponent() throws Exception {
    TestProvider testProvider = installProvider(keySet(1, 2));
    TestComponent component = registerAndAwaitKeys();

    nanoTime.set(TTNK.plus(LIFETIME.multipliedBy(3)).toNanos() + 1);
    assertNull(manager.publishContext(REF, MessageSecurityMode.Sign));
    assertEquals(PubSubState.Error, component.state());

    // fresh keys fetched at "now" (e.g. the retry cadence or an unknown-token trigger)
    long now = nanoTime.get();
    testProvider.next.set(CompletableFuture.completedFuture(keySet(9, 2)));
    manager.subscriberKey(REF, uint(9)); // unknown token: triggers the single-flight refresh

    awaitTrue("recovery on fresh keys", () -> component.state() == PubSubState.Operational);

    MessageSecurityContext context = manager.publishContext(REF, MessageSecurityMode.Sign);
    assertNotNull(context);
    assertEquals(uint(9), context.securityTokenId());
    assertEquals(now, nanoTime.get());
  }

  @Test
  void subscriberTokenExpiredBeyondTwiceLifetimeIsStale() throws Exception {
    installProvider(keySet(1, 3));
    registerAndAwaitKeys();

    // token 1 is replaced at ttnk; it stops being usable at ttnk + 2*lifetime (§6.2.12.2)
    nanoTime.set(TTNK.plus(LIFETIME.multipliedBy(2)).toNanos() + 1);

    SecurityKeyManager.SubscriberKey key = manager.subscriberKey(REF, uint(1));
    assertNull(key.material());
    assertEquals(SecurityKeyManager.SubscriberKeyReason.STALE_KEY, key.reason());

    // token 3 (last future key) is still within its usable window
    assertNotNull(manager.subscriberKey(REF, uint(3)).material());
  }

  // endregion

  // region static-key form

  @Test
  void staticKeySetNeverRotatesAndNeverExpires() throws Exception {
    installProvider(keySet(PubSubSecurityPolicy.Aes128Ctr, 1, 1, Duration.ZERO, Duration.ZERO));
    registerAndAwaitKeys();

    assertEquals(uint(1), tokenOfPublishContext());

    // no refresh is scheduled for static keys
    assertNull(manager.scheduledRefreshDelayNanos(REF));

    nanoTime.set(Duration.ofDays(365).toNanos());
    assertEquals(uint(1), tokenOfPublishContext());
    assertNotNull(manager.subscriberKey(REF, uint(1)).material());

    SecurityKeyManager.TokenInfo tokenInfo = manager.tokenInfo(REF);
    assertNotNull(tokenInfo);
    assertEquals(uint(1), tokenInfo.securityTokenId());
    assertEquals(Duration.ZERO, tokenInfo.timeToNextKey());
  }

  // endregion

  // region K8 policy precedence

  @Test
  void providerPolicyMismatchingConfiguredUriFailsFetch() throws Exception {
    TestProvider testProvider = installProvider(keySet(1, 2)); // returns Aes256Ctr

    TestComponent component = activeComponent("conn/WG");
    manager.register(groupConfig(), REF, component, PubSubSecurityPolicy.Aes128Ctr.getUri());

    awaitTrue("fetch attempted", () -> testProvider.fetchCount.get() >= 1);
    awaitTrue(
        "mismatch recorded",
        () ->
            diagnostics.snapshot().get("conn/WG") != null
                && diagnostics.snapshot().get("conn/WG").lastError() != null);

    // never downgrade: the fetch FAILED, no keys are usable, startup is not completed
    assertEquals(PubSubState.PreOperational, component.state());
    assertNull(manager.publishContext(REF, MessageSecurityMode.Sign));
  }

  @Test
  void unsupportedProviderPolicyUriFailsFetch() throws Exception {
    var badKeySet =
        new SecurityKeySet(
            "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Unsupported",
            uint(1),
            List.of(keyData(PubSubSecurityPolicy.Aes256Ctr, 1)),
            TTNK,
            LIFETIME);
    TestProvider testProvider = installProvider(badKeySet);

    TestComponent component = activeComponent("conn/WG");
    manager.register(groupConfig(), REF, component, null);

    awaitTrue("fetch attempted", () -> testProvider.fetchCount.get() >= 1);
    assertEquals(PubSubState.PreOperational, component.state());
    assertNull(manager.publishContext(REF, MessageSecurityMode.Sign));
  }

  @Test
  void registeringAgainstHeldKeysWithMismatchedPolicyUriThrows() throws Exception {
    installProvider(keySet(1, 2)); // serves Aes256Ctr
    registerAndAwaitKeys(); // keys are already held when the second component registers

    // the K8 gate at registration time: the fetch-completion gate only sees the consumers
    // registered then, so a later registrant must be validated against the held policy — never
    // silently substituted onto a policy other than the URI the operator pinned
    TestComponent second = activeComponent("conn/WG2");
    UaException e =
        assertThrows(
            UaException.class,
            () ->
                manager.register(
                    groupConfig(), REF, second, PubSubSecurityPolicy.Aes128Ctr.getUri()));

    assertEquals(StatusCodes.Bad_ConfigurationError, e.getStatusCode().getValue());
    // the mismatched component was never registered as a consumer
    assertFalse(manager.allKeysAvailable(second));
  }

  @Test
  void registeringAgainstHeldKeysWithMatchingPolicyUriSucceeds() throws Exception {
    installProvider(keySet(1, 2)); // serves Aes256Ctr
    registerAndAwaitKeys();

    TestComponent second = activeComponent("conn/WG2");
    manager.register(groupConfig(), REF, second, PubSubSecurityPolicy.Aes256Ctr.getUri());

    assertTrue(manager.allKeysAvailable(second));
  }

  // endregion

  // region subscriber window: unknown tokens, past keys, dedup/discard

  @Test
  void unknownTokenTriggersAtMostOneRefreshInFlight() throws Exception {
    TestProvider testProvider = installProvider(keySet(1, 1));
    registerAndAwaitKeys();
    int initialFetches = testProvider.fetchCount.get();

    // park the next fetch so it stays in flight
    var pending = new CompletableFuture<SecurityKeySet>();
    testProvider.next.set(pending);

    // wire triggers are rate-limited (unknownTokenRefreshIsRateLimited): step past the cooldown
    nanoTime.set(WIRE_TRIGGER_COOLDOWN.toNanos());

    SecurityKeyManager.SubscriberKey first = manager.subscriberKey(REF, uint(7));
    assertEquals(SecurityKeyManager.SubscriberKeyReason.UNKNOWN_TOKEN, first.reason());
    awaitTrue("refresh triggered", () -> testProvider.fetchCount.get() == initialFetches + 1);

    // more unknown tokens while the refresh is in flight: dropped and counted by the caller,
    // no additional fetch (single-flight), never buffered
    manager.subscriberKey(REF, uint(7));
    manager.subscriberKey(REF, uint(8));
    Thread.sleep(50);
    assertEquals(initialFetches + 1, testProvider.fetchCount.get());

    pending.complete(keySet(7, 2));
    awaitTrue("window replaced", () -> manager.subscriberKey(REF, uint(7)).material() != null);
  }

  @Test
  void zeroTokenIdResolvesToTheActiveKey() throws Exception {
    installProvider(keySet(1, 3));
    registerAndAwaitKeys();

    // K4: the literal Table 154 sign-only form carries SecurityTokenId 0; token ids are 1-based,
    // so 0 names the currently active key rather than a (below-window) past key
    SecurityKeyManager.SubscriberKey zero = manager.subscriberKey(REF, uint(0));
    assertNotNull(zero.material());
    assertEquals(SecurityKeyManager.SubscriberKeyReason.RESOLVED, zero.reason());
    assertSame(manager.subscriberKey(REF, uint(1)).material(), zero.material());

    // ...and tracks the switch schedule
    nanoTime.set(TTNK.toNanos());
    SecurityKeyManager.SubscriberKey switched = manager.subscriberKey(REF, uint(0));
    assertNotNull(switched.material());
    assertSame(manager.subscriberKey(REF, uint(2)).material(), switched.material());
  }

  @Test
  void zeroTokenIdResolvesToTheStaticKey() throws Exception {
    // the S2OPC-style static-key interop path (K14) emits the zero-token sign-only form
    installProvider(keySet(PubSubSecurityPolicy.Aes128Ctr, 1, 1, Duration.ZERO, Duration.ZERO));
    registerAndAwaitKeys();

    SecurityKeyManager.SubscriberKey zero = manager.subscriberKey(REF, uint(0));
    assertNotNull(zero.material());
    assertEquals(SecurityKeyManager.SubscriberKeyReason.RESOLVED, zero.reason());
    assertSame(manager.subscriberKey(REF, uint(1)).material(), zero.material());
  }

  @Test
  void pastTokenIsStaleAndNeverRefetched() throws Exception {
    TestProvider testProvider = installProvider(keySet(5, 2));
    registerAndAwaitKeys();
    int fetches = testProvider.fetchCount.get();

    SecurityKeyManager.SubscriberKey key = manager.subscriberKey(REF, uint(2));
    assertNull(key.material());
    assertEquals(SecurityKeyManager.SubscriberKeyReason.STALE_KEY, key.reason());

    Thread.sleep(50);
    assertEquals(fetches, testProvider.fetchCount.get(), "past keys are never re-fetched");
  }

  @Test
  void overlappingFetchMergesAndKeepsKnownTokenMaterial() throws Exception {
    TestProvider testProvider = installProvider(keySet(1, 3));
    registerAndAwaitKeys();

    SecurityKeyMaterial token2Before = manager.subscriberKey(REF, uint(2)).material();
    assertNotNull(token2Before);

    // overlap: FirstTokenId 2 is known => merge, duplicates eliminated (§8.3.2).
    // forceKeyReset is a rate-limited wire trigger: step past the cooldown first.
    nanoTime.set(WIRE_TRIGGER_COOLDOWN.toNanos());
    testProvider.next.set(CompletableFuture.completedFuture(keySet(2, 3)));
    manager.forceKeyReset(REF);
    awaitTrue(
        "merged window resolves token 4",
        () -> manager.subscriberKey(REF, uint(4)).material() != null);

    assertSame(token2Before, manager.subscriberKey(REF, uint(2)).material());
    // token 1 stays retained as the "previous" token of the merged window
    assertNotNull(manager.subscriberKey(REF, uint(1)).material());
  }

  @Test
  void unknownFirstTokenIdDiscardsAndReplacesWindow() throws Exception {
    TestProvider testProvider = installProvider(keySet(1, 2));
    registerAndAwaitKeys();
    assertNotNull(manager.subscriberKey(REF, uint(1)).material());

    // no overlap with {1,2}: "If the FirstTokenId is unknown, the existing list shall be
    // discarded and replaced" (§8.3.2). Step past the wire-trigger cooldown first.
    nanoTime.set(WIRE_TRIGGER_COOLDOWN.toNanos());
    testProvider.next.set(CompletableFuture.completedFuture(keySet(10, 2)));
    manager.forceKeyReset(REF);
    awaitTrue(
        "replaced window resolves token 10",
        () -> manager.subscriberKey(REF, uint(10)).material() != null);

    SecurityKeyManager.SubscriberKey old = manager.subscriberKey(REF, uint(2));
    assertNull(old.material());
    assertEquals(SecurityKeyManager.SubscriberKeyReason.STALE_KEY, old.reason());
  }

  // endregion

  // region unregister

  @Test
  void publishContextHandsOutACycleOwnedCopyOfTheKeyMaterial() throws Exception {
    installProvider(keySet(1, 2));
    registerAndAwaitKeys();

    SecurityKeyMaterial windowMaterial = manager.subscriberKey(REF, uint(1)).material();
    assertNotNull(windowMaterial);

    MessageSecurityContext context = manager.publishContext(REF, MessageSecurityMode.Sign);
    assertNotNull(context);
    // the publish cycle spans user source reads of unbounded duration: it gets a COPY, never a
    // window reference that a concurrent key retirement could destroy (wipe) mid-cycle
    assertNotSame(windowMaterial, context.keyMaterial());
    assertArrayEquals(windowMaterial.getSigningKey(), context.keyMaterial().getSigningKey());
    assertArrayEquals(windowMaterial.getEncryptingKey(), context.keyMaterial().getEncryptingKey());
    assertArrayEquals(windowMaterial.getKeyNonce(), context.keyMaterial().getKeyNonce());

    // destroying the cycle's copy at cycle end leaves the window (and later cycles) untouched
    context.keyMaterial().destroy();
    MessageSecurityContext next = manager.publishContext(REF, MessageSecurityMode.Sign);
    assertNotNull(next);
    assertFalse(next.keyMaterial().isDestroyed());
    assertArrayEquals(windowMaterial.getSigningKey(), next.keyMaterial().getSigningKey());
  }

  @Test
  void multiRefComponentCompletesStartupOnlyWhenAllRefsHaveKeys() throws Exception {
    installProvider(keySet(1, 2));
    var pendingB = new CompletableFuture<SecurityKeySet>();
    var providerB = new TestProvider(keySet(1, 2));
    providerB.next.set(pendingB);
    provider2.set(providerB);

    TestComponent component = activeComponent("conn/RG");
    manager.registerAll(
        List.of(
            new SecurityKeyManager.Registration(groupConfig(), REF, null),
            new SecurityKeyManager.Registration(groupConfig2(), REF2, null)),
        component);

    // the first ref's (immediate) fetch lands while the second is still outstanding: the
    // component's complete ref set was registered atomically, so startup must NOT complete on
    // the partial set
    awaitTrue("first ref fetched", () -> manager.subscriberKey(REF, uint(1)).material() != null);
    Thread.sleep(50);
    assertEquals(PubSubState.PreOperational, component.state());
    assertFalse(manager.allKeysAvailable(component));

    pendingB.complete(keySet(1, 2));
    awaitTrue(
        "startup completes once every ref has keys",
        () -> component.state() == PubSubState.Operational);
    assertTrue(manager.allKeysAvailable(component));
  }

  @Test
  void multiRefFailedComponentRecoversOnlyWhenEveryRefHasUsableKeys() throws Exception {
    // ref A fetches once; ref B's provider is down from the start
    TestProvider providerA = installProvider(keySet(1, 2));
    var providerB = new TestProvider(keySet(1, 2));
    providerB.next.set(CompletableFuture.failedFuture(new RuntimeException("SKS down")));
    provider2.set(providerB);

    TestComponent component = activeComponent("conn/RG");
    manager.registerAll(
        List.of(
            new SecurityKeyManager.Registration(groupConfig(), REF, null),
            new SecurityKeyManager.Registration(groupConfig2(), REF2, null)),
        component);

    awaitTrue("ref A fetched", () -> manager.subscriberKey(REF, uint(1)).material() != null);
    assertEquals(PubSubState.PreOperational, component.state());

    // ref A's keys expire beyond 2x KeyLifetime: the manager fails the component to Error
    nanoTime.set(TTNK.plus(LIFETIME.multipliedBy(3)).toNanos() + 1);
    assertNull(manager.publishContext(REF, MessageSecurityMode.Sign));
    assertEquals(PubSubState.Error, component.state());

    // ref A refreshes with fresh keys, but ref B still has none: the component must stay in
    // Error and its failure marker must survive for the fetch that actually completes the set
    providerA.next.set(CompletableFuture.completedFuture(keySet(9, 2)));
    manager.subscriberKey(REF, uint(9));
    awaitTrue("ref A refreshed", () -> manager.subscriberKey(REF, uint(9)).material() != null);
    Thread.sleep(50);
    assertEquals(PubSubState.Error, component.state());

    // ref B's first successful fetch completes the set: NOW the component recovers
    providerB.next.set(CompletableFuture.completedFuture(keySet(9, 2)));
    manager.subscriberKey(REF2, uint(9));
    awaitTrue(
        "recovery once every ref has usable keys",
        () -> component.state() == PubSubState.Operational);
  }

  @Test
  void staleRecoveryRequiresEveryRefFreshNotJustTheFetchedOne() throws Exception {
    // both refs hold keys, then BOTH go stale; a good fetch on one ref alone must not recover
    TestProvider providerA = installProvider(keySet(1, 2));
    var providerB = new TestProvider(keySet(1, 2));
    provider2.set(providerB);

    TestComponent component = activeComponent("conn/RG");
    manager.registerAll(
        List.of(
            new SecurityKeyManager.Registration(groupConfig(), REF, null),
            new SecurityKeyManager.Registration(groupConfig2(), REF2, null)),
        component);
    awaitTrue("both refs fetched", () -> component.state() == PubSubState.Operational);

    nanoTime.set(TTNK.plus(LIFETIME.multipliedBy(3)).toNanos() + 1);
    assertNull(manager.publishContext(REF, MessageSecurityMode.Sign));
    assertEquals(PubSubState.Error, component.state());

    // fresh keys for ref A only: ref B is still expired beyond 2x KeyLifetime, so recovering now
    // would report Operational for a component that cannot process B's traffic
    providerA.next.set(CompletableFuture.completedFuture(keySet(9, 2)));
    manager.subscriberKey(REF, uint(9));
    awaitTrue("ref A refreshed", () -> manager.subscriberKey(REF, uint(9)).material() != null);
    Thread.sleep(50);
    assertEquals(PubSubState.Error, component.state());

    providerB.next.set(CompletableFuture.completedFuture(keySet(9, 2)));
    manager.subscriberKey(REF2, uint(9));
    awaitTrue(
        "recovery once both refs are fresh", () -> component.state() == PubSubState.Operational);
  }

  @Test
  void staleKeyFailureNeverResurrectsAComponentFailedForAnotherReason() throws Exception {
    TestProvider testProvider = installProvider(keySet(1, 2));
    TestComponent component = registerAndAwaitKeys();

    // the component fails for an unrelated reason (e.g. an activation error)
    var unrelated = new StatusCode(StatusCodes.Bad_InternalError);
    stateMachine.fail(component, unrelated);
    assertEquals(PubSubState.Error, component.state());

    // keys also go stale: the stale episode must not claim the already-Error component as its own
    nanoTime.set(TTNK.plus(LIFETIME.multipliedBy(3)).toNanos() + 1);
    assertNull(manager.publishContext(REF, MessageSecurityMode.Sign));

    // fresh keys arrive: the manager recovers only components IT failed — the unrelated Error
    // (whose activation never completed) must stay in Error
    testProvider.next.set(CompletableFuture.completedFuture(keySet(9, 2)));
    manager.subscriberKey(REF, uint(9));
    awaitTrue("refresh applied", () -> manager.subscriberKey(REF, uint(9)).material() != null);
    Thread.sleep(50);
    assertEquals(PubSubState.Error, component.state());
  }

  @Test
  void fetchCompletionForAReplacedStateIsDiscarded() throws Exception {
    // park the initial fetch of the FIRST registration so it completes only after the state it
    // was started for has been unregistered and replaced by a successor
    var stalePending = new CompletableFuture<SecurityKeySet>();
    var testProvider = new TestProvider(keySet(1, 2));
    testProvider.next.set(stalePending);
    provider.set(testProvider);

    TestComponent component = activeComponent("conn/WG");
    manager.register(groupConfig(), REF, component, null);
    awaitTrue("stale fetch started", () -> testProvider.fetchCount.get() == 1);

    // reconfigure-style restart: unregister disposes the state, re-register creates a successor
    manager.unregister(component);

    var successorPending = new CompletableFuture<SecurityKeySet>();
    testProvider.next.set(successorPending);
    TestComponent successor = activeComponent("conn/WG2");
    manager.register(groupConfig(), REF, successor, null);
    awaitTrue("successor fetch started", () -> testProvider.fetchCount.get() == 2);

    // the stale fetch completes: its result must be DISCARDED — neither applied to the successor
    // state (a dead generation's key stream) nor clearing the successor's single-flight gate
    stalePending.complete(keySet(1, 2));
    Thread.sleep(50);
    assertNull(manager.subscriberKey(REF, uint(1)).material());
    assertEquals(PubSubState.PreOperational, successor.state());

    // the successor's own fetch still applies normally
    successorPending.complete(keySet(5, 2));
    awaitTrue(
        "successor keys applied", () -> manager.subscriberKey(REF, uint(5)).material() != null);
    assertNull(manager.subscriberKey(REF, uint(1)).material());
    assertEquals(PubSubState.Operational, successor.state());
  }

  @Test
  void overlappingFetchWithDifferentKeyBytesReplacesWindow() throws Exception {
    TestProvider testProvider = installProvider(keySet(2, 5)); // tokens {2..6}
    registerAndAwaitKeys();

    SecurityKeyMaterial heldToken2 = manager.subscriberKey(REF, uint(2)).material();
    assertNotNull(heldToken2);

    // an SKS restart lost its key state and restarted token ids near the held window: the token
    // ranges intersect numerically, but the key BYTES of the duplicate ids differ — the §8.3.2
    // merge presumes one continuous key stream, so this fetch must replace, not merge (merging
    // keeps dead pre-restart material for tokens 2..6 and breaks verification for KeyLifetimes)
    nanoTime.set(WIRE_TRIGGER_COOLDOWN.toNanos());
    testProvider.next.set(CompletableFuture.completedFuture(keySet(1, 8, 100)));
    manager.forceKeyReset(REF);

    awaitTrue(
        "restarted window applied", () -> manager.subscriberKey(REF, uint(8)).material() != null);

    SecurityKeyMaterial newToken2 = manager.subscriberKey(REF, uint(2)).material();
    assertNotNull(newToken2);
    assertNotSame(heldToken2, newToken2);
    SecurityKeyMaterial expected =
        SecurityKeyMaterial.of(
            PubSubSecurityPolicy.Aes256Ctr, keyData(PubSubSecurityPolicy.Aes256Ctr, 2 + 100));
    assertArrayEquals(expected.getSigningKey(), newToken2.getSigningKey());
  }

  @Test
  void unknownTokenRefreshIsRateLimited() throws Exception {
    TestProvider testProvider = installProvider(keySet(1, 1));
    registerAndAwaitKeys();
    int initialFetches = testProvider.fetchCount.get();

    // spoofed-header burst right after the initial fetch: within the cooldown NO wire-triggered
    // fetch fires — an immediate re-fetch could not learn the unknown token anyway, and both
    // trigger fields ride unauthenticated plaintext headers
    manager.subscriberKey(REF, uint(0xFFFF));
    manager.forceKeyReset(REF);
    Thread.sleep(50);
    assertEquals(initialFetches, testProvider.fetchCount.get());

    // past the cooldown exactly ONE trigger is allowed...
    nanoTime.set(WIRE_TRIGGER_COOLDOWN.toNanos());
    manager.subscriberKey(REF, uint(0xFFFF));
    awaitTrue(
        "one wire-triggered refresh allowed",
        () -> testProvider.fetchCount.get() == initialFetches + 1);

    // ...and the burst that follows (the fetch completed immediately, the spoofed token is still
    // unknown) stays suppressed until the next interval elapses
    manager.subscriberKey(REF, uint(0xFFFF));
    manager.subscriberKey(REF, uint(0xFFFE));
    manager.forceKeyReset(REF);
    Thread.sleep(50);
    assertEquals(initialFetches + 1, testProvider.fetchCount.get());

    nanoTime.set(WIRE_TRIGGER_COOLDOWN.multipliedBy(2).toNanos());
    manager.subscriberKey(REF, uint(0xFFFF));
    awaitTrue(
        "the next interval allows one more",
        () -> testProvider.fetchCount.get() == initialFetches + 2);
  }

  @Test
  void unregisteringLastConsumerDisposesState() throws Exception {
    TestProvider testProvider = installProvider(keySet(1, 2));
    TestComponent component = registerAndAwaitKeys();
    int fetches = testProvider.fetchCount.get();

    manager.unregister(component);

    assertNull(manager.publishContext(REF, MessageSecurityMode.Sign));
    assertNull(manager.tokenInfo(REF));
    // no state left: an unknown token no longer triggers fetches
    manager.subscriberKey(REF, uint(1));
    Thread.sleep(50);
    assertEquals(fetches, testProvider.fetchCount.get());
  }

  // endregion
}
