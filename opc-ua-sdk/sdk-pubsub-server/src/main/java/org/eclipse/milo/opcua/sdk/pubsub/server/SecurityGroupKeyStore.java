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

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfigValidationException;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Server-side key store backing the SKS face of {@link ServerPubSub}: generates, rotates, and
 * serves the security keys of the SecurityGroups configured on the attached PubSub configuration
 * (OPC UA Part 14 §8.3.2 GetSecurityKeys semantics).
 *
 * <p>One {@link GroupKeyState} exists per {@link SecurityGroupConfig} present at construction;
 * groups added by later reconfiguration are not picked up (a documented v1 limitation matching the
 * rest of {@code ServerPubSub}'s attach-time posture).
 *
 * <p>Key material is CSPRNG-generated, {@link PubSubSecurityPolicy#getKeyDataLength()} bytes per
 * key (the Table 155 concatenation {@code SigningKey || EncryptingKey || KeyNonce}). SecurityToken
 * ids are a function of time at the SKS (§8.3.2: incremented by one each time the KeyLifetime
 * elapses, "even if no keys are requested"): the id starts at 1 when the store is created and is
 * derived from the elapsed time on every access, so it is monotonically increasing and never reused
 * — a scheduler stall cannot replay an id, and a backward system-clock jump is absorbed by a
 * high-water mark. The scheduled housekeeping task per group (KeyLifetime cadence, on the server's
 * scheduled executor) only prunes expired history and pre-generates the future window.
 *
 * <p>SKS defaults applied per §8.5.2 ("0/null inputs → SKS defaults"), documented here because the
 * config model uses 0/null for "not configured":
 *
 * <ul>
 *   <li>{@code securityPolicyUri} null → {@link PubSubSecurityPolicy#Aes256Ctr}; a non-null URI
 *       naming no supported policy fails construction with {@link PubSubConfigValidationException}
 *       (the store cannot size keys for an unknown policy).
 *   <li>{@code keyLifeTime} zero → 1 hour; sub-second lifetimes are clamped up to 1 second.
 *   <li>{@code maxFutureKeyCount} 0 → 10 (MaxFutureKeyCount is in the §8.5.2 defaults list).
 *   <li>{@code maxPastKeyCount} 0 → no history is retained (MaxPastKeyCount is deliberately
 *       <em>not</em> in the §8.5.2 defaults list; 0 is a meaningful value).
 * </ul>
 *
 * <p>Slice semantics of {@link #getSecurityKeys} per §8.3.2: {@code startingTokenId} 0 requests the
 * current token; any other value is clamped into the retained window {@code [current -
 * maxPastKeyCount, current + maxFutureKeyCount]} (the spec allows both past and future
 * StartingTokenIds and defines no error for out-of-window values). {@code requestedKeyCount}
 * subsequent keys are returned after the starting key, clamped at the future edge of the window; 0
 * returns only the starting key. {@code TimeToNextKey} is the time until the <em>current</em> key
 * is replaced regardless of the requested slice.
 *
 * <p>Keys are immutable {@link ByteString}s and are never zeroized (the same posture as {@link
 * SecurityKeySet}); pruned history simply becomes unreachable.
 */
final class SecurityGroupKeyStore {

  private static final Logger LOGGER = LoggerFactory.getLogger(SecurityGroupKeyStore.class);

  static final PubSubSecurityPolicy DEFAULT_SECURITY_POLICY = PubSubSecurityPolicy.Aes256Ctr;
  static final Duration DEFAULT_KEY_LIFETIME = Duration.ofHours(1);
  static final Duration MIN_KEY_LIFETIME = Duration.ofSeconds(1);
  static final long DEFAULT_MAX_FUTURE_KEY_COUNT = 10L;

  private final SecureRandom random = new SecureRandom();

  /** Housekeeping futures; non-empty only between startup and shutdown. Guarded by this. */
  private final List<ScheduledFuture<?>> housekeepingFutures = new ArrayList<>();

  private final Map<String, GroupKeyState> states;
  private final ScheduledExecutorService scheduler;
  private final InstantSource clock;

  SecurityGroupKeyStore(
      List<SecurityGroupConfig> securityGroups, ScheduledExecutorService scheduler) {

    this(securityGroups, scheduler, InstantSource.system());
  }

  /**
   * Test seam: {@code clock} drives token derivation, making rotation and window behavior
   * observable without waiting on real time.
   */
  SecurityGroupKeyStore(
      List<SecurityGroupConfig> securityGroups,
      ScheduledExecutorService scheduler,
      InstantSource clock) {

    this.scheduler = scheduler;
    this.clock = clock;

    var states = new LinkedHashMap<String, GroupKeyState>();

    for (SecurityGroupConfig group : securityGroups) {
      GroupKeyState state = new GroupKeyState(group, clock.instant());

      if (states.put(group.getSecurityGroupId(), state) != null) {
        throw new PubSubConfigValidationException(
            "SecurityGroupConfig '%s': duplicate securityGroupId '%s'"
                .formatted(group.getName(), group.getSecurityGroupId()));
      }
    }

    this.states = Map.copyOf(states);
  }

  /** Schedule per-group housekeeping (prune history, pre-generate the future window). */
  synchronized void startup() {
    if (!housekeepingFutures.isEmpty()) {
      return;
    }

    for (GroupKeyState state : states.values()) {
      long periodMillis = state.keyLifetime.toMillis();

      housekeepingFutures.add(
          scheduler.scheduleWithFixedDelay(
              () -> housekeep(state), periodMillis, periodMillis, TimeUnit.MILLISECONDS));
    }
  }

  /** Cancel the housekeeping tasks. The store remains readable after shutdown. */
  synchronized void shutdown() {
    housekeepingFutures.forEach(future -> future.cancel(false));
    housekeepingFutures.clear();
  }

  private void housekeep(GroupKeyState state) {
    try {
      state.advance(clock.instant());
    } catch (Exception e) {
      LOGGER.warn(
          "Error rotating keys for SecurityGroup '{}'", state.config.getSecurityGroupId(), e);
    }
  }

  /**
   * Get the {@link SecurityGroupConfig} with the given SecurityGroupId, or {@code null} if the id
   * names no group known to this store.
   */
  @Nullable SecurityGroupConfig getGroup(String securityGroupId) {
    GroupKeyState state = states.get(securityGroupId);
    return state != null ? state.config : null;
  }

  /**
   * Serve a GetSecurityKeys slice for the given SecurityGroup per the class documentation.
   *
   * @param securityGroupId the SecurityGroupId.
   * @param startingTokenId the starting token id; 0 requests the current token.
   * @param requestedKeyCount the number of subsequent keys requested after the starting key.
   * @return the slice as a {@link SecurityKeySet}, or {@code null} if {@code securityGroupId} is
   *     unknown.
   */
  @Nullable SecurityKeySet getSecurityKeys(
      String securityGroupId, UInteger startingTokenId, UInteger requestedKeyCount) {

    GroupKeyState state = states.get(securityGroupId);
    if (state == null) {
      return null;
    }

    return state.slice(startingTokenId.longValue(), requestedKeyCount.longValue(), clock.instant());
  }

  private ByteString randomKeyData(PubSubSecurityPolicy policy) {
    byte[] keyData = new byte[policy.getKeyDataLength()];
    random.nextBytes(keyData);
    return ByteString.of(keyData);
  }

  /** Per-SecurityGroup key state; all access to the mutable window is synchronized. */
  private final class GroupKeyState {

    private final SecurityGroupConfig config;
    private final PubSubSecurityPolicy policy;
    private final Duration keyLifetime;
    private final long maxFutureKeyCount;
    private final long maxPastKeyCount;

    /** The instant token id 1 became current. */
    private final Instant baseInstant;

    /** Generated keys by internal (unwrapped) token id; spans the retained window. */
    private final NavigableMap<Long, ByteString> keysByToken = new TreeMap<>();

    /** High-water mark of the current token id: token ids never move backwards. */
    private long currentToken = 0;

    private GroupKeyState(SecurityGroupConfig config, Instant baseInstant) {
      this.config = config;
      this.baseInstant = baseInstant;

      String securityPolicyUri = config.getSecurityPolicyUri();
      if (securityPolicyUri == null) {
        this.policy = DEFAULT_SECURITY_POLICY;
      } else {
        this.policy =
            PubSubSecurityPolicy.fromUri(securityPolicyUri)
                .orElseThrow(
                    () ->
                        new PubSubConfigValidationException(
                            "SecurityGroupConfig '%s': unsupported securityPolicyUri '%s'"
                                .formatted(config.getName(), securityPolicyUri)));
      }

      Duration keyLifetime = config.getKeyLifeTime();
      if (keyLifetime.isZero()) {
        keyLifetime = DEFAULT_KEY_LIFETIME;
      } else if (keyLifetime.compareTo(MIN_KEY_LIFETIME) < 0) {
        keyLifetime = MIN_KEY_LIFETIME;
      }
      this.keyLifetime = keyLifetime;

      long maxFutureKeyCount = config.getMaxFutureKeyCount().longValue();
      this.maxFutureKeyCount =
          maxFutureKeyCount == 0 ? DEFAULT_MAX_FUTURE_KEY_COUNT : maxFutureKeyCount;

      this.maxPastKeyCount = config.getMaxPastKeyCount().longValue();
    }

    /** Advance the current token to {@code now}, prune history, fill the future window. */
    synchronized void advance(Instant now) {
      Duration elapsed = Duration.between(baseInstant, now);
      if (elapsed.isNegative()) {
        elapsed = Duration.ZERO;
      }

      long derived = 1 + elapsed.toMillis() / keyLifetime.toMillis();
      currentToken = Math.max(currentToken, derived);

      long oldest = oldestRetainedToken();
      keysByToken.headMap(oldest).clear();

      for (long token = oldest; token <= newestWindowToken(); token++) {
        keysByToken.computeIfAbsent(token, t -> randomKeyData(policy));
      }
    }

    synchronized SecurityKeySet slice(long startingTokenId, long requestedKeyCount, Instant now) {
      advance(now);

      long start =
          startingTokenId == 0
              ? currentToken
              : Math.max(oldestRetainedToken(), Math.min(startingTokenId, newestWindowToken()));

      // total keys = the starting key plus up to requestedKeyCount subsequent keys,
      // clamped at the future edge of the window (guard the addition against overflow)
      long end = Math.min(saturatedAdd(start, requestedKeyCount), newestWindowToken());

      var keys = new ArrayList<ByteString>();
      for (long token = start; token <= end; token++) {
        keys.add(keysByToken.get(token));
      }

      Instant nextSwitch = baseInstant.plus(keyLifetime.multipliedBy(currentToken));
      Duration timeToNextKey = Duration.between(now, nextSwitch);
      if (timeToNextKey.isNegative()) {
        timeToNextKey = Duration.ZERO;
      } else if (timeToNextKey.compareTo(keyLifetime) > 0) {
        // possible only under a backward clock jump absorbed by the high-water mark
        timeToNextKey = keyLifetime;
      }

      return new SecurityKeySet(
          policy.getUri(), exposedTokenId(start), keys, timeToNextKey, keyLifetime);
    }

    private long oldestRetainedToken() {
      return Math.max(1, currentToken - maxPastKeyCount);
    }

    private long newestWindowToken() {
      return currentToken + maxFutureKeyCount;
    }
  }

  private static long saturatedAdd(long a, long b) {
    long sum = a + b;
    return ((a ^ sum) & (b ^ sum)) < 0 ? Long.MAX_VALUE : sum;
  }

  /**
   * Expose an internal token id as a UInt32 SecurityTokenId: cycles through {@code [1,
   * 0xFFFFFFFF]}, skipping the reserved 0 ("current") value. The wrap is unreachable in practice
   * (2^32 - 1 key lifetimes).
   */
  private static UInteger exposedTokenId(long internalToken) {
    return uint(((internalToken - 1) % 0xFFFF_FFFFL) + 1);
  }
}
