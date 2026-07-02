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

import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupRef;
import org.eclipse.milo.opcua.sdk.pubsub.security.MessageNonceSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.security.MessageSecurityContext;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyMaterial;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
import org.eclipse.milo.opcua.sdk.pubsub.security.UadpMessageSecurity;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Part 14 security key lifecycle engine: one key state per {@link SecurityGroupRef} in use,
 * driven on the shared scheduled executor.
 *
 * <p><b>Fetch cadence</b> (§8.3.2): keys are fetched from the bound {@link SecurityKeyProvider}
 * when the first consumer registers, then refreshed every KeyLifetime/2 ("shall call the Method at
 * a period of half the KeyLifetime"); before the first successful fetch the configured {@link
 * SecurityGroupConfig#getKeyLifeTime()} seeds the cadence, and failed fetches are retried at the
 * same cadence clamped to at most 10 seconds (§5.4.5.3: "retry the key exchange at a faster rate
 * than the key lifetime"). Provider fetches always run via the scheduled executor and never on a
 * publish or dispatch path, and no lock is held across a fetch. Wire-triggered refreshes — an
 * unknown received SecurityTokenId or the force-key-reset bit, both read from unauthenticated
 * plaintext headers — are single-flight <b>and</b> rate-limited to one per retry interval per
 * SecurityGroup, so spoofed datagrams cannot drive back-to-back {@code GetSecurityKeys} calls
 * against the SKS; the scheduled cadence remains the recovery path.
 *
 * <p><b>Component state wiring</b> (§5.4.5.3): components registered before the first successful
 * fetch stay {@code PreOperational} — {@code startupCompleted} fires when every SecurityGroupRef a
 * component registered for has usable keys (a multi-ref component registers its complete ref set
 * atomically via {@link #registerAll}, so a fetch completing mid-registration can never observe a
 * partial set and complete startup early). When the last available key is expired beyond twice the
 * KeyLifetime (§6.2.12.2), registered components are failed to {@code Error} — publishers stop
 * sending ({@link #publishContext} returns null) and subscribers stop resolving — and a later
 * successful fetch recovers exactly the components this manager failed, only once every
 * SecurityGroupRef the component registered for holds usable (non-stale) key material again.
 *
 * <p><b>Token schedule</b> (§8.3.2): fetches always request StartingTokenId 0, so the returned
 * FirstTokenId is the current token at fetch time; the active token advances at TimeToNextKey and
 * then every KeyLifetime, computed lazily against the injected clock. Between the last key's expiry
 * and the 2x-KeyLifetime deadline the publisher keeps using the last available (expired) key, per
 * the §6.2.12.2 wording. A {@link SecurityKeySet} with both durations zero is the static-key form:
 * no rotation is ever scheduled and the keys never expire.
 *
 * <p><b>FirstTokenId dedup/discard</b> (§8.3.2): a fetch whose token range overlaps the current
 * window is merged, keeping the existing material (and its nonce counter) for already-known token
 * ids; a fetch with an unknown FirstTokenId discards and replaces the window. A fetched duplicate
 * token id whose key <b>bytes</b> differ from the held material is proof of a provider restart (the
 * dedup rule presumes one continuous key stream), so such a fetch replaces the window instead of
 * merging. The subscriber window retains one previous token plus the current and future tokens (the
 * §8.3.2 overlap allowance); a token id below the window is a past key and is never re-fetched.
 *
 * <p><b>K8 policy precedence</b>: the provider-returned {@link SecurityKeySet#securityPolicyUri()}
 * must be a supported policy and must equal every registering component's configured policy URI
 * (when one is configured), else the fetch is treated as <b>failed</b> — key material is never
 * silently used under a different security level than the operator pinned. The same gate runs at
 * {@link #register} time against keys already held, so a component registering after the fetch
 * completed fails with {@code Bad_ConfigurationError} instead of silently adopting the held policy.
 *
 * <p><b>Nonce state</b>: each token carries its own nonce state — 4 random bytes generated when the
 * token's key first becomes active and a counter starting at 1, incremented once per NetworkMessage
 * (Table 156). The {@link MessageSecurityContext} handed to a publish cycle captures one coherent
 * (token, material, nonce-state) triple, so a key switch concurrent with a publish cycle can never
 * pair a nonce counter with the wrong key; the counter is atomic because multiple writer groups may
 * share one SecurityGroup. A counter exhausting the UInt32 range fails the nonce supplier rather
 * than ever repeating a (key, nonce) pair.
 *
 * <p><b>Material destruction</b>: {@link SecurityKeyMaterial} that leaves the token window (or is
 * released at shutdown) is destroyed on the scheduled executor after a fixed grace period ({@value
 * #DESTROY_GRACE_SECONDS} s). The decode path borrows window material for one synchronous codec
 * call on the connection dispatch thread — orders of magnitude shorter than the grace period. A
 * publish cycle holds its {@link MessageSecurityContext} across the whole cycle, which includes
 * user-supplied dataset source reads of unbounded duration, so {@link #publishContext} hands each
 * cycle its own <b>copy</b> of the key material (destroyed by the cycle owner when the cycle
 * completes) instead of a window reference: window material is only ever read under the manager
 * lock while it is still inside the window, so no borrower can still be in flight when destroy
 * runs. If that assumption were ever violated the borrower fails with {@code IllegalStateException}
 * (counted as an error) rather than using zeroed key bytes.
 *
 * <p>Threading: one manager-wide lock guards all state; the lock is never held across provider
 * fetches or {@link PubSubStateMachine} calls (state machine notifications are collected under the
 * lock and run after releasing it, keeping the engine-lock ordering one-way).
 */
final class SecurityKeyManager {

  private static final Logger LOGGER = LoggerFactory.getLogger(SecurityKeyManager.class);

  /** Floor for the refresh cadence, guarding against degenerate KeyLifetime values. */
  private static final long MIN_REFRESH_NANOS = TimeUnit.SECONDS.toNanos(1);

  /** Ceiling for the retry delay while fetches fail (§5.4.5.3 "faster rate than the lifetime"). */
  private static final long MAX_FAILURE_RETRY_NANOS = TimeUnit.SECONDS.toNanos(10);

  /** Grace period between a material leaving the window and its destruction. */
  static final long DESTROY_GRACE_SECONDS = 5;

  private final Object lock = new Object();

  private final PubSubStateMachine stateMachine;
  private final DiagnosticsCollector diagnostics;
  private final ScheduledExecutorService scheduler;
  private final Function<SecurityGroupRef, @Nullable SecurityKeyProvider> providers;
  private final Supplier<byte[]> nonceRandomSupplier;
  private final LongSupplier nanoClock;

  /** Guarded by {@link #lock}. */
  private final Map<SecurityGroupRef, GroupKeyState> states = new HashMap<>();

  /**
   * The SecurityGroupRefs each registered component consumes keys for. Guarded by {@link #lock}.
   */
  private final Map<AbstractComponentRuntime, Set<SecurityGroupRef>> componentRefs =
      new HashMap<>();

  /** Guarded by {@link #lock}. */
  private boolean shutdown = false;

  SecurityKeyManager(
      PubSubStateMachine stateMachine,
      DiagnosticsCollector diagnostics,
      ScheduledExecutorService scheduler,
      Function<SecurityGroupRef, @Nullable SecurityKeyProvider> providers,
      Supplier<byte[]> nonceRandomSupplier,
      LongSupplier nanoClock) {

    this.stateMachine = stateMachine;
    this.diagnostics = diagnostics;
    this.scheduler = scheduler;
    this.providers = providers;
    this.nonceRandomSupplier = nonceRandomSupplier;
    this.nanoClock = nanoClock;
  }

  /** One SecurityGroupRef a component consumes keys for; see {@link #registerAll}. */
  record Registration(
      SecurityGroupConfig group, SecurityGroupRef ref, @Nullable String configuredPolicyUri) {}

  /**
   * Register {@code component} as a consumer of keys for {@code ref}, creating the per-group key
   * state and scheduling the initial fetch when this is the first consumer. Called under the engine
   * lock from a component's activate hook; the initial fetch runs asynchronously on the scheduled
   * executor. Components consuming multiple SecurityGroupRefs must register them all in one {@link
   * #registerAll} call instead.
   *
   * @param group the resolved SecurityGroup configuration of {@code ref}.
   * @param ref the SecurityGroupRef the component consumes keys for.
   * @param component the consuming component runtime (a writer or reader group).
   * @param configuredPolicyUri the component's effective configured policy URI, or {@code null}
   *     when the configuration does not constrain the policy (K8: any supported provider policy is
   *     then accepted).
   * @throws UaException with {@code Bad_ConfigurationError} if no {@link SecurityKeyProvider} is
   *     bound for {@code ref}, or if keys are already held under a policy that does not match
   *     {@code configuredPolicyUri} (the K8 gate at registration time).
   */
  void register(
      SecurityGroupConfig group,
      SecurityGroupRef ref,
      AbstractComponentRuntime component,
      @Nullable String configuredPolicyUri)
      throws UaException {

    registerAll(List.of(new Registration(group, ref, configuredPolicyUri)), component);
  }

  /**
   * Register {@code component} as a consumer of keys for every ref in {@code registrations},
   * atomically: the component's complete ref set is recorded — and every registration validated —
   * under one lock acquisition <b>before</b> any initial fetch is scheduled, so a fast provider
   * completing the first ref's fetch can never observe a partial ref set and complete the
   * component's startup while later refs still lack keys. On a validation failure nothing is
   * registered (no partial commit).
   *
   * @param registrations the refs the component consumes keys for, each with its resolved
   *     SecurityGroup configuration and effective configured policy URI (see {@link #register}).
   * @param component the consuming component runtime (a writer or reader group).
   * @throws UaException with {@code Bad_ConfigurationError} if any ref has no bound {@link
   *     SecurityKeyProvider}, or already holds keys under a policy mismatching that ref's
   *     configured URI (the K8 gate at registration time).
   */
  void registerAll(List<Registration> registrations, AbstractComponentRuntime component)
      throws UaException {

    var fetchNow = new ArrayList<SecurityGroupRef>(0);

    synchronized (lock) {
      if (shutdown) {
        return;
      }

      // validate-first, commit-second: a throw from a later registration must not leave the
      // component half-registered (a half-registered Error component would still be failed and
      // recovered by this manager for refs it never completed activation with)
      var newProviders = new HashMap<SecurityGroupRef, SecurityKeyProvider>(0);
      for (Registration registration : registrations) {
        SecurityGroupRef ref = registration.ref();
        GroupKeyState state = states.get(ref);
        if (state == null) {
          SecurityKeyProvider provider = providers.apply(ref);
          if (provider == null) {
            throw new UaException(
                StatusCodes.Bad_ConfigurationError,
                "no SecurityKeyProvider bound for SecurityGroup '%s'".formatted(ref.name()));
          }
          newProviders.put(ref, provider);
          continue;
        }

        // The K8 gate at registration time: the fetch-completion gate (validateKeySet) only sees
        // the consumers registered when the fetch completes, so a component registering after keys
        // are already held must be validated here — otherwise it would silently operate under the
        // held policy instead of the URI the operator pinned, until the next fetch at the
        // earliest.
        PubSubSecurityPolicy heldPolicy = state.policy;
        String configuredPolicyUri = registration.configuredPolicyUri();
        if (state.haveKeys
            && configuredPolicyUri != null
            && heldPolicy != null
            && !configuredPolicyUri.equals(heldPolicy.getUri())) {
          throw new UaException(
              StatusCodes.Bad_ConfigurationError,
              ("SecurityGroup '%s' holds keys for policy '%s' but '%s' is configured for '%s'")
                  .formatted(
                      ref.name(), heldPolicy.getUri(), configuredPolicyUri, component.path()));
        }
      }

      for (Registration registration : registrations) {
        SecurityGroupRef ref = registration.ref();
        GroupKeyState state = states.get(ref);
        if (state == null) {
          state = new GroupKeyState(ref, registration.group(), newProviders.get(ref));
          state.lastWireTriggerNanos = nanoClock.getAsLong();
          states.put(ref, state);
          fetchNow.add(ref);
        }
        state.consumers.put(component, registration.configuredPolicyUri());
        componentRefs.computeIfAbsent(component, c -> new LinkedHashSet<>()).add(ref);
      }
    }

    fetchNow.forEach(this::executeFetch);
  }

  /**
   * Whether every SecurityGroupRef {@code component} registered for currently has usable
   * (non-stale, §6.2.12.2) key material — i.e. whether the component's security startup is already
   * complete at registration time.
   */
  boolean allKeysAvailable(AbstractComponentRuntime component) {
    synchronized (lock) {
      return allKeysAvailableLocked(component, nanoClock.getAsLong());
    }
  }

  /**
   * Unregister {@code component} from every key state it registered for. When a state loses its
   * last consumer its refresh task is cancelled and its window is retired. Idempotent; called under
   * the engine lock from the component's deactivate hook.
   */
  void unregister(AbstractComponentRuntime component) {
    synchronized (lock) {
      Set<SecurityGroupRef> refs = componentRefs.remove(component);
      if (refs == null) {
        return;
      }
      for (SecurityGroupRef ref : refs) {
        GroupKeyState state = states.get(ref);
        if (state == null) {
          continue;
        }
        state.consumers.remove(component);
        state.failedForKeys.remove(component);
        if (state.consumers.isEmpty()) {
          states.remove(ref);
          disposeState(state);
        }
      }
    }
  }

  /**
   * Resolve the message security context for one publish cycle of a writer group secured by {@code
   * ref}: the active token, its material, and its nonce supplier — one coherent triple for the
   * whole cycle.
   *
   * <p>Returns {@code null} when no usable key is available (no successful fetch yet, or the last
   * available key is expired beyond twice the KeyLifetime): the cycle must not send anything
   * (§6.2.12.2 "stop sending messages secured with the expired key"). State transitions for the
   * stale case are handled here (once per staleness episode). Called on the publish thread; never
   * blocks and never fetches.
   *
   * <p>The returned context carries a cycle-owned <b>copy</b> of the key material: the cycle's
   * borrow spans user-supplied dataset source reads of unbounded duration, so it must never
   * reference window material that retirement may destroy mid-cycle. The caller owns the copy and
   * should {@link SecurityKeyMaterial#destroy() destroy} it when the cycle completes.
   *
   * @param ref the SecurityGroupRef securing the group.
   * @param mode the group's effective security mode; Sign or SignAndEncrypt.
   * @return the context for this cycle, or {@code null} when the cycle must not send.
   */
  @Nullable MessageSecurityContext publishContext(SecurityGroupRef ref, MessageSecurityMode mode) {
    List<Runnable> notifications = new ArrayList<>(0);
    try {
      synchronized (lock) {
        GroupKeyState state = states.get(ref);
        if (state == null || !state.haveKeys) {
          return null;
        }
        PubSubSecurityPolicy policy = state.policy;
        if (policy == null) {
          return null;
        }

        long now = nanoClock.getAsLong();

        if (checkStale(state, now, notifications)) {
          return null;
        }

        long activeToken = activeTokenId(state, now);
        TokenKey tokenKey = state.window.get(activeToken);
        if (tokenKey == null) {
          // defensive: activeTokenId clamps into the window whenever haveKeys is true
          return null;
        }

        NonceState nonceState = tokenKey.nonceState;
        if (nonceState == null) {
          nonceState = new NonceState(nonceRandomSupplier.get());
          tokenKey.nonceState = nonceState;
        }

        pruneWindow(state, activeToken);

        // hand the cycle its own copy (see the method Javadoc): the copy is made under the lock
        // while the material is still inside the window, so it can never race the (grace-delayed)
        // destroy of retired material
        SecurityKeyMaterial material = tokenKey.material;
        SecurityKeyMaterial cycleCopy =
            SecurityKeyMaterial.of(
                policy,
                material.getSigningKey(),
                material.getEncryptingKey(),
                material.getKeyNonce());

        return MessageSecurityContext.of(
            mode, policy, uint(activeToken), cycleCopy, nonceSupplier(nonceState));
      }
    } finally {
      notifications.forEach(Runnable::run);
    }
  }

  /** Why a subscriber-side token lookup did not resolve. */
  enum SubscriberKeyReason {
    /** The token resolved to usable key material. */
    RESOLVED,
    /**
     * The token is not (yet) in the window: a key refresh is triggered (§8.3.2 "If the
     * CurrentTokenId in the message is not recognized the receiver shall call this Method again") —
     * at most one in flight, and at most one per retry interval (the token id arrives in an
     * unauthenticated plaintext header, so wire-triggered refreshes are rate-limited).
     */
    UNKNOWN_TOKEN,
    /**
     * The token's key is expired beyond twice the KeyLifetime (§6.2.12.2) or names a past key no
     * longer held (past keys are never re-fetched).
     */
    STALE_KEY
  }

  /** The result of a subscriber-side token lookup. */
  record SubscriberKey(@Nullable SecurityKeyMaterial material, SubscriberKeyReason reason) {}

  /**
   * Look up the key material for a received SecurityTokenId within {@code ref}'s token window.
   * SecurityTokenId 0 — the literal Table 154 sign-only SecurityHeader form K4 accepts on decode —
   * resolves to the currently active key (token ids are 1-based, so 0 never names a real token).
   * Called on the connection dispatch thread; never blocks — an unknown token triggers an
   * asynchronous refresh (single-flight, rate-limited per {@link #wireTriggerAllowedLocked}) and
   * the message is dropped by the caller, never buffered.
   */
  SubscriberKey subscriberKey(SecurityGroupRef ref, UInteger securityTokenId) {
    boolean refresh = false;
    try {
      synchronized (lock) {
        GroupKeyState state = states.get(ref);
        if (state == null) {
          // an unregistered ref indicates a wiring gap (nothing can ever fetch keys for it):
          // resolvers should only offer refs their components registered
          LOGGER.warn(
              "subscriberKey lookup for unregistered SecurityGroup '{}' (no consumer registered)",
              ref.name());
          return new SubscriberKey(null, SubscriberKeyReason.UNKNOWN_TOKEN);
        }

        long token = securityTokenId.longValue();
        long now = nanoClock.getAsLong();

        if (token == 0 && state.haveKeys) {
          // K4 accepts the literal Table 154 sign-only SecurityHeader form (SecurityTokenId 0,
          // empty nonce). Token ids are 1-based (§8.3.2: they start at 1 and restart at 1 after
          // wrapping), so 0 never names a real token: treat it as naming the currently active
          // key (for the static-key form that is the single static token).
          token = activeTokenId(state, now);
        }

        TokenKey tokenKey = state.window.get(token);
        if (tokenKey != null) {
          if (!state.staticKeys && now > tokenUsableUntil(state, token)) {
            return new SubscriberKey(null, SubscriberKeyReason.STALE_KEY);
          }
          return new SubscriberKey(tokenKey.material, SubscriberKeyReason.RESOLVED);
        }

        if (state.haveKeys && token < state.window.firstKey()) {
          // a past key no longer held: never re-fetched (K6)
          return new SubscriberKey(null, SubscriberKeyReason.STALE_KEY);
        }

        // unknown (future or never-fetched) token: at most one refresh in flight and at most one
        // per retry interval, drop meanwhile. Static key sets never rotate, so re-fetching
        // cannot learn new tokens.
        refresh = !(state.staticKeys && state.haveKeys) && wireTriggerAllowedLocked(state, now);
        return new SubscriberKey(null, SubscriberKeyReason.UNKNOWN_TOKEN);
      }
    } finally {
      if (refresh) {
        executeFetch(ref);
      }
    }
  }

  /**
   * Handle a received force-key-reset signal (SecurityFlags bit 3, Table 154): the publisher is
   * about to invalidate its keys, so proactively refresh (single-flight and rate-limited like the
   * unknown-token trigger — the bit rides an unauthenticated plaintext header; K6 subscriber side).
   */
  void forceKeyReset(SecurityGroupRef ref) {
    synchronized (lock) {
      GroupKeyState state = states.get(ref);
      if (state == null
          || (state.staticKeys && state.haveKeys)
          || !wireTriggerAllowedLocked(state, nanoClock.getAsLong())) {
        return;
      }
    }
    executeFetch(ref);
  }

  /**
   * Invalidate all keys held for {@code ref} and re-fetch under the (possibly changed)
   * SecurityGroup parameters (Part 14 §6.2.12.2: "If the SecurityPolicyUri or the KeyLifetime of an
   * existing SecurityGroup are modified, all existing keys of the SecurityGroup are invalidated").
   * Unlike the wire-triggered refreshes ({@link #subscriberKey} unknown token, {@link
   * #forceKeyReset}) this is an authorized configuration action, so it is <b>not</b> rate-limited:
   * it drops the current token window immediately — publishers stop sending ({@link
   * #publishContext} returns null) and subscribers stop resolving until fresh keys arrive, per the
   * §6.2.12.2 "breaks communication until everyone re-fetches" behavior — and schedules a fresh
   * single-flight fetch on the scheduler. Registered consumers stay registered; the fetch
   * completion re-completes/recovers them through the normal {@link #applyKeySet} path (a fetch
   * returning key material under a policy that no longer matches a consumer's configured URI fails
   * the K8 gate, so the group correctly refuses stale-policy keys until the provider serves the new
   * policy). No-op if {@code ref} has no live key state (an unsecured group, or no consumer has
   * registered for it).
   *
   * <p>Called off the engine lock (never across I/O) after a successful reconfigure that changed
   * the group's policy or lifetime. The group's own reconfigure restart already re-registers it
   * under the new configuration and disposes the old key state when it was the group's last
   * consumer; this explicit invalidation additionally guarantees the drop when the SecurityGroup is
   * shared by another still-registered group, whose surviving registration would otherwise keep the
   * stale (old-policy, old-lifetime) window alive.
   *
   * @param ref the SecurityGroupRef whose keys are invalidated.
   */
  void invalidate(SecurityGroupRef ref) {
    synchronized (lock) {
      if (shutdown) {
        return;
      }
      GroupKeyState state = states.get(ref);
      if (state == null) {
        return;
      }
      cancelRefresh(state);
      state.window.values().forEach(tokenKey -> retire(tokenKey.material));
      state.window.clear();
      state.policy = null;
      state.haveKeys = false;
      state.staleFailed = false;
    }
    executeFetch(ref);
  }

  /**
   * Whether a wire-triggered refresh (unknown SecurityTokenId, force-key-reset bit) may fire now,
   * consuming the trigger slot when it may: both triggers are read from unauthenticated plaintext
   * SecurityHeader fields, so without a rate bound an off-path attacker spraying spoofed token ids
   * would drive one full {@code GetSecurityKeys} round trip per datagram against the SKS (and flood
   * the shared scheduler with no-op fetch tasks). Bounded to one trigger per retry interval ({@link
   * #retryDelayNanos}: KeyLifetime/2 clamped to [1 s, 10 s]) per SecurityGroup — an immediate
   * re-fetch after a completed fetch cannot learn a token the provider's current window does not
   * contain, and the scheduled KeyLifetime/2 cadence remains the recovery path. Must be called
   * holding {@link #lock}.
   */
  private boolean wireTriggerAllowedLocked(GroupKeyState state, long now) {
    if (state.fetchInFlight || now - state.lastWireTriggerNanos < retryDelayNanos(state)) {
      return false;
    }
    state.lastWireTriggerNanos = now;
    return true;
  }

  /**
   * The current token id and time to the next key switch of {@code ref}, or {@code null} when no
   * keys are available: the feed for the Phase 5 R13 {@code SecurityTokenID} / {@code
   * TimeToNextTokenID} LiveValues.
   */
  @Nullable TokenInfo tokenInfo(SecurityGroupRef ref) {
    synchronized (lock) {
      GroupKeyState state = states.get(ref);
      if (state == null || !state.haveKeys) {
        return null;
      }
      long now = nanoClock.getAsLong();
      long activeToken = activeTokenId(state, now);
      if (state.staticKeys) {
        return new TokenInfo(uint(activeToken), Duration.ZERO);
      }
      long nextSwitchNanos =
          state.fetchNanos
              + state.timeToNextKeyNanos
              + (activeToken - state.firstTokenIdAtFetch) * state.keyLifetimeNanos;
      return new TokenInfo(uint(activeToken), Duration.ofNanos(Math.max(0, nextSwitchNanos - now)));
    }
  }

  /** The current token id and time until it is replaced; static keys report {@code ZERO}. */
  record TokenInfo(UInteger securityTokenId, Duration timeToNextKey) {}

  /** The delay the most recent refresh was scheduled with; test/diagnostic introspection. */
  @Nullable Long scheduledRefreshDelayNanos(SecurityGroupRef ref) {
    synchronized (lock) {
      GroupKeyState state = states.get(ref);
      return state != null ? state.scheduledDelayNanos : null;
    }
  }

  /** Cancel all refresh tasks and retire all key material. */
  void shutdown() {
    synchronized (lock) {
      shutdown = true;
      states.values().forEach(this::disposeState);
      states.clear();
      componentRefs.clear();
    }
  }

  // region internals

  /**
   * Whether every SecurityGroupRef {@code component} registered for holds usable key material:
   * fetched and not expired beyond the 2x-KeyLifetime deadline (§6.2.12.2). Startup completion and
   * recovery both require ALL refs usable — completing or recovering on one ref's good fetch while
   * another ref's keys are missing or stale would report {@code Operational} for a component that
   * cannot process that other ref's traffic. Must be called holding {@link #lock}.
   */
  private boolean allKeysAvailableLocked(AbstractComponentRuntime component, long now) {
    Set<SecurityGroupRef> refs = componentRefs.get(component);
    if (refs == null || refs.isEmpty()) {
      return false;
    }
    for (SecurityGroupRef ref : refs) {
      GroupKeyState state = states.get(ref);
      if (state == null || !state.haveKeys || isStaleLocked(state, now)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Remove {@code component} from the {@code failedForKeys} marker set of every state it consumes,
   * returning whether any marker was present: the recovery precondition check across ALL of a
   * multi-ref component's states (the marker may live in a different state than the one whose fetch
   * completed). Must be called holding {@link #lock}.
   */
  private boolean clearFailedMarkersLocked(AbstractComponentRuntime component) {
    boolean failed = false;
    Set<SecurityGroupRef> refs = componentRefs.get(component);
    if (refs != null) {
      for (SecurityGroupRef ref : refs) {
        GroupKeyState state = states.get(ref);
        if (state != null) {
          failed |= state.failedForKeys.remove(component);
        }
      }
    }
    return failed;
  }

  /** Must be called holding {@link #lock}. */
  private void disposeState(GroupKeyState state) {
    ScheduledFuture<?> task = state.refreshTask;
    state.refreshTask = null;
    if (task != null) {
      task.cancel(false);
    }
    state.window.values().forEach(tokenKey -> retire(tokenKey.material));
    state.window.clear();
    state.haveKeys = false;
  }

  /**
   * Schedule the destruction of retired material after the grace period; see the class Javadoc for
   * why the grace period guarantees no borrower is still in flight.
   */
  private void retire(SecurityKeyMaterial material) {
    try {
      scheduler.schedule(material::destroy, DESTROY_GRACE_SECONDS, TimeUnit.SECONDS);
    } catch (RejectedExecutionException e) {
      // executor shutting down: destroy inline; nothing can borrow the material anymore
      material.destroy();
    }
  }

  /** Hop a fetch onto the scheduled executor; never fetches on the calling thread. */
  private void executeFetch(SecurityGroupRef ref) {
    try {
      scheduler.execute(() -> fetch(ref));
    } catch (RejectedExecutionException e) {
      LOGGER.debug("Scheduler rejected key fetch for SecurityGroup '{}'", ref.name());
    }
  }

  /** Runs on the scheduled executor. Single-flight: no-op while a fetch is in flight. */
  private void fetch(SecurityGroupRef ref) {
    GroupKeyState state;
    SecurityKeyProvider provider;
    String securityGroupId;
    UInteger requestedKeyCount;
    long timeoutNanos;

    synchronized (lock) {
      state = states.get(ref);
      if (state == null || shutdown || state.fetchInFlight) {
        return;
      }
      state.fetchInFlight = true;
      provider = state.provider;
      securityGroupId = state.securityGroupId;
      requestedKeyCount = state.requestedKeyCount;
      // bound the fetch so a provider future that never completes cannot wedge the single-flight
      // gate (SKS pull providers are unbounded by default); the timeout fails the fetch and the
      // normal retry cadence takes over
      timeoutNanos = retryDelayNanos(state);
    }

    CompletableFuture<SecurityKeySet> future;
    try {
      // StartingTokenId 0 always: "Publishers using a central SKS shall call GetSecurityKeys
      // always with StartingTokenId set to 0" (§8.3.2); past keys are never re-fetched (K6)
      future = provider.getKeys(securityGroupId, uint(0), requestedKeyCount);
    } catch (RuntimeException e) {
      future = CompletableFuture.failedFuture(e);
    }

    // the completion captures the GroupKeyState the fetch was started for, so a completion
    // arriving after unregister/re-register replaced the state (in-flight fetches are bounded by
    // orTimeout, not cancelled) can be recognized and discarded — see onFetchComplete
    GroupKeyState fetchState = state;
    future
        .orTimeout(timeoutNanos, TimeUnit.NANOSECONDS)
        .whenComplete((keySet, ex) -> onFetchComplete(ref, fetchState, keySet, ex));
  }

  /** Runs on whatever thread completed the provider future. */
  private void onFetchComplete(
      SecurityGroupRef ref,
      GroupKeyState state,
      @Nullable SecurityKeySet keySet,
      @Nullable Throwable ex) {

    var notifications = new ArrayList<Runnable>(0);

    synchronized (lock) {
      if (states.get(ref) != state) {
        // a stale completion: the state this fetch was started for was disposed (unregister,
        // reconfigure restart) and possibly replaced by a successor with its own key stream and
        // its own in-flight fetch. Applying the result would key the successor with a dead
        // generation's material, and clearing fetchInFlight would break its single-flight gate.
        return;
      }
      state.fetchInFlight = false;
      if (shutdown) {
        return;
      }

      long now = nanoClock.getAsLong();

      String error = null;
      if (ex != null) {
        error = "security key fetch failed: " + rootMessage(ex);
      } else if (keySet != null) {
        error = validateKeySet(state, keySet);
        if (error == null) {
          error = applyKeySet(state, keySet, now, notifications);
        }
      } else {
        error = "security key fetch failed: provider returned null";
      }

      if (error != null) {
        recordFetchFailure(state, error, ex, notifications);
        checkStale(state, now, notifications);
        scheduleRefresh(ref, state, retryDelayNanos(state));
      }
    }

    notifications.forEach(Runnable::run);
  }

  /**
   * The K8 gate: the provider-returned policy URI must be supported and must match every consumer's
   * configured URI (when configured). Returns an error message, or null when valid. Must be called
   * holding {@link #lock}.
   */
  private static @Nullable String validateKeySet(GroupKeyState state, SecurityKeySet keySet) {
    Optional<PubSubSecurityPolicy> policy =
        PubSubSecurityPolicy.fromUri(keySet.securityPolicyUri());
    if (policy.isEmpty()) {
      return "security key fetch failed: unsupported security policy URI '%s'"
          .formatted(keySet.securityPolicyUri());
    }
    for (Map.Entry<AbstractComponentRuntime, @Nullable String> consumer :
        state.consumers.entrySet()) {
      String configuredUri = consumer.getValue();
      if (configuredUri != null && !configuredUri.equals(keySet.securityPolicyUri())) {
        // never silently downgrade/re-key: a mismatching provider policy fails the fetch (K8)
        return ("security key fetch failed: provider returned policy '%s' but '%s' is configured"
                + " for '%s'")
            .formatted(keySet.securityPolicyUri(), configuredUri, consumer.getKey().path());
      }
    }
    return null;
  }

  /**
   * Apply a validated key set: split materials, merge or replace the window per the §8.3.2
   * FirstTokenId rule, update the switch schedule, and complete/recover consumers. Returns an error
   * message when the key data itself is invalid. Must be called holding {@link #lock}.
   */
  private @Nullable String applyKeySet(
      GroupKeyState state, SecurityKeySet keySet, long now, List<Runnable> notifications) {

    PubSubSecurityPolicy policy =
        PubSubSecurityPolicy.fromUri(keySet.securityPolicyUri()).orElseThrow();

    long firstTokenId = keySet.firstTokenId().longValue();
    List<ByteString> keys = keySet.keys();

    var fetched = new LinkedHashMap<Long, SecurityKeyMaterial>(keys.size());
    try {
      for (int i = 0; i < keys.size(); i++) {
        fetched.put(firstTokenId + i, SecurityKeyMaterial.of(policy, keys.get(i)));
      }
    } catch (IllegalArgumentException e) {
      fetched.values().forEach(SecurityKeyMaterial::destroy);
      return "security key fetch failed: " + e.getMessage();
    }

    // §8.3.2 FirstTokenId rule: overlap with the known window => merge, eliminating duplicates
    // (keep the existing material and its nonce state for known ids); unknown FirstTokenId =>
    // discard the existing list and replace. A policy change always replaces.
    boolean overlaps =
        state.haveKeys
            && state.policy == policy
            && firstTokenId <= state.window.lastKey()
            && firstTokenId + keys.size() > state.window.firstKey();

    if (overlaps) {
      // the §8.3.2 merge rule presumes one continuous key stream: a fetched duplicate token id
      // whose key bytes DIFFER from the held material is proof of a provider restart that
      // restarted token ids near the held window — merging would mix two unrelated key
      // generations (publisher signs with keys no restarted-SKS subscriber holds, subscriber
      // cannot verify the new generation) for up to (lastHeldId - currentId) KeyLifetimes, so
      // treat the fetch as a restart and discard-and-replace instead
      for (Map.Entry<Long, SecurityKeyMaterial> entry : fetched.entrySet()) {
        TokenKey existing = state.window.get(entry.getKey());
        if (existing != null && !sameKeyBytes(existing.material, entry.getValue())) {
          LOGGER.warn(
              "fetched key material for token {} differs from held material; treating the fetch"
                  + " as a provider restart and replacing the window (SecurityGroup '{}')",
              entry.getKey(),
              state.ref.name());
          overlaps = false;
          break;
        }
      }
    }

    if (!overlaps) {
      state.window.values().forEach(tokenKey -> retire(tokenKey.material));
      state.window.clear();
    }

    fetched.forEach(
        (tokenId, material) -> {
          TokenKey existing = state.window.get(tokenId);
          if (existing != null) {
            // duplicate of a known token: keep the existing material + nonce counter
            material.destroy();
          } else {
            state.window.put(tokenId, new TokenKey(material));
          }
        });

    state.policy = policy;
    state.fetchNanos = now;
    state.firstTokenIdAtFetch = firstTokenId;
    state.timeToNextKeyNanos = keySet.timeToNextKey().toNanos();
    state.keyLifetimeNanos = keySet.keyLifetime().toNanos();
    state.staticKeys = keySet.timeToNextKey().isZero() && keySet.keyLifetime().isZero();
    state.haveKeys = true;
    state.staleFailed = false;

    // the fetch names the current token: retain one previous token plus current + futures
    pruneWindow(state, firstTokenId);

    for (AbstractComponentRuntime component : state.consumers.keySet()) {
      if (!allKeysAvailableLocked(component, now)) {
        // a multi-ref component with another ref still lacking usable keys is neither started
        // nor recovered by this fetch — and its failure markers are deliberately NOT consumed:
        // the later good fetch of the outstanding ref performs the recovery (K6)
        continue;
      }
      boolean failed = clearFailedMarkersLocked(component);
      notifications.add(() -> stateMachine.startupCompleted(component));
      if (failed) {
        // recover only components THIS manager failed; never resurrect unrelated Errors
        notifications.add(() -> stateMachine.recover(component));
      }
    }

    if (!state.staticKeys) {
      scheduleRefresh(state.ref, state, refreshDelayNanos(state));
    } else {
      cancelRefresh(state);
    }

    return null;
  }

  /** Must be called holding {@link #lock}. */
  private void recordFetchFailure(
      GroupKeyState state, String message, @Nullable Throwable ex, List<Runnable> notifications) {

    StatusCode statusCode =
        ex != null
            ? UaException.extractStatusCode(ex)
                .orElse(new StatusCode(StatusCodes.Bad_InternalError))
            : new StatusCode(StatusCodes.Bad_ConfigurationError);

    String detail = "%s (SecurityGroup '%s')".formatted(message, state.ref.name());
    LOGGER.warn("{}", detail, ex);

    for (AbstractComponentRuntime component : state.consumers.keySet()) {
      String path = component.path();
      notifications.add(() -> diagnostics.error(path, statusCode, detail, ex));
    }
  }

  /**
   * Fail registered consumers when the last available key is expired beyond twice the KeyLifetime
   * (§6.2.12.2): once per staleness episode. Returns whether the state is stale. Must be called
   * holding {@link #lock}.
   *
   * <p>A consumer joins {@code failedForKeys} — the marker set a later good fetch recovers from —
   * only when the {@code fail} call actually transitioned it to {@code Error}: a component already
   * in {@code Error} for an unrelated reason (e.g. its activation threw after registering) must
   * never be resurrected to {@code Operational} by a key fetch, because {@code recover} does not
   * re-run its activation.
   */
  private boolean checkStale(GroupKeyState state, long now, List<Runnable> notifications) {
    boolean stale = isStaleLocked(state, now);

    if (stale && !state.staleFailed) {
      state.staleFailed = true;
      var statusCode = new StatusCode(StatusCodes.Bad_SecurityChecksFailed);
      String message =
          ("security key material expired: no new keys within two times the KeyLifetime"
                  + " (SecurityGroup '%s')")
              .formatted(state.ref.name());
      for (AbstractComponentRuntime component : state.consumers.keySet()) {
        String path = component.path();
        notifications.add(() -> diagnostics.error(path, statusCode, message, null));
        notifications.add(
            () -> {
              if (stateMachine.fail(component, statusCode)) {
                synchronized (lock) {
                  // guard against the state having been disposed/replaced or the component
                  // unregistered between the collection under the lock and this notification
                  if (states.get(state.ref) == state && state.consumers.containsKey(component)) {
                    state.failedForKeys.add(component);
                  }
                }
              }
            });
      }
    }

    return stale;
  }

  /**
   * Whether the last available key is expired beyond twice the KeyLifetime (§6.2.12.2). The
   * static-key form never expires. Must be called holding {@link #lock}; requires {@code
   * state.window} non-empty when {@code state.haveKeys}.
   */
  private static boolean isStaleLocked(GroupKeyState state, long now) {
    if (!state.haveKeys || state.staticKeys) {
      return false;
    }
    long lastKeyExpiry =
        state.fetchNanos
            + state.timeToNextKeyNanos
            + (state.window.lastKey() - state.firstTokenIdAtFetch) * state.keyLifetimeNanos;
    return now - lastKeyExpiry > 2 * state.keyLifetimeNanos;
  }

  /**
   * Constant-time comparison of two materials' key parts, for the provider-restart detection in
   * {@link #applyKeySet}: same policy and identical SigningKey, EncryptingKey, and KeyNonce bytes.
   */
  private static boolean sameKeyBytes(SecurityKeyMaterial held, SecurityKeyMaterial fetched) {
    return held.getPolicy() == fetched.getPolicy()
        && MessageDigest.isEqual(held.getSigningKey(), fetched.getSigningKey())
        && MessageDigest.isEqual(held.getEncryptingKey(), fetched.getEncryptingKey())
        && MessageDigest.isEqual(held.getKeyNonce(), fetched.getKeyNonce());
  }

  /**
   * The active token id at {@code now}: the fetch-time current token, advanced at TimeToNextKey and
   * then every KeyLifetime, clamped to the last available key (§6.2.12.2 allows the publisher to
   * keep using the expired last key until the 2x deadline). Must be called holding {@link #lock};
   * requires {@code state.haveKeys}.
   */
  private static long activeTokenId(GroupKeyState state, long now) {
    if (state.staticKeys) {
      return state.firstTokenIdAtFetch;
    }
    long elapsed = now - state.fetchNanos;
    long index;
    if (elapsed < state.timeToNextKeyNanos || state.keyLifetimeNanos <= 0) {
      index = 0;
    } else {
      index = 1 + (elapsed - state.timeToNextKeyNanos) / state.keyLifetimeNanos;
    }
    return Math.min(state.firstTokenIdAtFetch + index, state.window.lastKey());
  }

  /**
   * The instant until which {@code tokenId}'s key may still be used by a subscriber: its scheduled
   * replacement time plus twice the KeyLifetime (§6.2.12.2). Must be called holding {@link #lock}.
   */
  private static long tokenUsableUntil(GroupKeyState state, long tokenId) {
    long expiry =
        state.fetchNanos
            + state.timeToNextKeyNanos
            + (tokenId - state.firstTokenIdAtFetch) * state.keyLifetimeNanos;
    return expiry + 2 * state.keyLifetimeNanos;
  }

  /**
   * Retire tokens that left the retention window {previous, current, futures} (K6). Must be called
   * holding {@link #lock}.
   */
  private void pruneWindow(GroupKeyState state, long currentTokenId) {
    while (!state.window.isEmpty() && state.window.firstKey() < currentTokenId - 1) {
      retire(state.window.pollFirstEntry().getValue().material);
    }
  }

  /** Must be called holding {@link #lock}. */
  private void scheduleRefresh(SecurityGroupRef ref, GroupKeyState state, long delayNanos) {
    cancelRefresh(state);
    state.scheduledDelayNanos = delayNanos;
    try {
      state.refreshTask = scheduler.schedule(() -> fetch(ref), delayNanos, TimeUnit.NANOSECONDS);
    } catch (RejectedExecutionException e) {
      LOGGER.debug("Scheduler rejected key refresh for SecurityGroup '{}'", ref.name());
    }
  }

  /** Must be called holding {@link #lock}. */
  private static void cancelRefresh(GroupKeyState state) {
    ScheduledFuture<?> task = state.refreshTask;
    state.refreshTask = null;
    if (task != null) {
      task.cancel(false);
    }
  }

  /** Refresh every KeyLifetime/2 (§8.3.2 SHALL), with a floor. */
  private static long refreshDelayNanos(GroupKeyState state) {
    return Math.max(MIN_REFRESH_NANOS, state.effectiveLifetimeNanos() / 2);
  }

  /** Retry failed fetches at the refresh cadence clamped to at most 10 s (§5.4.5.3). */
  private static long retryDelayNanos(GroupKeyState state) {
    return Math.min(refreshDelayNanos(state), MAX_FAILURE_RETRY_NANOS);
  }

  private MessageNonceSupplier nonceSupplier(NonceState nonceState) {
    return () -> {
      long sequenceNumber = nonceState.counter.getAndIncrement();
      if (sequenceNumber > 0xFFFFFFFFL) {
        // never reuse a (key, nonce) pair: exhausting the UInt32 nonce space under one key fails
        // the cycle (counted as an encode error) rather than wrapping
        throw new IllegalStateException("MessageNonce sequence number space exhausted");
      }
      return UadpMessageSecurity.createMessageNonce(nonceState.random, sequenceNumber);
    };
  }

  private static String rootMessage(Throwable ex) {
    Throwable cause = ex;
    while (cause.getCause() != null && cause.getMessage() == null) {
      cause = cause.getCause();
    }
    String message = cause.getMessage();
    return message != null ? message : cause.getClass().getSimpleName();
  }

  /** All mutable fields guarded by the manager lock. */
  private static final class GroupKeyState {

    final SecurityGroupRef ref;
    final SecurityKeyProvider provider;
    final String securityGroupId;
    final UInteger requestedKeyCount;
    final long configuredLifetimeNanos;

    /** Consumer component -> its effective configured policy URI (nullable value). */
    final Map<AbstractComponentRuntime, @Nullable String> consumers = new LinkedHashMap<>();

    /** Consumers failed to {@code Error} by this manager; recovered on the next good fetch. */
    final Set<AbstractComponentRuntime> failedForKeys = new LinkedHashSet<>();

    /** Token id -> key, ascending. Token wrap past UInt32 is handled by the replace rule. */
    final TreeMap<Long, TokenKey> window = new TreeMap<>();

    @Nullable PubSubSecurityPolicy policy;
    long fetchNanos;
    long firstTokenIdAtFetch;
    long timeToNextKeyNanos;
    long keyLifetimeNanos;
    boolean staticKeys;
    boolean haveKeys;
    boolean staleFailed;
    boolean fetchInFlight;

    /**
     * When the last wire-triggered refresh (unknown token, force-key-reset bit) was allowed;
     * initialized to the registration instant so a spoofed-header burst right after the initial
     * fetch cannot immediately re-fetch. See {@link #wireTriggerAllowedLocked}.
     */
    long lastWireTriggerNanos;

    @Nullable ScheduledFuture<?> refreshTask;
    @Nullable Long scheduledDelayNanos;

    GroupKeyState(SecurityGroupRef ref, SecurityGroupConfig group, SecurityKeyProvider provider) {
      this.ref = ref;
      this.provider = provider;
      this.securityGroupId = group.getSecurityGroupId();
      this.requestedKeyCount = group.getMaxFutureKeyCount();
      this.configuredLifetimeNanos = group.getKeyLifeTime().toNanos();
    }

    long effectiveLifetimeNanos() {
      return haveKeys && keyLifetimeNanos > 0 ? keyLifetimeNanos : configuredLifetimeNanos;
    }
  }

  /** One token's key material and (publisher-side, lazily created) nonce state. */
  private static final class TokenKey {

    final SecurityKeyMaterial material;

    @Nullable NonceState nonceState;

    TokenKey(SecurityKeyMaterial material) {
      this.material = material;
    }
  }

  /**
   * Per-token nonce composition state (Table 156): the random part is generated when the key
   * becomes active, the counter starts at 1 and increments once per NetworkMessage. Atomic because
   * multiple writer groups sharing one SecurityGroup draw nonces from the same key.
   */
  private static final class NonceState {

    final byte[] random;
    final AtomicLong counter = new AtomicLong(1);

    NonceState(byte[] random) {
      this.random = random;
    }
  }

  // endregion
}
