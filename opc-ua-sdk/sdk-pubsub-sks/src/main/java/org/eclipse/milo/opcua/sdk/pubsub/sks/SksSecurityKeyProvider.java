/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.sks;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfigBuilder;
import org.eclipse.milo.opcua.sdk.client.identity.IdentityProvider;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityKeyServiceValidator;
import org.eclipse.milo.opcua.sdk.pubsub.security.KeyCredentialStore;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.security.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.DefaultClientCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.MemoryTrustListManager;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.transport.client.tcp.OpcTcpClientTransportConfigBuilder;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link SecurityKeyProvider} that pulls key material from a Security Key Service (SKS) by
 * calling the {@code GetSecurityKeys} method (NodeId i=15215 on the well-known PublishSubscribe
 * Object i=14443, OPC UA Part 14 §8.3.2) over a SignAndEncrypt client session.
 *
 * <h2>SKS resolution (Part 14 §6.2.5.4 / Table 40)</h2>
 *
 * <p>The configured {@code SecurityKeyServices} entries are SKS <em>identity records</em>, not
 * connectable endpoints (Table 40: {@code EndpointUrl} "Shall be null or empty."). Entries with
 * {@code ApplicationType} {@code Server} are tried in array order; for each entry the provider runs
 * GetEndpoints at each {@code server.discoveryUrls[j]}, keeps endpoints whose {@code
 * server.applicationUri} matches the entry's and whose security mode is SignAndEncrypt, constrains
 * them to the entry's {@code securityPolicyUri} when one is set (otherwise ranks by the discovered
 * {@code securityLevel}), and connects with a session identity chosen per the entry's {@code
 * UserIdentityTokens}: {@code Anonymous} (the default when the array is empty), or {@code UserName}
 * with credentials from the {@link KeyCredentialStore}, looked up by the entry's {@code
 * server.applicationUri} (the Part 12 KeyCredential {@code ResourceUri}). Configured token types
 * are tried in listed order; when none can be satisfied the entry fails — the provider never
 * downgrades to a token type the configuration did not list.
 *
 * <p>Tolerance fallback (on, non-spec): an entry carrying a filled {@code endpointUrl} and no
 * discovery URLs — the open62541 ecosystem shape — has its {@code endpointUrl} used as a discovery
 * target (then the same URL with {@code /discovery} appended), with a WARN logged at construction.
 * There is no LDS FindServers leg and no SessionlessInvoke support.
 *
 * <p>The resolved session is cached across fetches (Part 4 §6.1.4: discovery results change rarely)
 * and re-resolved after any failure, failing over across entries in array order. Entries are
 * validated at construction with {@link SecurityKeyServiceValidator}: errors throw {@link
 * IllegalArgumentException}, warnings are logged once.
 *
 * <h2>Results and errors</h2>
 *
 * <p>{@code GetSecurityKeys} outputs map verbatim onto {@link SecurityKeySet}; in particular the
 * returned {@code SecurityPolicyUri} is passed through untouched — the key manager, not this
 * provider, enforces the configured-policy precedence rule. Method-level failures complete the
 * future exceptionally with a {@link UaException} carrying the real {@link StatusCode} ({@code
 * Bad_NotFound} for an unknown SecurityGroupId, {@code Bad_UserAccessDenied} for missing
 * RolePermissions, {@code Bad_SecurityModeInsufficient} for an insufficiently secure channel).
 *
 * <h2>Certificate trust</h2>
 *
 * <p>The SKS certificate arrives via discovery and must be validated (Part 4 §6.1.4). The trust
 * posture is the caller's: supply a {@link CertificateValidator} — typically a {@link
 * DefaultClientCertificateValidator} over your trust lists. <b>The default is fail-closed</b>: a
 * {@link DefaultClientCertificateValidator} with an empty in-memory trust list, which rejects every
 * SKS certificate until a validator is configured. Session endpoint validation (the CreateSession
 * response comparison defense) is always enabled.
 *
 * <h2>Asynchrony and lifecycle</h2>
 *
 * <p>{@link #getKeys} never blocks: discovery, connect, and call are composed on the client's
 * futures, and overlapping fetches are serialized internally. {@link #close()} releases the cached
 * session; it does not wait for the disconnect to complete.
 *
 * <h2>Wiring</h2>
 *
 * <p>Construct one provider per SecurityGroup — the entries, the credential identity, and the
 * cached session are all per-group state — and bind it via {@code PubSubBindings}. The effective
 * entry list for a group comes from {@code EffectiveMessageSecurity}:
 *
 * <pre>{@code
 * EffectiveMessageSecurity security = EffectiveMessageSecurity.of(config, readerGroup);
 * SecurityGroupConfig group = requireNonNull(security.securityGroup());
 *
 * SksSecurityKeyProvider provider =
 *     SksSecurityKeyProvider.builder()
 *         .securityKeyServices(security.securityKeyServices())
 *         .securityGroupId(group.getSecurityGroupId())
 *         .keyCredentialStore(credentialStore)
 *         .certificateValidator(certificateValidator)
 *         .clientCustomizer(
 *             b ->
 *                 b.setApplicationUri(applicationUri)
 *                     .setCertificate(clientCertificate)
 *                     .setCertificateChain(new X509Certificate[] {clientCertificate})
 *                     .setKeyPair(clientKeyPair))
 *         .build();
 *
 * PubSubBindings bindings =
 *     PubSubBindings.builder().securityKeys(group.ref(), provider).build();
 * }</pre>
 *
 * <p>SignAndEncrypt sessions require a client certificate, its certificate chain (the single
 * certificate for self-signed setups — the chain is not derived from the certificate, and a session
 * without one fails with {@code Bad_ConfigurationError}), and a key pair; supply them (and the
 * matching application URI) through the client customizer, which runs after the provider's own
 * configuration and may override anything, including the selected endpoint.
 */
public final class SksSecurityKeyProvider implements SecurityKeyProvider, AutoCloseable {

  private final Logger logger = LoggerFactory.getLogger(SksSecurityKeyProvider.class);

  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final AtomicReference<SksClientOperations.Session> cachedSession =
      new AtomicReference<>();

  private final Object fetchLock = new Object();

  /** The tail of the serialized fetch chain; guarded by {@link #fetchLock}. */
  private CompletableFuture<?> fetchTail = CompletableFuture.completedFuture(null);

  private final List<EndpointDescription> serverEntries;
  private final @Nullable String securityGroupId;
  private final @Nullable UInteger requestedKeyCount;
  private final KeyCredentialStore keyCredentialStore;
  private final CertificateValidator certificateValidator;
  private final @Nullable Duration fetchTimeout;
  private final SksClientOperations operations;

  SksSecurityKeyProvider(Builder builder, SksClientOperations operations) {
    List<EndpointDescription> entries = List.copyOf(builder.securityKeyServices);
    if (entries.isEmpty()) {
      throw new IllegalArgumentException("securityKeyServices must not be empty");
    }

    SecurityKeyServiceValidator.Result result = SecurityKeyServiceValidator.validate(entries);
    if (!result.isValid()) {
      throw new IllegalArgumentException(
          "invalid SecurityKeyServices: " + String.join("; ", result.errors()));
    }
    result.warnings().forEach(warning -> logger.warn("SecurityKeyServices: {}", warning));

    this.serverEntries =
        entries.stream()
            .filter(
                e ->
                    e.getServer() != null
                        && e.getServer().getApplicationType() == ApplicationType.Server)
            .toList();
    if (serverEntries.isEmpty()) {
      throw new IllegalArgumentException(
          "securityKeyServices contains no ApplicationType=Server entry; "
              + "pull access requires at least one (Part 14 Table 40)");
    }

    this.securityGroupId = builder.securityGroupId;
    this.requestedKeyCount = builder.requestedKeyCount;
    this.keyCredentialStore = builder.keyCredentialStore;
    this.certificateValidator = builder.effectiveCertificateValidator();
    this.fetchTimeout = builder.fetchTimeout;
    this.operations = operations;
  }

  @Override
  public CompletableFuture<SecurityKeySet> getKeys(
      String securityGroupId, UInteger startingTokenId, UInteger requestedKeyCount) {

    if (closed.get()) {
      return CompletableFuture.failedFuture(
          new IllegalStateException("SksSecurityKeyProvider is closed"));
    }
    if (this.securityGroupId != null && !this.securityGroupId.equals(securityGroupId)) {
      return CompletableFuture.failedFuture(
          new IllegalArgumentException(
              "provider is bound to SecurityGroupId '%s', got '%s'"
                  .formatted(this.securityGroupId, securityGroupId)));
    }

    UInteger effectiveKeyCount =
        this.requestedKeyCount != null ? this.requestedKeyCount : requestedKeyCount;

    CompletableFuture<SecurityKeySet> future;
    synchronized (fetchLock) {
      CompletableFuture<?> previous = fetchTail;
      future =
          previous
              .handle((r, t) -> null)
              .thenCompose(ignored -> fetch(securityGroupId, startingTokenId, effectiveKeyCount));
      fetchTail = future.handle((r, t) -> null);
    }

    if (fetchTimeout != null) {
      future = future.orTimeout(fetchTimeout.toMillis(), TimeUnit.MILLISECONDS);
    }
    return future;
  }

  /**
   * Close this provider: subsequent fetches fail with {@link IllegalStateException} and the cached
   * session, if any, is disconnected. Does not block waiting for the disconnect.
   */
  @Override
  public void close() {
    if (closed.compareAndSet(false, true)) {
      SksClientOperations.Session session = cachedSession.getAndSet(null);
      if (session != null) {
        session.disconnect();
      }
    }
  }

  private CompletableFuture<SecurityKeySet> fetch(
      String securityGroupId, UInteger startingTokenId, UInteger requestedKeyCount) {

    SksClientOperations.Session session = cachedSession.get();
    if (session == null) {
      return attemptEntry(
          0, securityGroupId, startingTokenId, requestedKeyCount, new ArrayList<>());
    }

    return callGetSecurityKeys(session, securityGroupId, startingTokenId, requestedKeyCount)
        .handle(
            (keySet, t) -> {
              if (t == null) {
                return CompletableFuture.completedFuture(keySet);
              }
              Throwable cause = unwrap(t);
              logger.debug("cached SKS session failed; re-resolving", cause);
              invalidate(session);
              var failures = new ArrayList<Throwable>();
              failures.add(cause);
              return attemptEntry(0, securityGroupId, startingTokenId, requestedKeyCount, failures);
            })
        .thenCompose(Function.identity());
  }

  /**
   * Attempt the fetch against {@code serverEntries[index]}, failing over to the next entry (array
   * order, the unconstrained default of §6.2.5.4 redundancy) on any resolution, connect, or call
   * failure.
   */
  private CompletableFuture<SecurityKeySet> attemptEntry(
      int index,
      String securityGroupId,
      UInteger startingTokenId,
      UInteger requestedKeyCount,
      List<Throwable> failures) {

    if (index >= serverEntries.size()) {
      return CompletableFuture.failedFuture(aggregate(failures));
    }

    EndpointDescription entry = serverEntries.get(index);
    List<String> targets = SksEndpointSelector.discoveryTargets(entry);

    return connectEntry(entry, targets, 0, failures)
        .handle(
            (session, connectError) -> {
              if (connectError != null) {
                failures.add(unwrap(connectError));
                return attemptEntry(
                    index + 1, securityGroupId, startingTokenId, requestedKeyCount, failures);
              }

              return callGetSecurityKeys(
                      session, securityGroupId, startingTokenId, requestedKeyCount)
                  .handle(
                      (keySet, callError) -> {
                        if (callError != null) {
                          session.disconnect();
                          failures.add(unwrap(callError));
                          return attemptEntry(
                              index + 1,
                              securityGroupId,
                              startingTokenId,
                              requestedKeyCount,
                              failures);
                        }
                        cacheSession(session);
                        return CompletableFuture.completedFuture(keySet);
                      })
                  .thenCompose(Function.identity());
            })
        .thenCompose(Function.identity());
  }

  /**
   * Resolve and connect for one entry: GetEndpoints at {@code targets[targetIndex]}, filter/rank
   * per Table 40, and connect to the candidates in ranked order; failing over to the next discovery
   * target on failure.
   */
  private CompletableFuture<SksClientOperations.Session> connectEntry(
      EndpointDescription entry, List<String> targets, int targetIndex, List<Throwable> failures) {

    if (targetIndex >= targets.size()) {
      return CompletableFuture.failedFuture(
          new UaException(
              StatusCodes.Bad_ConfigurationError,
              "no usable endpoint resolved for SKS applicationUri=%s"
                  .formatted(applicationUri(entry))));
    }

    String target = targets.get(targetIndex);

    return operations
        .getEndpoints(target)
        .thenCompose(
            endpoints -> {
              List<EndpointDescription> candidates =
                  SksEndpointSelector.selectCandidates(entry, endpoints);
              if (candidates.isEmpty()) {
                return CompletableFuture.failedFuture(
                    new UaException(
                        StatusCodes.Bad_ConfigurationError,
                        ("GetEndpoints at %s returned no SignAndEncrypt endpoint"
                                + " for applicationUri=%s")
                            .formatted(target, applicationUri(entry))));
              }
              return connectCandidates(entry, endpoints, candidates, 0, failures);
            })
        .handle(
            (session, t) -> {
              if (t == null) {
                return CompletableFuture.completedFuture(session);
              }
              Throwable cause = unwrap(t);
              logger.debug("SKS discovery target {} failed: {}", target, cause.toString());
              failures.add(cause);
              return connectEntry(entry, targets, targetIndex + 1, failures);
            })
        .thenCompose(Function.identity());
  }

  /**
   * Connect to {@code candidates[index]} with an identity resolved per the entry's {@code
   * UserIdentityTokens}; candidates without a resolvable identity are skipped, connect failures
   * fail over to the next candidate.
   */
  private CompletableFuture<SksClientOperations.Session> connectCandidates(
      EndpointDescription entry,
      List<EndpointDescription> discoveredEndpoints,
      List<EndpointDescription> candidates,
      int index,
      List<Throwable> failures) {

    if (index >= candidates.size()) {
      return CompletableFuture.failedFuture(
          new UaException(
              StatusCodes.Bad_ConfigurationError,
              ("no candidate endpoint for applicationUri=%s could be connected with a "
                      + "configured identity token type (Table 40 UserIdentityTokens)")
                  .formatted(applicationUri(entry))));
    }

    EndpointDescription candidate = candidates.get(index);

    Optional<IdentityProvider> identityProvider =
        SksIdentityResolver.resolve(entry, candidate, keyCredentialStore, certificateValidator);

    if (identityProvider.isEmpty()) {
      logger.debug(
          "no configured identity token type intersects endpoint {} (policy {})",
          candidate.getEndpointUrl(),
          candidate.getSecurityPolicyUri());
      return connectCandidates(entry, discoveredEndpoints, candidates, index + 1, failures);
    }

    return operations
        .connect(candidate, discoveredEndpoints, identityProvider.get())
        .handle(
            (session, t) -> {
              if (t == null) {
                return CompletableFuture.completedFuture(session);
              }
              failures.add(unwrap(t));
              return connectCandidates(entry, discoveredEndpoints, candidates, index + 1, failures);
            })
        .thenCompose(Function.identity());
  }

  private CompletableFuture<SecurityKeySet> callGetSecurityKeys(
      SksClientOperations.Session session,
      String securityGroupId,
      UInteger startingTokenId,
      UInteger requestedKeyCount) {

    var request =
        new CallMethodRequest(
            NodeIds.PublishSubscribe,
            NodeIds.PublishSubscribe_GetSecurityKeys,
            new Variant[] {
              Variant.of(securityGroupId),
              Variant.of(startingTokenId),
              Variant.of(requestedKeyCount)
            });

    return session
        .call(request)
        .thenCompose(
            result -> {
              StatusCode statusCode = result.getStatusCode();
              if (statusCode == null || !statusCode.isGood()) {
                StatusCode sc =
                    statusCode != null
                        ? statusCode
                        : new StatusCode(StatusCodes.Bad_UnexpectedError);
                return CompletableFuture.failedFuture(
                    new UaException(sc, "GetSecurityKeys failed: %s".formatted(sc)));
              }
              try {
                return CompletableFuture.completedFuture(mapKeySet(result.getOutputArguments()));
              } catch (UaException e) {
                return CompletableFuture.failedFuture(e);
              }
            });
  }

  /**
   * Map the {@code GetSecurityKeys} output arguments verbatim onto a {@link SecurityKeySet}: {@code
   * SecurityPolicyUri, FirstTokenId, Keys[], TimeToNextKey, KeyLifetime} (§8.3.2; durations arrive
   * as Double milliseconds).
   */
  private static SecurityKeySet mapKeySet(Variant @Nullable [] outputs) throws UaException {
    if (outputs == null || outputs.length != 5) {
      throw new UaException(
          StatusCodes.Bad_UnexpectedError,
          "GetSecurityKeys returned %d output arguments, expected 5"
              .formatted(outputs == null ? 0 : outputs.length));
    }

    String securityPolicyUri = output(outputs, 0, String.class);
    UInteger firstTokenId = output(outputs, 1, UInteger.class);
    ByteString[] keys = output(outputs, 2, ByteString[].class);
    Double timeToNextKey = output(outputs, 3, Double.class);
    Double keyLifetime = output(outputs, 4, Double.class);

    try {
      return new SecurityKeySet(
          securityPolicyUri,
          firstTokenId,
          Arrays.asList(keys),
          durationOfMillis(timeToNextKey),
          durationOfMillis(keyLifetime));
    } catch (RuntimeException e) {
      throw new UaException(
          StatusCodes.Bad_UnexpectedError, "GetSecurityKeys returned invalid key material", e);
    }
  }

  private static <T> T output(Variant[] outputs, int index, Class<T> type) throws UaException {
    Object value = outputs[index].getValue();
    if (!type.isInstance(value)) {
      throw new UaException(
          StatusCodes.Bad_UnexpectedError,
          "GetSecurityKeys output[%d]: expected %s, got %s"
              .formatted(
                  index,
                  type.getSimpleName(),
                  value == null ? "null" : value.getClass().getSimpleName()));
    }
    return type.cast(value);
  }

  private static Duration durationOfMillis(double millis) {
    if (!Double.isFinite(millis)) {
      throw new IllegalArgumentException("duration is not finite: " + millis);
    }
    return Duration.ofNanos(Math.round(millis * 1_000_000d));
  }

  /**
   * Cache a freshly connected session, disconnecting any session it displaces. Displacement is a
   * real scenario, not just a theoretical race: a caller-side timeout (e.g. {@code orTimeout} on
   * the future returned by {@link #getKeys}) completes the fetch future — releasing the internal
   * fetch serialization — without cancelling the still-running connect chain behind it, so a
   * caller's retry starts a second chain and both may eventually succeed, each caching a session.
   */
  private void cacheSession(SksClientOperations.Session session) {
    SksClientOperations.Session displaced = cachedSession.getAndSet(session);
    if (displaced != null && displaced != session) {
      displaced.disconnect();
    }
    if (closed.get()) {
      SksClientOperations.Session raced = cachedSession.getAndSet(null);
      if (raced != null) {
        raced.disconnect();
      }
    }
  }

  /**
   * Drop a failed session: clear it from the cache unless a racing chain already replaced it, and
   * disconnect it unconditionally — the failure may be method-level (e.g. {@code
   * Bad_UserAccessDenied}) on an otherwise live session, and one no longer in the cache would
   * otherwise never be disconnected. Disconnect is idempotent, so re-disconnecting a session that
   * displacement or {@link #close} already handled is harmless.
   */
  private void invalidate(SksClientOperations.Session session) {
    cachedSession.compareAndSet(session, null);
    session.disconnect();
  }

  private static Throwable unwrap(Throwable t) {
    if (t instanceof CompletionException e && e.getCause() != null) {
      return e.getCause();
    }
    return t;
  }

  /**
   * The primary failure is the first one recorded (the primary SKS entry's), so its status code
   * surfaces on the fetch future; later failures are attached as suppressed.
   */
  private static Throwable aggregate(List<Throwable> failures) {
    if (failures.isEmpty()) {
      return new UaException(StatusCodes.Bad_InternalError, "GetSecurityKeys fetch failed");
    }
    Throwable primary = failures.get(0);
    for (int i = 1; i < failures.size(); i++) {
      Throwable t = failures.get(i);
      if (t != primary) {
        try {
          primary.addSuppressed(t);
        } catch (RuntimeException ignored) {
          // suppression disabled on the primary; nothing to attach.
        }
      }
    }
    return primary;
  }

  private static String applicationUri(EndpointDescription entry) {
    ApplicationDescription server = entry.getServer();
    return server != null && server.getApplicationUri() != null
        ? server.getApplicationUri()
        : "<unknown>";
  }

  /**
   * Create a new {@link Builder}.
   *
   * @return a new {@link Builder}.
   */
  public static Builder builder() {
    return new Builder();
  }

  /** A builder for {@link SksSecurityKeyProvider} instances. */
  public static final class Builder {

    private final List<EndpointDescription> securityKeyServices = new ArrayList<>();
    private @Nullable String securityGroupId;
    private @Nullable UInteger requestedKeyCount;
    private KeyCredentialStore keyCredentialStore = resourceUri -> Optional.empty();
    private @Nullable CertificateValidator certificateValidator;
    private Consumer<OpcUaClientConfigBuilder> clientCustomizer = b -> {};
    private Consumer<OpcTcpClientTransportConfigBuilder> transportCustomizer = b -> {};
    private @Nullable Duration requestTimeout;
    private @Nullable Duration fetchTimeout;

    private Builder() {}

    /**
     * Set the SecurityKeyServices entries identifying the SKS (Part 14 §6.2.5.4), replacing any
     * previously set. Feed this from {@code EffectiveMessageSecurity.securityKeyServices()} to
     * honor the reader-override/group/root inheritance chain.
     *
     * @param securityKeyServices the SecurityKeyServices entries, in configured (failover) order.
     * @return this {@link Builder}.
     */
    public Builder securityKeyServices(List<EndpointDescription> securityKeyServices) {
      this.securityKeyServices.clear();
      this.securityKeyServices.addAll(securityKeyServices);
      return this;
    }

    /**
     * Pin the provider to a SecurityGroupId: {@link SksSecurityKeyProvider#getKeys} calls naming
     * any other id fail immediately, guarding against binding one group's provider (whose entries,
     * credentials, and cached session are group-specific) to a different group.
     *
     * @param securityGroupId the SecurityGroupId this provider serves.
     * @return this {@link Builder}.
     */
    public Builder securityGroupId(String securityGroupId) {
      this.securityGroupId = securityGroupId;
      return this;
    }

    /**
     * Override the number of keys requested from the SKS: when set, every {@code GetSecurityKeys}
     * call requests this many keys regardless of the count passed to {@link
     * SksSecurityKeyProvider#getKeys} (the key window an operator wants cached ahead of rotation).
     * When unset the caller's count is forwarded verbatim.
     *
     * @param requestedKeyCount the number of keys to request in addition to the starting token's
     *     key (Part 14 §8.3.2 RequestedKeyCount; the SKS returns this many future keys after the
     *     current one).
     * @return this {@link Builder}.
     */
    public Builder requestedKeyCount(UInteger requestedKeyCount) {
      this.requestedKeyCount = requestedKeyCount;
      return this;
    }

    /**
     * Set the store consulted for the Table 40 USERNAME identity path, keyed by the SKS
     * ApplicationUri. The default store is empty, in which case only entries satisfiable with
     * {@code Anonymous} can be used.
     *
     * @param keyCredentialStore the {@link KeyCredentialStore} to use.
     * @return this {@link Builder}.
     */
    public Builder keyCredentialStore(KeyCredentialStore keyCredentialStore) {
      this.keyCredentialStore = keyCredentialStore;
      return this;
    }

    /**
     * Set the trust posture used to validate the SKS certificate before creating a session (Part 4
     * §6.1.4), typically a {@link DefaultClientCertificateValidator} over the application's trust
     * lists. The default is fail-closed: an empty-trust-list validator that rejects every
     * certificate.
     *
     * @param certificateValidator the {@link CertificateValidator} to use.
     * @return this {@link Builder}.
     */
    public Builder certificateValidator(CertificateValidator certificateValidator) {
      this.certificateValidator = certificateValidator;
      return this;
    }

    /**
     * Set a customizer applied to every session client's {@link OpcUaClientConfigBuilder} after the
     * provider's own configuration. SignAndEncrypt sessions require the client certificate, its
     * certificate chain, the key pair, and the matching application URI to be supplied here; the
     * customizer runs last and may override anything, including the selected endpoint (e.g. a host
     * rewrite for unresolvable discovery hostnames).
     *
     * @param clientCustomizer the customizer to apply.
     * @return this {@link Builder}.
     */
    public Builder clientCustomizer(Consumer<OpcUaClientConfigBuilder> clientCustomizer) {
      this.clientCustomizer = clientCustomizer;
      return this;
    }

    /**
     * Set a customizer applied to the {@link OpcTcpClientTransportConfigBuilder} of both the
     * discovery channels and the session clients.
     *
     * @param transportCustomizer the customizer to apply.
     * @return this {@link Builder}.
     */
    public Builder transportCustomizer(
        Consumer<OpcTcpClientTransportConfigBuilder> transportCustomizer) {
      this.transportCustomizer = transportCustomizer;
      return this;
    }

    /**
     * Set the per-request timeout of the session clients (the {@code GetSecurityKeys} call itself).
     * Defaults to the client SDK default (60 seconds) when unset.
     *
     * @param requestTimeout the request timeout.
     * @return this {@link Builder}.
     */
    public Builder requestTimeout(Duration requestTimeout) {
      this.requestTimeout = requestTimeout;
      return this;
    }

    /**
     * Bound the total duration of one {@link SksSecurityKeyProvider#getKeys} future — resolution,
     * connect, call, and failover across all entries, including time spent queued behind an
     * in-flight fetch. Unset means unbounded; setting a bound is recommended when the caller does
     * not apply its own.
     *
     * @param fetchTimeout the overall fetch timeout.
     * @return this {@link Builder}.
     */
    public Builder fetchTimeout(Duration fetchTimeout) {
      this.fetchTimeout = fetchTimeout;
      return this;
    }

    /**
     * Build the {@link SksSecurityKeyProvider}.
     *
     * @return a new {@link SksSecurityKeyProvider}.
     * @throws IllegalArgumentException if the configured SecurityKeyServices entries are empty,
     *     fail {@link SecurityKeyServiceValidator} validation, or contain no {@code
     *     ApplicationType=Server} entry.
     */
    public SksSecurityKeyProvider build() {
      return new SksSecurityKeyProvider(
          this,
          new DefaultSksClientOperations(
              effectiveCertificateValidator(),
              clientCustomizer,
              transportCustomizer,
              requestTimeout));
    }

    /** Build against stubbed client operations; the test seam. */
    SksSecurityKeyProvider build(SksClientOperations operations) {
      return new SksSecurityKeyProvider(this, operations);
    }

    private CertificateValidator effectiveCertificateValidator() {
      CertificateValidator validator = certificateValidator;
      if (validator == null) {
        validator =
            new DefaultClientCertificateValidator(
                new MemoryTrustListManager(), new MemoryCertificateQuarantine());
      }
      return validator;
    }
  }
}
