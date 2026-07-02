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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.eclipse.milo.opcua.sdk.client.identity.AnonymousProvider;
import org.eclipse.milo.opcua.sdk.client.identity.IdentityProvider;
import org.eclipse.milo.opcua.sdk.client.identity.UsernameProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.KeyCredential;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.junit.jupiter.api.Test;

class SksSecurityKeyProviderTest {

  private static final String APP_URI = "urn:test:sks";
  private static final String APP_URI_2 = "urn:test:sks2";
  private static final String GROUP_ID = "SG-1";
  private static final String PUBSUB_AES256_URI =
      "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR";

  private static final ByteString KEY_DATA = ByteString.of(new byte[] {1, 2, 3, 4});

  @Test
  void constructionRejectsEmptyEntries() {
    assertThrows(
        IllegalArgumentException.class,
        () -> SksSecurityKeyProvider.builder().build(new StubOperations()));
  }

  @Test
  void constructionRejectsInvalidEntries() {
    EndpointDescription invalid =
        new EndpointDescription(
            null,
            new ApplicationDescription(
                APP_URI,
                null,
                LocalizedText.NULL_VALUE,
                ApplicationType.ClientAndServer,
                null,
                null,
                new String[] {"opc.tcp://sks:4840"}),
            ByteString.NULL_VALUE,
            MessageSecurityMode.SignAndEncrypt,
            null,
            null,
            null,
            ubyte(0));

    assertThrows(
        IllegalArgumentException.class,
        () ->
            SksSecurityKeyProvider.builder()
                .securityKeyServices(List.of(invalid))
                .build(new StubOperations()));
  }

  @Test
  void constructionRequiresAtLeastOneServerEntry() {
    EndpointDescription pushEntry =
        new EndpointDescription(
            null,
            new ApplicationDescription(
                APP_URI, null, LocalizedText.NULL_VALUE, ApplicationType.Client, null, null, null),
            ByteString.NULL_VALUE,
            MessageSecurityMode.SignAndEncrypt,
            null,
            null,
            null,
            ubyte(0));

    assertThrows(
        IllegalArgumentException.class,
        () ->
            SksSecurityKeyProvider.builder()
                .securityKeyServices(List.of(pushEntry))
                .build(new StubOperations()));
  }

  @Test
  void fetchResolvesConnectsCallsAndMapsVerbatim() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();
    EndpointDescription endpoint = endpoint(APP_URI, 3);

    operations.onGetEndpoints = url -> CompletableFuture.completedFuture(List.of(endpoint));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider = provider(operations, entry(APP_URI, "opc.tcp://sks:4840"));

    SecurityKeySet keySet = provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    assertEquals(List.of("opc.tcp://sks:4840"), operations.endpointCalls);
    assertEquals(1, operations.connectCalls.size());
    assertEquals(endpoint, operations.connectCalls.get(0).endpoint());
    assertInstanceOf(AnonymousProvider.class, operations.connectCalls.get(0).identity());

    assertEquals(1, session.calls.size());
    CallMethodRequest request = session.calls.get(0);
    assertEquals(NodeIds.PublishSubscribe, request.getObjectId());
    assertEquals(NodeIds.PublishSubscribe_GetSecurityKeys, request.getMethodId());
    Variant[] inputs = request.getInputArguments();
    assertEquals(Variant.of(GROUP_ID), inputs[0]);
    assertEquals(Variant.of(uint(0)), inputs[1]);
    assertEquals(Variant.of(uint(3)), inputs[2]);

    assertEquals(PUBSUB_AES256_URI, keySet.securityPolicyUri());
    assertEquals(uint(7), keySet.firstTokenId());
    assertEquals(List.of(KEY_DATA), keySet.keys());
    assertEquals(Duration.ofSeconds(5), keySet.timeToNextKey());
    assertEquals(Duration.ofSeconds(10), keySet.keyLifetime());
  }

  @Test
  void resolvedSessionIsCachedAcrossFetches() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider = provider(operations, entry(APP_URI, "opc.tcp://sks:4840"));

    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);
    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    assertEquals(1, operations.endpointCalls.size());
    assertEquals(1, operations.connectCalls.size());
    assertEquals(2, session.calls.size());
  }

  @Test
  void cachedSessionFailureTriggersReResolution() throws Exception {
    var operations = new StubOperations();
    var session1 = new StubSession();
    var session2 = new StubSession();

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session1);
    session1.onCall = request -> CompletableFuture.completedFuture(goodResult());
    session2.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider = provider(operations, entry(APP_URI, "opc.tcp://sks:4840"));

    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    // the cached session starts failing; the next resolution connects session2.
    session1.onCall =
        request ->
            CompletableFuture.failedFuture(
                new UaException(StatusCodes.Bad_ConnectionClosed, "channel closed"));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session2);

    SecurityKeySet keySet = provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    assertEquals(PUBSUB_AES256_URI, keySet.securityPolicyUri());
    assertTrue(session1.disconnected.get());
    assertEquals(2, operations.endpointCalls.size());
    assertEquals(1, session2.calls.size());
  }

  @Test
  void cachedSessionFailureIsThePrimaryCauseWhenReResolutionAlsoFails() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider = provider(operations, entry(APP_URI, "opc.tcp://sks:4840"));

    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    session.onCall =
        request ->
            CompletableFuture.failedFuture(
                new UaException(StatusCodes.Bad_UserAccessDenied, "denied"));
    operations.onGetEndpoints =
        url ->
            CompletableFuture.failedFuture(new UaException(StatusCodes.Bad_Timeout, "no answer"));

    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS));

    UaException cause = assertInstanceOf(UaException.class, e.getCause());
    assertEquals(StatusCodes.Bad_UserAccessDenied, cause.getStatusCode().value());
    assertTrue(cause.getSuppressed().length >= 1);
  }

  @Test
  void failsOverAcrossEntriesInArrayOrder() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();
    EndpointDescription endpoint2 = endpoint(APP_URI_2, 3);

    operations.onGetEndpoints =
        url -> {
          if (url.equals("opc.tcp://sks1:4840")) {
            return CompletableFuture.failedFuture(
                new UaException(StatusCodes.Bad_Timeout, "no answer"));
          }
          return CompletableFuture.completedFuture(List.of(endpoint2));
        };
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider =
        provider(
            operations,
            entry(APP_URI, "opc.tcp://sks1:4840"),
            entry(APP_URI_2, "opc.tcp://sks2:4840"));

    SecurityKeySet keySet = provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    assertEquals(List.of("opc.tcp://sks1:4840", "opc.tcp://sks2:4840"), operations.endpointCalls);
    assertEquals(endpoint2, operations.connectCalls.get(0).endpoint());
    assertEquals(PUBSUB_AES256_URI, keySet.securityPolicyUri());
  }

  @Test
  void toleranceFallbackUsesEndpointUrlAsDiscoveryTarget() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall = request -> CompletableFuture.completedFuture(goodResult());

    // open62541-shaped entry: filled endpointUrl, no discovery URLs.
    EndpointDescription legacyEntry =
        new EndpointDescription(
            "opc.tcp://legacy-sks:4840",
            new ApplicationDescription(
                APP_URI, null, LocalizedText.NULL_VALUE, ApplicationType.Server, null, null, null),
            ByteString.NULL_VALUE,
            MessageSecurityMode.SignAndEncrypt,
            null,
            null,
            null,
            ubyte(0));

    SksSecurityKeyProvider provider = provider(operations, legacyEntry);

    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    assertEquals(List.of("opc.tcp://legacy-sks:4840"), operations.endpointCalls);
  }

  @Test
  void badStatusCodeSurfacesOnTheFuture() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall =
        request ->
            CompletableFuture.completedFuture(
                new CallMethodResult(
                    new StatusCode(StatusCodes.Bad_UserAccessDenied), null, null, null));

    SksSecurityKeyProvider provider = provider(operations, entry(APP_URI, "opc.tcp://sks:4840"));

    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS));

    UaException cause = assertInstanceOf(UaException.class, e.getCause());
    assertEquals(StatusCodes.Bad_UserAccessDenied, cause.getStatusCode().value());
    assertTrue(session.disconnected.get());
  }

  @Test
  void malformedOutputsFailTheFetch() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall =
        request ->
            CompletableFuture.completedFuture(
                new CallMethodResult(
                    StatusCode.GOOD, null, null, new Variant[] {Variant.of("only-one")}));

    SksSecurityKeyProvider provider = provider(operations, entry(APP_URI, "opc.tcp://sks:4840"));

    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS));

    UaException cause = assertInstanceOf(UaException.class, e.getCause());
    assertEquals(StatusCodes.Bad_UnexpectedError, cause.getStatusCode().value());
  }

  @Test
  void identityNonIntersectionFailsTheEntry() throws Exception {
    var operations = new StubOperations();

    // the entry lists USERNAME only; no credential is configured, so the entry must fail
    // rather than silently downgrade to the Anonymous the endpoint offers.
    EndpointDescription entry =
        new EndpointDescription(
            null,
            new ApplicationDescription(
                APP_URI,
                null,
                LocalizedText.NULL_VALUE,
                ApplicationType.Server,
                null,
                null,
                new String[] {"opc.tcp://sks:4840"}),
            ByteString.NULL_VALUE,
            MessageSecurityMode.SignAndEncrypt,
            null,
            new UserTokenPolicy[] {
              new UserTokenPolicy("username", UserTokenType.UserName, null, null, null)
            },
            null,
            ubyte(0));

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect =
        (e, discovered, identity) ->
            CompletableFuture.failedFuture(new AssertionError("must not connect"));

    SksSecurityKeyProvider provider = provider(operations, entry);

    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS));

    UaException cause = assertInstanceOf(UaException.class, e.getCause());
    assertTrue(cause.getMessage() != null && cause.getMessage().contains("identity token type"));
    assertTrue(operations.connectCalls.isEmpty());
  }

  @Test
  void userNameIdentityResolvedFromCredentialStore() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();

    EndpointDescription entry =
        new EndpointDescription(
            null,
            new ApplicationDescription(
                APP_URI,
                null,
                LocalizedText.NULL_VALUE,
                ApplicationType.Server,
                null,
                null,
                new String[] {"opc.tcp://sks:4840"}),
            ByteString.NULL_VALUE,
            MessageSecurityMode.SignAndEncrypt,
            null,
            new UserTokenPolicy[] {
              new UserTokenPolicy("username", UserTokenType.UserName, null, null, null)
            },
            null,
            ubyte(0));

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider =
        SksSecurityKeyProvider.builder()
            .securityKeyServices(List.of(entry))
            .keyCredentialStore(
                resourceUri ->
                    APP_URI.equals(resourceUri)
                        ? Optional.of(new KeyCredential("user1", "hunter2".toCharArray()))
                        : Optional.empty())
            .build(operations);

    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    assertInstanceOf(UsernameProvider.class, operations.connectCalls.get(0).identity());
  }

  @Test
  void requestedKeyCountOverrideReplacesCallerCount() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider =
        SksSecurityKeyProvider.builder()
            .securityKeyServices(List.of(entry(APP_URI, "opc.tcp://sks:4840")))
            .requestedKeyCount(uint(9))
            .build(operations);

    provider.getKeys(GROUP_ID, uint(4), uint(2)).get(2, TimeUnit.SECONDS);

    Variant[] inputs = session.calls.get(0).getInputArguments();
    assertEquals(Variant.of(uint(4)), inputs[1]);
    assertEquals(Variant.of(uint(9)), inputs[2]);
  }

  @Test
  void pinnedSecurityGroupIdRejectsMismatchedCalls() {
    var operations = new StubOperations();

    SksSecurityKeyProvider provider =
        SksSecurityKeyProvider.builder()
            .securityKeyServices(List.of(entry(APP_URI, "opc.tcp://sks:4840")))
            .securityGroupId(GROUP_ID)
            .build(operations);

    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> provider.getKeys("SG-other", uint(0), uint(3)).get(2, TimeUnit.SECONDS));

    assertInstanceOf(IllegalArgumentException.class, e.getCause());
    assertTrue(operations.endpointCalls.isEmpty());
  }

  @Test
  void closeDisconnectsCachedSessionAndFailsSubsequentFetches() throws Exception {
    var operations = new StubOperations();
    var session = new StubSession();

    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session);
    session.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider = provider(operations, entry(APP_URI, "opc.tcp://sks:4840"));

    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    provider.close();

    assertTrue(session.disconnected.get());

    ExecutionException e =
        assertThrows(
            ExecutionException.class,
            () -> provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS));
    assertInstanceOf(IllegalStateException.class, e.getCause());
  }

  /**
   * A caller-side timeout (e.g. the key manager's {@code orTimeout}) completes the fetch future —
   * releasing the internal fetch serialization — without cancelling the still-running connect
   * chain, so a retry can start a second chain and both eventually succeed. The session displaced
   * from the cache by the late chain must be disconnected, not leaked.
   */
  @Test
  void lateChainDisconnectsTheCachedSessionItDisplaces() throws Exception {
    var operations = new StubOperations();
    var session1 = new StubSession();
    var session2 = new StubSession();

    // chain 1: the connect hangs (a slow SKS).
    var pendingConnect = new CompletableFuture<SksClientOperations.Session>();
    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> pendingConnect;
    session1.onCall = request -> CompletableFuture.completedFuture(goodResult());
    session2.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider = provider(operations, entry(APP_URI, "opc.tcp://sks:4840"));

    CompletableFuture<SecurityKeySet> fetch1 = provider.getKeys(GROUP_ID, uint(0), uint(3));
    fetch1.completeExceptionally(new TimeoutException("caller-side timeout"));

    // chain 2: the caller's retry connects and caches session2.
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session2);
    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    // chain 1 finally succeeds and caches session1, displacing session2.
    pendingConnect.complete(session1);

    assertTrue(session2.disconnected.get());
    assertFalse(session1.disconnected.get());

    // subsequent fetches reuse the surviving cached session; no new resolution.
    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);
    assertEquals(2, session1.calls.size());
    assertEquals(2, operations.connectCalls.size());
  }

  /**
   * The mirror hole: a cached session's call fails after a late chain already displaced it from the
   * cache, so invalidate's CAS misses — the failed session must still be disconnected (its failure
   * may be method-level on an otherwise live session, e.g. Bad_UserAccessDenied).
   */
  @Test
  void failedCachedSessionIsDisconnectedEvenWhenAlreadyDisplaced() throws Exception {
    var operations = new StubOperations();
    var session1 = new StubSession();
    var session2 = new StubSession();

    // chain 1: the connect hangs; the caller times the fetch out.
    var pendingConnect = new CompletableFuture<SksClientOperations.Session>();
    operations.onGetEndpoints =
        url -> CompletableFuture.completedFuture(List.of(endpoint(APP_URI, 3)));
    operations.onConnect = (e, discovered, identity) -> pendingConnect;
    session1.onCall = request -> CompletableFuture.completedFuture(goodResult());

    SksSecurityKeyProvider provider = provider(operations, entry(APP_URI, "opc.tcp://sks:4840"));

    CompletableFuture<SecurityKeySet> fetch1 = provider.getKeys(GROUP_ID, uint(0), uint(3));
    fetch1.completeExceptionally(new TimeoutException("caller-side timeout"));

    // chain 2: the retry connects and caches session2.
    operations.onConnect = (e, discovered, identity) -> CompletableFuture.completedFuture(session2);
    session2.onCall = request -> CompletableFuture.completedFuture(goodResult());
    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);

    // chain 3: uses cached session2; its call hangs, and the caller times it out too.
    var pendingCall = new CompletableFuture<CallMethodResult>();
    session2.onCall = request -> pendingCall;
    CompletableFuture<SecurityKeySet> fetch3 = provider.getKeys(GROUP_ID, uint(0), uint(3));
    fetch3.completeExceptionally(new TimeoutException("caller-side timeout"));

    // chain 1 finally succeeds: session1 displaces session2 in the cache.
    pendingConnect.complete(session1);

    // chain 3's hung call on session2 now fails at method level; the cache no longer holds
    // session2, and its re-resolution attempt fails outright.
    operations.onConnect =
        (e, discovered, identity) ->
            CompletableFuture.failedFuture(new UaException(StatusCodes.Bad_Timeout, "no answer"));
    pendingCall.completeExceptionally(new UaException(StatusCodes.Bad_UserAccessDenied, "denied"));

    assertTrue(session2.disconnected.get());
    assertFalse(session1.disconnected.get());

    // session1 remains the cached session.
    provider.getKeys(GROUP_ID, uint(0), uint(3)).get(2, TimeUnit.SECONDS);
    assertEquals(2, session1.calls.size());
  }

  private static SksSecurityKeyProvider provider(
      StubOperations operations, EndpointDescription... entries) {

    return SksSecurityKeyProvider.builder().securityKeyServices(List.of(entries)).build(operations);
  }

  private static EndpointDescription entry(String applicationUri, String... discoveryUrls) {
    var server =
        new ApplicationDescription(
            applicationUri,
            null,
            LocalizedText.NULL_VALUE,
            ApplicationType.Server,
            null,
            null,
            discoveryUrls);

    return new EndpointDescription(
        null,
        server,
        ByteString.NULL_VALUE,
        MessageSecurityMode.SignAndEncrypt,
        null,
        null,
        null,
        ubyte(0));
  }

  private static EndpointDescription endpoint(String applicationUri, int securityLevel) {
    var server =
        new ApplicationDescription(
            applicationUri,
            null,
            LocalizedText.NULL_VALUE,
            ApplicationType.Server,
            null,
            null,
            null);

    return new EndpointDescription(
        "opc.tcp://sks:4840",
        server,
        ByteString.NULL_VALUE,
        MessageSecurityMode.SignAndEncrypt,
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss",
        new UserTokenPolicy[] {
          new UserTokenPolicy("anonymous", UserTokenType.Anonymous, null, null, null),
          new UserTokenPolicy("username", UserTokenType.UserName, null, null, null)
        },
        null,
        ubyte(securityLevel));
  }

  private static CallMethodResult goodResult() {
    return new CallMethodResult(
        StatusCode.GOOD,
        null,
        null,
        new Variant[] {
          Variant.of(PUBSUB_AES256_URI),
          Variant.of(uint(7)),
          Variant.of(new ByteString[] {KEY_DATA}),
          Variant.of(5_000.0),
          Variant.of(10_000.0)
        });
  }

  private static final class StubOperations implements SksClientOperations {

    final List<String> endpointCalls = new ArrayList<>();
    final List<ConnectCall> connectCalls = new ArrayList<>();

    Function<String, CompletableFuture<List<EndpointDescription>>> onGetEndpoints =
        url ->
            CompletableFuture.failedFuture(new AssertionError("unexpected getEndpoints: " + url));

    ConnectHandler onConnect =
        (endpoint, discovered, identity) ->
            CompletableFuture.failedFuture(new AssertionError("unexpected connect"));

    @Override
    public CompletableFuture<List<EndpointDescription>> getEndpoints(String discoveryUrl) {
      endpointCalls.add(discoveryUrl);
      return onGetEndpoints.apply(discoveryUrl);
    }

    @Override
    public CompletableFuture<Session> connect(
        EndpointDescription endpoint,
        List<EndpointDescription> discoveredEndpoints,
        IdentityProvider identityProvider) {

      connectCalls.add(new ConnectCall(endpoint, discoveredEndpoints, identityProvider));
      return onConnect.connect(endpoint, discoveredEndpoints, identityProvider);
    }

    record ConnectCall(
        EndpointDescription endpoint,
        List<EndpointDescription> discovered,
        IdentityProvider identity) {}

    interface ConnectHandler {
      CompletableFuture<SksClientOperations.Session> connect(
          EndpointDescription endpoint,
          List<EndpointDescription> discoveredEndpoints,
          IdentityProvider identityProvider);
    }
  }

  private static final class StubSession implements SksClientOperations.Session {

    final List<CallMethodRequest> calls = new ArrayList<>();
    final AtomicBoolean disconnected = new AtomicBoolean(false);

    Function<CallMethodRequest, CompletableFuture<CallMethodResult>> onCall =
        request -> CompletableFuture.failedFuture(new AssertionError("unexpected call"));

    @Override
    public CompletableFuture<CallMethodResult> call(CallMethodRequest request) {
      calls.add(request);
      return onCall.apply(request);
    }

    @Override
    public CompletableFuture<Void> disconnect() {
      disconnected.set(true);
      return CompletableFuture.completedFuture(null);
    }
  }
}
