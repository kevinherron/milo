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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.eclipse.milo.opcua.sdk.client.identity.AnonymousProvider;
import org.eclipse.milo.opcua.sdk.client.identity.IdentityProvider;
import org.eclipse.milo.opcua.sdk.client.identity.UsernameProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.KeyCredential;
import org.eclipse.milo.opcua.sdk.pubsub.security.KeyCredentialStore;
import org.eclipse.milo.opcua.stack.core.security.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.junit.jupiter.api.Test;

class SksIdentityResolverTest {

  private static final String APP_URI = "urn:test:sks";

  private static final KeyCredentialStore EMPTY_STORE = resourceUri -> Optional.empty();

  private static final CertificateValidator VALIDATOR =
      new CertificateValidator.InsecureCertificateValidator();

  @Test
  void emptyConfiguredTokensDefaultsToAnonymous() {
    EndpointDescription entry = entry();
    EndpointDescription endpoint = endpoint(UserTokenType.Anonymous);

    Optional<IdentityProvider> identity =
        SksIdentityResolver.resolve(entry, endpoint, EMPTY_STORE, VALIDATOR);

    assertInstanceOf(AnonymousProvider.class, identity.orElseThrow());
  }

  @Test
  void anonymousDefaultRequiresEndpointToOfferAnonymous() {
    EndpointDescription entry = entry();
    EndpointDescription endpoint = endpoint(UserTokenType.UserName);

    Optional<IdentityProvider> identity =
        SksIdentityResolver.resolve(entry, endpoint, EMPTY_STORE, VALIDATOR);

    assertTrue(identity.isEmpty());
  }

  @Test
  void userNameResolvedThroughCredentialStore() {
    EndpointDescription entry = entry(UserTokenType.UserName);
    EndpointDescription endpoint = endpoint(UserTokenType.UserName, UserTokenType.Anonymous);

    KeyCredentialStore store =
        resourceUri ->
            APP_URI.equals(resourceUri)
                ? Optional.of(new KeyCredential("user1", "hunter2".toCharArray()))
                : Optional.empty();

    Optional<IdentityProvider> identity =
        SksIdentityResolver.resolve(entry, endpoint, store, VALIDATOR);

    assertInstanceOf(UsernameProvider.class, identity.orElseThrow());
  }

  @Test
  void userNameProbeCopyIsWiped() {
    EndpointDescription entry = entry(UserTokenType.UserName);
    EndpointDescription endpoint = endpoint(UserTokenType.UserName);

    var copies = new ArrayList<char[]>();
    KeyCredentialStore store =
        resourceUri -> {
          char[] secret = "hunter2".toCharArray();
          copies.add(secret);
          return Optional.of(new KeyCredential("user1", secret));
        };

    SksIdentityResolver.resolve(entry, endpoint, store, VALIDATOR).orElseThrow();

    assertEquals(1, copies.size());
    for (char c : copies.get(0)) {
      assertEquals('\0', c);
    }
  }

  @Test
  void missingCredentialFallsThroughToNextListedType() {
    EndpointDescription entry = entry(UserTokenType.UserName, UserTokenType.Anonymous);
    EndpointDescription endpoint = endpoint(UserTokenType.UserName, UserTokenType.Anonymous);

    Optional<IdentityProvider> identity =
        SksIdentityResolver.resolve(entry, endpoint, EMPTY_STORE, VALIDATOR);

    assertInstanceOf(AnonymousProvider.class, identity.orElseThrow());
  }

  @Test
  void missingCredentialWithNoFallbackFailsResolution() {
    EndpointDescription entry = entry(UserTokenType.UserName);
    EndpointDescription endpoint = endpoint(UserTokenType.UserName, UserTokenType.Anonymous);

    Optional<IdentityProvider> identity =
        SksIdentityResolver.resolve(entry, endpoint, EMPTY_STORE, VALIDATOR);

    // Anonymous is NOT listed by the entry: never silently downgrade (pinned rule).
    assertTrue(identity.isEmpty());
  }

  @Test
  void listedOrderWins() {
    EndpointDescription entry = entry(UserTokenType.Anonymous, UserTokenType.UserName);
    EndpointDescription endpoint = endpoint(UserTokenType.UserName, UserTokenType.Anonymous);

    KeyCredentialStore store =
        resourceUri -> Optional.of(new KeyCredential("user1", "hunter2".toCharArray()));

    Optional<IdentityProvider> identity =
        SksIdentityResolver.resolve(entry, endpoint, store, VALIDATOR);

    assertInstanceOf(AnonymousProvider.class, identity.orElseThrow());
  }

  @Test
  void unsupportedTokenTypesAreSkipped() {
    EndpointDescription entry = entry(UserTokenType.Certificate, UserTokenType.Anonymous);
    EndpointDescription endpoint = endpoint(UserTokenType.Certificate, UserTokenType.Anonymous);

    Optional<IdentityProvider> identity =
        SksIdentityResolver.resolve(entry, endpoint, EMPTY_STORE, VALIDATOR);

    assertInstanceOf(AnonymousProvider.class, identity.orElseThrow());
  }

  @Test
  void nonIntersectionFailsResolution() {
    EndpointDescription entry = entry(UserTokenType.Anonymous);
    EndpointDescription endpoint = endpoint(UserTokenType.UserName, UserTokenType.Certificate);

    Optional<IdentityProvider> identity =
        SksIdentityResolver.resolve(entry, endpoint, EMPTY_STORE, VALIDATOR);

    assertTrue(identity.isEmpty());
  }

  private static EndpointDescription entry(UserTokenType... tokenTypes) {
    var server =
        new ApplicationDescription(
            APP_URI,
            null,
            LocalizedText.NULL_VALUE,
            ApplicationType.Server,
            null,
            null,
            new String[] {"opc.tcp://sks:4840"});

    return new EndpointDescription(
        null,
        server,
        ByteString.NULL_VALUE,
        MessageSecurityMode.SignAndEncrypt,
        null,
        tokenPolicies(tokenTypes),
        null,
        ubyte(0));
  }

  private static EndpointDescription endpoint(UserTokenType... tokenTypes) {
    var server =
        new ApplicationDescription(
            APP_URI, null, LocalizedText.NULL_VALUE, ApplicationType.Server, null, null, null);

    return new EndpointDescription(
        "opc.tcp://sks:4840",
        server,
        ByteString.NULL_VALUE,
        MessageSecurityMode.SignAndEncrypt,
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss",
        tokenPolicies(tokenTypes),
        null,
        ubyte(3));
  }

  private static UserTokenPolicy[] tokenPolicies(UserTokenType... tokenTypes) {
    List<UserTokenPolicy> policies = new ArrayList<>();
    for (UserTokenType tokenType : tokenTypes) {
      policies.add(
          new UserTokenPolicy(tokenType.name().toLowerCase(), tokenType, null, null, null));
    }
    return policies.toArray(new UserTokenPolicy[0]);
  }
}
