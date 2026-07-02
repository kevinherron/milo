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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.eclipse.milo.opcua.sdk.client.identity.AnonymousProvider;
import org.eclipse.milo.opcua.sdk.client.identity.IdentityProvider;
import org.eclipse.milo.opcua.sdk.client.identity.UsernameProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.KeyCredential;
import org.eclipse.milo.opcua.sdk.pubsub.security.KeyCredentialStore;
import org.eclipse.milo.opcua.stack.core.security.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.jspecify.annotations.Nullable;

/**
 * Resolves the session identity for an SKS connection per the Part 14 Table 40 {@code
 * UserIdentityTokens} rule: the entry lists the token types that should be used (default ANONYMOUS
 * when empty), intersected with what the selected endpoint offers and what the provider can
 * actually produce — {@code Anonymous}, or {@code UserName} backed by a Part 12 KeyCredential
 * record looked up by {@code ResourceUri == SKS ApplicationUri}.
 *
 * <p>Non-intersection rule (pinned): configured token types are tried in listed order; if none can
 * be satisfied the resolution is empty and the caller fails the entry — the provider never silently
 * downgrades to a token type the configuration did not list.
 */
final class SksIdentityResolver {

  private SksIdentityResolver() {}

  /**
   * Resolve an {@link IdentityProvider} for connecting to {@code endpoint} on behalf of {@code
   * entry}.
   *
   * @param entry the Server-typed SecurityKeyServices entry being resolved.
   * @param endpoint the discovered endpoint selected for connection.
   * @param credentialStore the store consulted for the USERNAME path, keyed by the entry's {@code
   *     server.applicationUri}.
   * @param certificateValidator the validator a {@link UsernameProvider} uses when encrypting the
   *     password for transmission.
   * @return the resolved {@link IdentityProvider}, or empty if no configured token type can be
   *     satisfied against {@code endpoint}.
   */
  static Optional<IdentityProvider> resolve(
      EndpointDescription entry,
      EndpointDescription endpoint,
      KeyCredentialStore credentialStore,
      CertificateValidator certificateValidator) {

    Set<UserTokenType> offeredTypes = tokenTypes(endpoint.getUserIdentityTokens());

    for (UserTokenType configuredType : configuredTokenTypes(entry)) {
      if (!offeredTypes.contains(configuredType)) {
        continue;
      }

      switch (configuredType) {
        case Anonymous -> {
          return Optional.of(new AnonymousProvider());
        }

        case UserName -> {
          String resourceUri =
              entry.getServer() != null ? entry.getServer().getApplicationUri() : null;
          if (resourceUri == null || resourceUri.isEmpty()) {
            continue;
          }

          Optional<KeyCredential> credential = credentialStore.lookup(resourceUri);
          if (credential.isEmpty()) {
            // no credential record: the provider cannot do USERNAME; try the next listed type.
            continue;
          }

          String credentialId = credential.get().credentialId();
          // the probe copy is ours to wipe; the password is looked up fresh at activation time.
          Arrays.fill(credential.get().secret(), '\0');

          return Optional.of(
              new UsernameProvider(
                  credentialId,
                  () -> lookupPasswordBytes(credentialStore, resourceUri),
                  certificateValidator));
        }

        default -> {
          // Certificate/IssuedToken: not producible by this provider; try the next listed type.
        }
      }
    }

    return Optional.empty();
  }

  /**
   * The token types the entry's {@code UserIdentityTokens} lists, deduplicated in listed order;
   * {@code [Anonymous]} when the array is null or empty (Table 40: "The default is ANONYMOUS if the
   * array is empty.").
   */
  private static List<UserTokenType> configuredTokenTypes(EndpointDescription entry) {
    UserTokenPolicy[] policies = entry.getUserIdentityTokens();
    if (policies == null || policies.length == 0) {
      return List.of(UserTokenType.Anonymous);
    }

    var types = new ArrayList<UserTokenType>();
    for (UserTokenPolicy policy : policies) {
      UserTokenType type = policy.getTokenType();
      if (type != null && !types.contains(type)) {
        types.add(type);
      }
    }
    return types;
  }

  private static Set<UserTokenType> tokenTypes(UserTokenPolicy @Nullable [] policies) {
    Set<UserTokenType> types = EnumSet.noneOf(UserTokenType.class);
    if (policies != null) {
      for (UserTokenPolicy policy : policies) {
        if (policy.getTokenType() != null) {
          types.add(policy.getTokenType());
        }
      }
    }
    return types;
  }

  /**
   * Look up the credential for {@code resourceUri} and return its secret as UTF-8 bytes, wiping the
   * intermediate copies. {@link UsernameProvider} zeroes the returned array after use.
   *
   * @throws IllegalStateException if the credential is no longer available.
   */
  private static byte[] lookupPasswordBytes(
      KeyCredentialStore credentialStore, String resourceUri) {
    KeyCredential credential =
        credentialStore
            .lookup(resourceUri)
            .orElseThrow(
                () ->
                    new IllegalStateException(
                        "no KeyCredential available for resourceUri=" + resourceUri));

    char[] secret = credential.secret();
    try {
      ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(secret));
      byte[] bytes = new byte[encoded.remaining()];
      encoded.get(bytes);
      if (encoded.hasArray()) {
        Arrays.fill(encoded.array(), (byte) 0);
      }
      return bytes;
    } finally {
      Arrays.fill(secret, '\0');
    }
  }
}
