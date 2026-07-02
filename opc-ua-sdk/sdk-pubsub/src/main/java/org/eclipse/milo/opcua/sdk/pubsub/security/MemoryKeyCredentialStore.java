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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A {@link KeyCredentialStore} backed by an in-memory map.
 *
 * <p>Secrets are copied on the way in and on the way out: {@link #put(String, String, char[])}
 * stores its own copy (the caller keeps ownership of, and should wipe, the array it passed), each
 * {@link #lookup(String)} returns a fresh copy the caller owns and wipes, and the store wipes its
 * internal copy when an entry is removed or replaced. The internal copies live unencrypted on the
 * heap for the lifetime of their entries; wiping is best-effort (see the package documentation for
 * the zeroization posture).
 *
 * <p>All methods are safe for concurrent use.
 */
public final class MemoryKeyCredentialStore implements KeyCredentialStore {

  private final Map<String, KeyCredential> credentials = new HashMap<>();

  @Override
  public synchronized Optional<KeyCredential> lookup(String resourceUri) {
    KeyCredential credential = credentials.get(resourceUri);

    if (credential == null) {
      return Optional.empty();
    } else {
      return Optional.of(new KeyCredential(credential.credentialId(), credential.secret().clone()));
    }
  }

  /**
   * Add or replace the credential for a resource.
   *
   * <p>The store keeps its own copy of {@code secret}; the caller retains ownership of the array
   * passed in and should wipe it. A replaced entry's internal secret copy is wiped.
   *
   * @param resourceUri the URI identifying the resource.
   * @param credentialId the credential identity, e.g. a username.
   * @param secret the credential secret.
   */
  public synchronized void put(String resourceUri, String credentialId, char[] secret) {
    KeyCredential replaced =
        credentials.put(resourceUri, new KeyCredential(credentialId, secret.clone()));

    if (replaced != null) {
      Arrays.fill(replaced.secret(), '\0');
    }
  }

  /**
   * Remove the credential for a resource, wiping the store's internal secret copy.
   *
   * @param resourceUri the URI identifying the resource.
   */
  public synchronized void remove(String resourceUri) {
    KeyCredential removed = credentials.remove(resourceUri);

    if (removed != null) {
      Arrays.fill(removed.secret(), '\0');
    }
  }
}
