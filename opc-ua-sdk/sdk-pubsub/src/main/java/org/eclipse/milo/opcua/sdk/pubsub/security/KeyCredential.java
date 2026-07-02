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

/**
 * A credential returned by a {@link KeyCredentialStore}: the identity/secret pair of an OPC UA Part
 * 12 KeyCredential record (e.g. a username/password for a Security Key Service session or a broker
 * connection).
 *
 * <p>The secret is a {@code char[]} so it can be wiped. This record does not copy it: {@link
 * KeyCredentialStore} implementations return a fresh copy per lookup, and the caller owns the
 * returned array — wipe it ({@code Arrays.fill(secret, '\0')}) as soon as the credential has been
 * used. Record equality consequently compares the secret array by identity, not content, and {@link
 * #toString()} never includes it.
 *
 * @param credentialId the credential identity, e.g. a username.
 * @param secret the credential secret; owned by the caller, wipe after use.
 */
public record KeyCredential(String credentialId, char[] secret) {

  @Override
  public String toString() {
    return "KeyCredential{credentialId=" + credentialId + "}";
  }
}
