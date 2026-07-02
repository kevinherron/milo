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

import java.util.Optional;

/**
 * SPI resolving a resource URI to the {@link KeyCredential} used to authenticate against that
 * resource.
 *
 * <p>This is the minimal Milo stand-in for the OPC UA Part 12 KeyCredential configuration model:
 * Part 14 routes USERNAME identity tokens for Security Key Service sessions to a Part 12 record
 * looked up by {@code ResourceUri == SKS ApplicationUri} (Table 40), and the same mechanism backs
 * broker-transport {@code resourceUri}/{@code authenticationProfileUri} credentials. Consumers pass
 * the store to the component that needs credentials (e.g. an SKS pull provider); hosting the Part
 * 12 information model (KeyCredentialConfiguration folder and its methods) is out of scope.
 *
 * <p>Implementations must return a fresh copy of the secret per lookup; the caller owns and wipes
 * the returned {@link KeyCredential#secret()}. {@link MemoryKeyCredentialStore} is the bundled
 * implementation.
 */
@FunctionalInterface
public interface KeyCredentialStore {

  /**
   * Look up the credential for a resource.
   *
   * @param resourceUri the URI identifying the resource, e.g. the ApplicationUri of a Security Key
   *     Service or the resource URI of a broker.
   * @return the {@link KeyCredential} for the resource, or empty if none is configured.
   */
  Optional<KeyCredential> lookup(String resourceUri);
}
