/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

/**
 * Security Key Service (SKS) pull client for OPC UA PubSub message security (OPC UA Part 14
 * §5.4.5.3, §6.2.5.4, §8.3.2).
 *
 * <p>{@code SksSecurityKeyProvider} implements the {@code SecurityKeyProvider} SPI of {@code
 * org.eclipse.milo.opcua.sdk.pubsub.security} by pulling keys from an SKS with the {@code
 * GetSecurityKeys} method over an encrypted OPC UA client session. It lives in its own module
 * because the Part 14 §6.2.5.4 Table 40 resolution model is decisively client-shaped: a configured
 * {@code SecurityKeyServices} entry is an SKS <em>identity record</em> (ApplicationUri +
 * DiscoveryUrls), not a connectable endpoint, so pulling keys requires the discovery service, an
 * {@code OpcUaClient} session with certificate trust validation, and identity providers — none of
 * which {@code milo-sdk-pubsub} may depend on.
 *
 * <p>The scope of this module is the pull direction only: the push model ({@code SetSecurityKeys})
 * is not implemented, and hosting the SKS server face lives with the server-integrated PubSub
 * module.
 */
@NullMarked
package org.eclipse.milo.opcua.sdk.pubsub.sks;

import org.jspecify.annotations.NullMarked;
