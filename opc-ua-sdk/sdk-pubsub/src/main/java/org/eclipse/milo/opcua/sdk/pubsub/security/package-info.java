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
 * PubSub message security primitives and SPIs (OPC UA Part 14 §7.2.4.4.3, §8.3.2).
 *
 * <p>Key acquisition: {@code SecurityKeyProvider} supplies {@code SecurityKeySet} key material for
 * SecurityGroups, mirroring the Security Key Service {@code GetSecurityKeys} method; {@code
 * StaticSecurityKeyProvider} is the bundled pre-shared-key implementation (including the S2OPC/OPC
 * Labs key file directory convention), and {@code KeyCredentialStore} resolves the credentials an
 * SKS or broker connection authenticates with.
 *
 * <p>Crypto primitives: {@code PubSubSecurityPolicy} holds the parameter table of the two PubSub
 * SecurityPolicies (PubSub-Aes128-CTR, PubSub-Aes256-CTR); {@code SecurityKeyMaterial} splits key
 * data into its SigningKey/EncryptingKey/KeyNonce parts; {@code UadpMessageSecurity} implements the
 * AES-CTR payload transform, HMAC signing/verification, and MessageNonce composition.
 *
 * <p>Codec seams: {@code MessageSecurityContext} (with its {@code MessageNonceSupplier}) carries
 * everything the UADP encoder needs to secure one publish cycle, and {@code
 * SecurityContextResolver} is what the decoder consults per received secured NetworkMessage; both
 * ride the {@code EncodeContext}/{@code DecodeContext} records of the {@code .uadp} package.
 *
 * <p><b>Zeroization posture</b> (best-effort, explicitly owned): transport-shaped key data — the
 * immutable {@code ByteString}s in {@code SecurityKeySet} — is never wiped and remains reachable
 * until garbage collected. The mutable working copies are the wipeable representations: {@code
 * SecurityKeyMaterial} supports {@code destroy()} and should be destroyed by its owner when its
 * token leaves the retention window, and credential secrets are {@code char[]} copies wiped by
 * their owners after use. Zeroization on the JVM is best-effort defense in depth only — the garbage
 * collector may copy buffers and no physical-erasure guarantee exists; the process boundary remains
 * the primary protection for key material.
 */
@NullMarked
package org.eclipse.milo.opcua.sdk.pubsub.security;

import org.jspecify.annotations.NullMarked;
