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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

class SksEndpointSelectorTest {

  private static final String APP_URI = "urn:test:sks";
  private static final String AES256_URI =
      "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";
  private static final String AES128_URI =
      "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep";

  @Test
  void discoveryTargetsUsesDiscoveryUrlsInOrder() {
    EndpointDescription entry =
        entry(APP_URI, null, null, "opc.tcp://sks-a:4840", "opc.tcp://sks-b:4840");

    assertEquals(
        List.of("opc.tcp://sks-a:4840", "opc.tcp://sks-b:4840"),
        SksEndpointSelector.discoveryTargets(entry));
  }

  @Test
  void discoveryTargetsSkipsEmptyUrls() {
    EndpointDescription entry = entry(APP_URI, null, null, "", "opc.tcp://sks-b:4840");

    assertEquals(List.of("opc.tcp://sks-b:4840"), SksEndpointSelector.discoveryTargets(entry));
  }

  @Test
  void discoveryTargetsFallsBackToEndpointUrlWhenNoDiscoveryUrls() {
    EndpointDescription entry = entry(APP_URI, "opc.tcp://sks-a:4840/session", null);

    assertEquals(
        List.of("opc.tcp://sks-a:4840/session", "opc.tcp://sks-a:4840/session/discovery"),
        SksEndpointSelector.discoveryTargets(entry));
  }

  @Test
  void discoveryTargetsFallbackDoesNotDoubleAppendDiscovery() {
    EndpointDescription entry = entry(APP_URI, "opc.tcp://sks-a:4840/discovery", null);

    assertEquals(
        List.of("opc.tcp://sks-a:4840/discovery"), SksEndpointSelector.discoveryTargets(entry));
  }

  @Test
  void discoveryTargetsIgnoresEndpointUrlWhenDiscoveryUrlsPresent() {
    EndpointDescription entry =
        entry(APP_URI, "opc.tcp://sks-a:4840/session", null, "opc.tcp://sks-a:4840");

    assertEquals(List.of("opc.tcp://sks-a:4840"), SksEndpointSelector.discoveryTargets(entry));
  }

  @Test
  void selectCandidatesFiltersApplicationUriAndSecurityMode() {
    EndpointDescription entry = entry(APP_URI, null, null, "opc.tcp://sks:4840");

    EndpointDescription matching =
        endpoint(APP_URI, MessageSecurityMode.SignAndEncrypt, AES256_URI, 3);
    EndpointDescription wrongUri =
        endpoint("urn:test:other", MessageSecurityMode.SignAndEncrypt, AES256_URI, 3);
    EndpointDescription signOnly = endpoint(APP_URI, MessageSecurityMode.Sign, AES256_URI, 2);
    EndpointDescription none = endpoint(APP_URI, MessageSecurityMode.None, null, 0);

    List<EndpointDescription> candidates =
        SksEndpointSelector.selectCandidates(entry, List.of(wrongUri, signOnly, none, matching));

    assertEquals(List.of(matching), candidates);
  }

  @Test
  void selectCandidatesConstrainsByEntryPolicyUri() {
    EndpointDescription entry = entry(APP_URI, null, AES128_URI, "opc.tcp://sks:4840");

    EndpointDescription aes256 =
        endpoint(APP_URI, MessageSecurityMode.SignAndEncrypt, AES256_URI, 5);
    EndpointDescription aes128 =
        endpoint(APP_URI, MessageSecurityMode.SignAndEncrypt, AES128_URI, 3);

    List<EndpointDescription> candidates =
        SksEndpointSelector.selectCandidates(entry, List.of(aes256, aes128));

    assertEquals(List.of(aes128), candidates);
  }

  @Test
  void selectCandidatesRanksBySecurityLevelWhenPolicyUnconstrained() {
    EndpointDescription entry = entry(APP_URI, null, null, "opc.tcp://sks:4840");

    EndpointDescription low = endpoint(APP_URI, MessageSecurityMode.SignAndEncrypt, AES128_URI, 1);
    EndpointDescription high = endpoint(APP_URI, MessageSecurityMode.SignAndEncrypt, AES256_URI, 9);
    EndpointDescription mid = endpoint(APP_URI, MessageSecurityMode.SignAndEncrypt, AES256_URI, 5);

    List<EndpointDescription> candidates =
        SksEndpointSelector.selectCandidates(entry, List.of(low, high, mid));

    assertEquals(List.of(high, mid, low), candidates);
  }

  @Test
  void selectCandidatesRankingIsStable() {
    EndpointDescription entry = entry(APP_URI, null, null, "opc.tcp://sks:4840");

    EndpointDescription first =
        endpoint(APP_URI, MessageSecurityMode.SignAndEncrypt, AES128_URI, 3);
    EndpointDescription second =
        endpoint(APP_URI, MessageSecurityMode.SignAndEncrypt, AES256_URI, 3);

    List<EndpointDescription> candidates =
        SksEndpointSelector.selectCandidates(entry, List.of(first, second));

    assertEquals(List.of(first, second), candidates);
  }

  @Test
  void selectCandidatesIsEmptyForNothingMatching() {
    EndpointDescription entry = entry(APP_URI, null, null, "opc.tcp://sks:4840");

    EndpointDescription wrongUri =
        endpoint("urn:test:other", MessageSecurityMode.SignAndEncrypt, AES256_URI, 3);

    assertTrue(SksEndpointSelector.selectCandidates(entry, List.of(wrongUri)).isEmpty());
  }

  private static EndpointDescription entry(
      String applicationUri,
      @Nullable String endpointUrl,
      @Nullable String securityPolicyUri,
      String... discoveryUrls) {

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
        endpointUrl,
        server,
        ByteString.NULL_VALUE,
        MessageSecurityMode.SignAndEncrypt,
        securityPolicyUri,
        null,
        null,
        ubyte(0));
  }

  private static EndpointDescription endpoint(
      String applicationUri,
      MessageSecurityMode securityMode,
      @Nullable String securityPolicyUri,
      int securityLevel) {

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
        securityMode,
        securityPolicyUri,
        null,
        null,
        ubyte(securityLevel));
  }
}
