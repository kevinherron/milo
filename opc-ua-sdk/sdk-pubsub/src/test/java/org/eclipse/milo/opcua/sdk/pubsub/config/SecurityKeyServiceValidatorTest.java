/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.config;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link SecurityKeyServiceValidator}: the Part 14 §6.2.5.4 Table 40 identity-record
 * contract, with hard errors for unusable entries and warnings for tolerated producer-side "shall"
 * violations.
 */
class SecurityKeyServiceValidatorTest {

  private static EndpointDescription entry(
      String endpointUrl,
      String applicationUri,
      ApplicationType applicationType,
      String[] discoveryUrls) {

    return new EndpointDescription(
        endpointUrl,
        new ApplicationDescription(
            applicationUri,
            null,
            LocalizedText.english("SKS"),
            applicationType,
            null,
            null,
            discoveryUrls),
        ByteString.NULL_VALUE,
        MessageSecurityMode.SignAndEncrypt,
        null,
        null,
        null,
        ubyte(0));
  }

  @Test
  void conformantServerEntryIsValidWithoutWarnings() {
    EndpointDescription entry =
        entry(null, "urn:sks", ApplicationType.Server, new String[] {"opc.tcp://sks:4840"});

    SecurityKeyServiceValidator.Result result = SecurityKeyServiceValidator.validate(entry);

    assertTrue(result.isValid());
    assertTrue(result.errors().isEmpty());
    assertTrue(result.warnings().isEmpty());
  }

  @Test
  void serverEntryWithoutApplicationUriIsInvalid() {
    EndpointDescription entry =
        entry(null, null, ApplicationType.Server, new String[] {"opc.tcp://sks:4840"});

    SecurityKeyServiceValidator.Result result = SecurityKeyServiceValidator.validate(entry);

    assertFalse(result.isValid());
    assertTrue(result.errors().get(0).contains("applicationUri"), result.errors().toString());
  }

  @Test
  void serverEntryWithoutAnyUrlIsInvalid() {
    EndpointDescription entry = entry(null, "urn:sks", ApplicationType.Server, null);

    SecurityKeyServiceValidator.Result result = SecurityKeyServiceValidator.validate(entry);

    assertFalse(result.isValid());
    assertTrue(result.errors().get(0).contains("discoveryUrls"), result.errors().toString());
  }

  @Test
  void serverEntryWithOnlyEndpointUrlIsValidButWarned() {
    // The open62541-ecosystem reality: EndpointUrl filled, DiscoveryUrls empty (tolerance
    // fallback per K12: usable as a discovery target, with a warning).
    EndpointDescription entry =
        entry("opc.tcp://sks:4840", "urn:sks", ApplicationType.Server, null);

    SecurityKeyServiceValidator.Result result = SecurityKeyServiceValidator.validate(entry);

    assertTrue(result.isValid());
    assertFalse(result.warnings().isEmpty());
    assertTrue(result.warnings().get(0).contains("endpointUrl"), result.warnings().toString());
  }

  @Test
  void clientAndServerAndDiscoveryServerTypesAreInvalid() {
    for (ApplicationType type :
        List.of(ApplicationType.ClientAndServer, ApplicationType.DiscoveryServer)) {
      EndpointDescription entry = entry(null, "urn:sks", type, null);

      SecurityKeyServiceValidator.Result result = SecurityKeyServiceValidator.validate(entry);

      assertFalse(result.isValid());
      assertTrue(result.errors().get(0).contains("ApplicationType"), result.errors().toString());
    }
  }

  @Test
  void nonConformantChannelFieldsAreWarnedNotFailed() {
    EndpointDescription entry =
        new EndpointDescription(
            null,
            new ApplicationDescription(
                "urn:sks",
                null,
                LocalizedText.english("SKS"),
                ApplicationType.Server,
                null,
                null,
                new String[] {"opc.tcp://sks:4840"}),
            ByteString.of(new byte[] {1, 2, 3}),
            MessageSecurityMode.Sign,
            null,
            null,
            null,
            ubyte(3));

    SecurityKeyServiceValidator.Result result = SecurityKeyServiceValidator.validate(entry);

    assertTrue(result.isValid());
    assertEquals(3, result.warnings().size(), result.warnings().toString());
  }

  @Test
  void listValidationPrefixesEntryIndexes() {
    List<EndpointDescription> entries =
        List.of(
            entry(null, "urn:sks", ApplicationType.Server, new String[] {"opc.tcp://sks:4840"}),
            entry(null, null, ApplicationType.Server, null));

    SecurityKeyServiceValidator.Result result = SecurityKeyServiceValidator.validate(entries);

    assertFalse(result.isValid());
    assertTrue(
        result.errors().stream().allMatch(e -> e.startsWith("securityKeyServices[1]: ")),
        result.errors().toString());
  }

  @Test
  void emptyListIsValid() {
    SecurityKeyServiceValidator.Result result = SecurityKeyServiceValidator.validate(List.of());

    assertTrue(result.isValid());
    assertTrue(result.warnings().isEmpty());
  }
}
