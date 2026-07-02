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
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
 * Tests for {@link EffectiveMessageSecurity}: the root default → group → DataSetReader override
 * inheritance chain of Part 14 §6.2.5.4 / §6.2.9.9–6.2.9.11 / Table 232.
 */
class EffectiveMessageSecurityTest {

  private static final String POLICY_A =
      "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR";
  private static final String POLICY_B =
      "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR";

  private static EndpointDescription keyService(String applicationUri) {
    return new EndpointDescription(
        null,
        new ApplicationDescription(
            applicationUri,
            null,
            LocalizedText.english("SKS"),
            ApplicationType.Server,
            null,
            null,
            new String[] {"opc.tcp://sks.example:4840"}),
        ByteString.NULL_VALUE,
        MessageSecurityMode.SignAndEncrypt,
        null,
        null,
        null,
        ubyte(0));
  }

  private static SecurityGroupConfig securityGroup(String name) {
    return SecurityGroupConfig.builder(name).securityPolicyUri(POLICY_A).build();
  }

  private static PubSubConfig config(List<EndpointDescription> defaultKeyServices) {
    return PubSubConfig.builder()
        .securityGroup(securityGroup("sg-1"))
        .securityGroup(securityGroup("sg-2"))
        .defaultSecurityKeyServices(defaultKeyServices)
        .build();
  }

  private static WriterGroupConfig writerGroup(MessageSecurityConfig security) {
    return WriterGroupConfig.builder("wg")
        .writerGroupId(ushort(1))
        .messageSecurity(security)
        .build();
  }

  private static ReaderGroupConfig readerGroup(MessageSecurityConfig security) {
    return ReaderGroupConfig.builder("rg").messageSecurity(security).build();
  }

  private static DataSetReaderConfig dataSetReader(MessageSecurityConfig security) {
    return DataSetReaderConfig.builder("r").messageSecurity(security).build();
  }

  @Test
  void groupWithoutKeyServicesInheritsRootDefaults() {
    EndpointDescription defaultService = keyService("urn:sks:default");
    PubSubConfig config = config(List.of(defaultService));

    WriterGroupConfig group =
        writerGroup(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.Sign)
                .securityGroup(new SecurityGroupRef("sg-1"))
                .build());

    EffectiveMessageSecurity effective = EffectiveMessageSecurity.of(config, group);

    assertEquals(MessageSecurityMode.Sign, effective.mode());
    assertTrue(effective.isSecured());
    assertNotNull(effective.securityGroup());
    assertEquals("sg-1", effective.securityGroup().getName());
    // No explicit policy on the group: the SecurityGroup's policy applies.
    assertEquals(POLICY_A, effective.securityPolicyUri());
    assertEquals(List.of(defaultService), effective.securityKeyServices());
  }

  @Test
  void groupKeyServicesAndPolicyWinOverInherited() {
    EndpointDescription groupService = keyService("urn:sks:group");
    PubSubConfig config = config(List.of(keyService("urn:sks:default")));

    ReaderGroupConfig group =
        readerGroup(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.SignAndEncrypt)
                .securityGroup(new SecurityGroupRef("sg-1"))
                .securityPolicyUri(POLICY_B)
                .keyServices(List.of(groupService))
                .build());

    EffectiveMessageSecurity effective = EffectiveMessageSecurity.of(config, group);

    assertEquals(MessageSecurityMode.SignAndEncrypt, effective.mode());
    assertEquals(POLICY_B, effective.securityPolicyUri());
    assertEquals(List.of(groupService), effective.securityKeyServices());
  }

  @Test
  void activeReaderOverrideReplacesGroupSettings() {
    EndpointDescription readerService = keyService("urn:sks:reader");
    PubSubConfig config = config(List.of());

    ReaderGroupConfig group =
        readerGroup(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.None)
                .securityGroup(new SecurityGroupRef("sg-1"))
                .keyServices(List.of(keyService("urn:sks:group")))
                .build());

    DataSetReaderConfig reader =
        dataSetReader(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.Sign)
                .securityGroup(new SecurityGroupRef("sg-2"))
                .keyServices(List.of(readerService))
                .build());

    EffectiveMessageSecurity effective = EffectiveMessageSecurity.of(config, group, reader);

    assertEquals(MessageSecurityMode.Sign, effective.mode());
    assertNotNull(effective.securityGroup());
    assertEquals("sg-2", effective.securityGroup().getName());
    assertEquals(List.of(readerService), effective.securityKeyServices());
  }

  @Test
  void invalidModeReaderOverrideIsInactive() {
    EndpointDescription groupService = keyService("urn:sks:group");
    PubSubConfig config = config(List.of());

    ReaderGroupConfig group =
        readerGroup(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.SignAndEncrypt)
                .securityGroup(new SecurityGroupRef("sg-1"))
                .keyServices(List.of(groupService))
                .build());

    // Invalid = the §6.2.9.9 "no override" sentinel: everything comes from the group.
    DataSetReaderConfig reader =
        dataSetReader(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.Invalid)
                .securityGroup(new SecurityGroupRef("sg-2"))
                .build());

    EffectiveMessageSecurity effective = EffectiveMessageSecurity.of(config, group, reader);

    assertEquals(MessageSecurityMode.SignAndEncrypt, effective.mode());
    assertNotNull(effective.securityGroup());
    assertEquals("sg-1", effective.securityGroup().getName());
    assertEquals(List.of(groupService), effective.securityKeyServices());
  }

  @Test
  void activeReaderOverrideFallsBackPerField() {
    EndpointDescription groupService = keyService("urn:sks:group");
    PubSubConfig config = config(List.of());

    ReaderGroupConfig group =
        readerGroup(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.SignAndEncrypt)
                .securityGroup(new SecurityGroupRef("sg-1"))
                .keyServices(List.of(groupService))
                .build());

    // The override restates only the mode; group and key services fall back to the group's.
    DataSetReaderConfig reader =
        dataSetReader(MessageSecurityConfig.builder().mode(MessageSecurityMode.Sign).build());

    EffectiveMessageSecurity effective = EffectiveMessageSecurity.of(config, group, reader);

    assertEquals(MessageSecurityMode.Sign, effective.mode());
    assertNotNull(effective.securityGroup());
    assertEquals("sg-1", effective.securityGroup().getName());
    assertEquals(List.of(groupService), effective.securityKeyServices());
  }

  @Test
  void readerOverrideSelectedGroupPolicyWinsOverGroupExplicitUri() {
    // sg-a pins POLICY_A, sg-b pins POLICY_B
    PubSubConfig config =
        PubSubConfig.builder()
            .securityGroup(SecurityGroupConfig.builder("sg-a").securityPolicyUri(POLICY_A).build())
            .securityGroup(SecurityGroupConfig.builder("sg-b").securityPolicyUri(POLICY_B).build())
            .build();

    // the group's explicit URI describes ITS SecurityGroup (sg-a)...
    ReaderGroupConfig group =
        readerGroup(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.Sign)
                .securityGroup(new SecurityGroupRef("sg-a"))
                .securityPolicyUri(POLICY_A)
                .build());

    // ...and must not constrain the DIFFERENT SecurityGroup an active reader override selects
    DataSetReaderConfig reader =
        dataSetReader(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.Sign)
                .securityGroup(new SecurityGroupRef("sg-b"))
                .build());

    EffectiveMessageSecurity effective = EffectiveMessageSecurity.of(config, group, reader);

    assertNotNull(effective.securityGroup());
    assertEquals("sg-b", effective.securityGroup().getName());
    assertEquals(POLICY_B, effective.securityPolicyUri());
  }

  @Test
  void groupExplicitUriAppliesWhenOverrideRestatesTheSameGroup() {
    PubSubConfig config =
        PubSubConfig.builder()
            .securityGroup(SecurityGroupConfig.builder("sg-a").securityPolicyUri(POLICY_A).build())
            .build();

    // the group pins an explicit URI for sg-a (overriding sg-a's own POLICY_A)
    ReaderGroupConfig group =
        readerGroup(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.Sign)
                .securityGroup(new SecurityGroupRef("sg-a"))
                .securityPolicyUri(POLICY_B)
                .build());

    // the override names the SAME SecurityGroup without restating a URI: the group's explicit
    // URI still describes that group and applies
    DataSetReaderConfig reader =
        dataSetReader(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.SignAndEncrypt)
                .securityGroup(new SecurityGroupRef("sg-a"))
                .build());

    EffectiveMessageSecurity effective = EffectiveMessageSecurity.of(config, group, reader);

    assertEquals(POLICY_B, effective.securityPolicyUri());
  }

  @Test
  void readerOverrideExplicitUriAlwaysWins() {
    PubSubConfig config =
        PubSubConfig.builder()
            .securityGroup(SecurityGroupConfig.builder("sg-b").securityPolicyUri(POLICY_B).build())
            .build();

    ReaderGroupConfig group = readerGroup(MessageSecurityConfig.builder().build());

    DataSetReaderConfig reader =
        dataSetReader(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.Sign)
                .securityGroup(new SecurityGroupRef("sg-b"))
                .securityPolicyUri(POLICY_A)
                .build());

    EffectiveMessageSecurity effective = EffectiveMessageSecurity.of(config, group, reader);

    assertEquals(POLICY_A, effective.securityPolicyUri());
  }

  @Test
  void noSecurityAnywhereIsUnsecuredWithRootDefaults() {
    EndpointDescription defaultService = keyService("urn:sks:default");
    PubSubConfig config = config(List.of(defaultService));

    WriterGroupConfig group = WriterGroupConfig.builder("wg").writerGroupId(ushort(1)).build();

    EffectiveMessageSecurity effective = EffectiveMessageSecurity.of(config, group);

    assertEquals(MessageSecurityMode.None, effective.mode());
    assertFalse(effective.isSecured());
    assertNull(effective.securityGroup());
    assertNull(effective.securityPolicyUri());
    assertEquals(List.of(defaultService), effective.securityKeyServices());
  }
}
