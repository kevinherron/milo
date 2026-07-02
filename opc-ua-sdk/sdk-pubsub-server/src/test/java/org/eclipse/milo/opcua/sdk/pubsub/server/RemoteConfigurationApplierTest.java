/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.server;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ulong;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationRefDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationRefMask;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationRefMask.Field;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConnectionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PublishedDataSetDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.SecurityGroupDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.WriterGroupDataType;
import org.junit.jupiter.api.Test;

/** The CloseAndUpdate element-op matrix at unit level ({@link RemoteConfigurationApplier}). */
class RemoteConfigurationApplierTest {

  private static final ULong DEFAULT_PUBLISHER_ID = ulong(0x1122334455667788L);

  private static PubSubConnectionDataType connection(String name) {
    return new PubSubConnectionDataType(
        name, true, Variant.NULL_VALUE, "p", null, null, null, null, null);
  }

  private static PubSubConnectionDataType connection(
      String name, WriterGroupDataType... writerGroups) {
    return new PubSubConnectionDataType(
        name, true, Variant.NULL_VALUE, "p", null, null, null, writerGroups, null);
  }

  private static WriterGroupDataType writerGroup(String name, int id) {
    return new WriterGroupDataType(
        name,
        true,
        MessageSecurityMode.None,
        null,
        null,
        null,
        null,
        id == 0 ? null : ushort(id),
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null);
  }

  private static PubSubConfiguration2DataType config(PubSubConnectionDataType... connections) {
    return new PubSubConfiguration2DataType(
        null, connections, true, null, null, null, null, null, uint(0), null);
  }

  private static PubSubConfiguration2DataType config(
      PubSubConnectionDataType[] connections, SecurityGroupDataType[] securityGroups) {
    return new PubSubConfiguration2DataType(
        null, connections, true, null, null, null, securityGroups, null, uint(0), null);
  }

  private static PubSubConfigurationRefDataType ref(
      PubSubConfigurationRefMask mask, int connectionIndex, int groupIndex, int elementIndex) {
    return new PubSubConfigurationRefDataType(
        mask, ushort(elementIndex), ushort(connectionIndex), ushort(groupIndex));
  }

  private static RemoteConfigurationApplier applier(
      PubSubConfiguration2DataType current,
      PubSubConfiguration2DataType file,
      boolean sksAdminAllowed) {
    return new RemoteConfigurationApplier(
        current, file, sksAdminAllowed, DEFAULT_PUBLISHER_ID, Set.of(), Set.of());
  }

  @Test
  void addConnectionAppendsAndReportsAValue() {
    var current = config(connection("c1"));
    var file = config(connection("c2"));

    var result =
        applier(current, file, false)
            .apply(
                new PubSubConfigurationRefDataType[] {
                  ref(
                      PubSubConfigurationRefMask.of(Field.ElementAdd, Field.ReferenceConnection),
                      0,
                      0,
                      0)
                },
                uint(1));

    assertTrue(result.allGood());
    assertEquals(2, result.candidate().getConnections().length);
    assertEquals(1, result.configurationValues().length);
    assertEquals("c2", result.configurationValues()[0].getName());
  }

  @Test
  void removeConnectionDropsItByName() {
    var current = config(connection("c1"), connection("c2"));
    var file = config(connection("c1"));

    var result =
        applier(current, file, false)
            .apply(
                new PubSubConfigurationRefDataType[] {
                  ref(
                      PubSubConfigurationRefMask.of(Field.ElementRemove, Field.ReferenceConnection),
                      0,
                      0,
                      0)
                },
                uint(1));

    assertTrue(result.allGood());
    assertEquals(1, result.candidate().getConnections().length);
    assertEquals("c2", result.candidate().getConnections()[0].getName());
  }

  @Test
  void modifyOfAMissingElementIsNoMatch() {
    var current = config(connection("c1"));
    var file = config(connection("cX"));

    var result =
        applier(current, file, false)
            .apply(
                new PubSubConfigurationRefDataType[] {
                  ref(
                      PubSubConfigurationRefMask.of(Field.ElementModify, Field.ReferenceConnection),
                      0,
                      0,
                      0)
                },
                uint(1));

    assertFalse(result.allGood());
    assertEquals(StatusCodes.Bad_NoMatch, result.referencesResults()[0].getValue());
  }

  @Test
  void invalidOperationBitCombinationIsInvalidArgument() {
    var current = config(connection("c1"));
    var file = config(connection("c1"));

    var result =
        applier(current, file, false)
            .apply(
                new PubSubConfigurationRefDataType[] {
                  ref(
                      PubSubConfigurationRefMask.of(
                          Field.ElementAdd, Field.ElementModify, Field.ReferenceConnection),
                      0,
                      0,
                      0)
                },
                uint(1));

    assertEquals(StatusCodes.Bad_InvalidArgument, result.referencesResults()[0].getValue());
  }

  @Test
  void matchFindsAStructurallyEqualConnectionWithoutAdding() {
    var current = config(connection("c1"));
    var file = config(connection(null)); // name null for match

    var result =
        applier(current, file, false)
            .apply(
                new PubSubConfigurationRefDataType[] {
                  ref(
                      PubSubConfigurationRefMask.of(Field.ElementMatch, Field.ReferenceConnection),
                      0,
                      0,
                      0)
                },
                uint(1));

    assertTrue(result.allGood());
    assertEquals(1, result.candidate().getConnections().length);
  }

  @Test
  void matchReportsResolvedNameViaConfigurationValues() {
    var current = config(connection("c1"));
    var file = config(connection(null)); // name null for match

    var result =
        applier(current, file, false)
            .apply(
                new PubSubConfigurationRefDataType[] {
                  ref(
                      PubSubConfigurationRefMask.of(Field.ElementMatch, Field.ReferenceConnection),
                      0,
                      0,
                      0)
                },
                uint(1));

    assertTrue(result.allGood());
    // §9.1.3.7.6: the client learns the matched element's resolved name from ConfigurationValues
    assertEquals(1, result.configurationValues().length);
    assertEquals("c1", result.configurationValues()[0].getName());
  }

  @Test
  void addTopLevelPublishedDataSetAutoAssignsNullName() {
    var pds = new PublishedDataSetDataType(null, null, null, null, null);
    var current =
        new PubSubConfiguration2DataType(
            null, null, true, null, null, null, null, null, uint(0), null);
    var file =
        new PubSubConfiguration2DataType(
            new PublishedDataSetDataType[] {pds},
            null,
            true,
            null,
            null,
            null,
            null,
            null,
            uint(0),
            null);

    var result =
        applier(current, file, false)
            .apply(
                new PubSubConfigurationRefDataType[] {
                  ref(
                      PubSubConfigurationRefMask.of(Field.ElementAdd, Field.ReferencePubDataset),
                      0,
                      0,
                      0)
                },
                uint(1));

    assertTrue(result.allGood());
    PublishedDataSetDataType[] added = result.candidate().getPublishedDataSets();
    assertEquals(1, added.length);
    assertTrue(added[0].getName() != null && !added[0].getName().isEmpty());
    assertEquals(1, result.configurationValues().length);
    assertEquals(added[0].getName(), result.configurationValues()[0].getName());
  }

  @Test
  void pushTargetReferencesAreRejectedPerElement() {
    var current = config(connection("c1"));
    var file = config(connection("c1"));

    var result =
        applier(current, file, false)
            .apply(
                new PubSubConfigurationRefDataType[] {
                  ref(
                      PubSubConfigurationRefMask.of(Field.ElementAdd, Field.ReferencePushTarget),
                      0,
                      0,
                      0)
                },
                uint(1));

    assertEquals(StatusCodes.Bad_InvalidArgument, result.referencesResults()[0].getValue());
  }

  @Test
  void securityGroupReferencesRequireSksAdmin() {
    var sg = new SecurityGroupDataType("sg", null, null, null, null, null, null, null, null);
    var current = config(new PubSubConnectionDataType[0], new SecurityGroupDataType[0]);
    var file = config(new PubSubConnectionDataType[0], new SecurityGroupDataType[] {sg});

    var addSg =
        new PubSubConfigurationRefDataType[] {
          ref(
              PubSubConfigurationRefMask.of(Field.ElementAdd, Field.ReferenceSecurityGroup),
              0,
              0,
              0)
        };

    var denied = applier(current, file, false).apply(addSg, uint(1));
    assertEquals(StatusCodes.Bad_UserAccessDenied, denied.referencesResults()[0].getValue());

    var allowed = applier(current, file, true).apply(addSg, uint(1));
    assertTrue(allowed.allGood());
    assertEquals(1, allowed.candidate().getSecurityGroups().length);
  }

  @Test
  void partialModeAppliesSurvivorsWhileAtomicModeSeesTheFailure() {
    var current = config(connection("c1"));
    var file = config(connection("c2"), connection("cX"));

    var refs =
        new PubSubConfigurationRefDataType[] {
          ref(PubSubConfigurationRefMask.of(Field.ElementAdd, Field.ReferenceConnection), 0, 0, 0),
          ref(
              PubSubConfigurationRefMask.of(Field.ElementModify, Field.ReferenceConnection),
              1,
              0,
              0)
        };

    var result = applier(current, file, false).apply(refs, uint(1));

    assertFalse(result.allGood());
    assertTrue(result.anyGood());
    assertTrue(result.referencesResults()[0].isGood());
    assertEquals(StatusCodes.Bad_NoMatch, result.referencesResults()[1].getValue());
    // the survivor (add of c2) is in the candidate; the caller applies it only in partial mode
    assertEquals(2, result.candidate().getConnections().length);
  }

  @Test
  void addWriterGroupAutoAssignsNameAndInternalId() {
    var current = config(connection("c1"));
    var file = config(connection("c1", writerGroup(null, 0)));

    var result =
        applier(current, file, false)
            .apply(
                new PubSubConfigurationRefDataType[] {
                  ref(
                      PubSubConfigurationRefMask.of(Field.ElementAdd, Field.ReferenceWriterGroup),
                      0,
                      0,
                      0)
                },
                uint(1));

    assertTrue(result.allGood());
    WriterGroupDataType[] groups = result.candidate().getConnections()[0].getWriterGroups();
    assertEquals(1, groups.length);
    assertTrue(groups[0].getName() != null && !groups[0].getName().isEmpty());
    assertTrue(groups[0].getWriterGroupId().intValue() >= ReserveIdRegistry.MIN_INTERNAL_ID);
  }
}
