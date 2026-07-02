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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetMetaDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetReaderDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetWriterDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.KeyValuePair;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationRefDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationRefMask;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationValueDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConnectionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PublishedDataSetDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.ReaderGroupDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.SecurityGroupDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.StandaloneSubscribedDataSetDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpWriterGroupMessageDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.WriterGroupDataType;
import org.jspecify.annotations.Nullable;

/**
 * Applies the {@code ConfigurationReferences} of a {@code CloseAndUpdate} call to the current
 * PubSub configuration, producing a candidate {@link PubSubConfiguration2DataType} plus the
 * full-length per-reference results, the assigned {@code ConfigurationValues} and the {@code
 * ConfigurationObjects} NodeIds (OPC UA Part 14 §9.1.3.7.6, element-op rules per §9.1.3.7.2 Table
 * 239 — the authoritative closeandupdate gap analysis).
 *
 * <p>Element-op semantics (WP-X pin R4):
 *
 * <ul>
 *   <li>Exactly five operation-bit rows are valid: Add, Match, Add+Match, Modify, Remove. Every
 *       other combination — including zero operation bits, multiple operation bits, or
 *       zero/multiple reference bits — is per-element {@code Bad_InvalidArgument}.
 *   <li>Match applies only to Connection / WriterGroup / ReaderGroup references (else {@code
 *       Bad_InvalidArgument}); Match against a live UADP WriterGroup whose GroupHeader is active is
 *       {@code Bad_InvalidState}. Add+Match is the add-if-missing idiom.
 *   <li>Removes are processed first; remaining refs are processed parents-before-children so an
 *       added parent is visible to a child add in the same call.
 *   <li>Add auto-assigns a name when null/empty, the transport-profile default PublisherId when
 *       null (connections), and a unique WriterGroupId/DataSetWriterId from the internal range
 *       {@code 0x8000-0xFFFF} when null/0.
 *   <li>SecurityGroup references (bit 11) are honored only when SKS administration is authorized
 *       ({@code Bad_UserAccessDenied} otherwise); PushTarget references (bit 12) are always
 *       rejected per-element with {@code Bad_InvalidArgument} (unsupported), never a method-level
 *       failure.
 * </ul>
 *
 * <p>The applier builds the "survivors-applied" candidate: failed refs never mutate it. The caller
 * decides whether to apply the candidate based on {@code RequireCompleteUpdate}: in atomic mode
 * only when every ref succeeded, in partial mode whenever at least one ref succeeded. Whole-config
 * validity (id uniqueness, publisher-id presence, ...) is enforced by the subsequent {@code
 * reconfigure}, not here.
 */
final class RemoteConfigurationApplier {

  /** The outcome of applying the references to the current configuration. */
  record Result(
      PubSubConfiguration2DataType candidate,
      StatusCode[] referencesResults,
      PubSubConfigurationValueDataType[] configurationValues,
      String[] objectPaths,
      boolean allGood,
      boolean anyGood) {}

  private final PubSubConfiguration2DataType fileConfig;
  private final boolean sksAdminAllowed;
  private final Object defaultDatagramPublisherId;

  // working configuration, seeded from the current configuration
  private final List<PubSubConnectionDataType> connections;
  private final List<PublishedDataSetDataType> publishedDataSets;
  private final List<StandaloneSubscribedDataSetDataType> subscribedDataSets;
  private final List<SecurityGroupDataType> securityGroups;
  private final @Nullable Boolean enabled;
  private final DataSetMetaDataType @Nullable [] dataSetClasses;
  private EndpointDescription @Nullable [] defaultSecurityKeyServices;
  private final Map<QualifiedName, KeyValuePair> configurationProperties = new LinkedHashMap<>();

  // id allocation bookkeeping (config ids + all outstanding reservations, grown as ids are
  // assigned)
  private final Set<Integer> usedWriterGroupIds;
  private final Set<Integer> usedDataSetWriterIds;
  private int nameCounter = 0;

  /**
   * @param currentConfig the live configuration in wire form.
   * @param fileConfig the written file body.
   * @param sksAdminAllowed whether the caller is authorized for SKS administration (gates bit 11).
   * @param defaultDatagramPublisherId the datagram/UADP default PublisherId (UInt64) used for
   *     connection Add auto-assignment.
   * @param usedWriterGroupIds WriterGroupIds already used by the config or any outstanding
   *     reservation (the allocator avoids these).
   * @param usedDataSetWriterIds DataSetWriterIds already used by the config or any reservation.
   */
  RemoteConfigurationApplier(
      PubSubConfiguration2DataType currentConfig,
      PubSubConfiguration2DataType fileConfig,
      boolean sksAdminAllowed,
      Object defaultDatagramPublisherId,
      Set<Integer> usedWriterGroupIds,
      Set<Integer> usedDataSetWriterIds) {

    this.fileConfig = fileConfig;
    this.sksAdminAllowed = sksAdminAllowed;
    this.defaultDatagramPublisherId = defaultDatagramPublisherId;
    this.usedWriterGroupIds = new HashSet<>(usedWriterGroupIds);
    this.usedDataSetWriterIds = new HashSet<>(usedDataSetWriterIds);

    this.connections = new ArrayList<>(asList(currentConfig.getConnections()));
    this.publishedDataSets = new ArrayList<>(asList(currentConfig.getPublishedDataSets()));
    this.subscribedDataSets = new ArrayList<>(asList(currentConfig.getSubscribedDataSets()));
    this.securityGroups = new ArrayList<>(asList(currentConfig.getSecurityGroups()));
    this.enabled = currentConfig.getEnabled();
    this.dataSetClasses = currentConfig.getDataSetClasses();
    this.defaultSecurityKeyServices = currentConfig.getDefaultSecurityKeyServices();
    for (KeyValuePair pair : asList(currentConfig.getConfigurationProperties())) {
      if (pair.getKey() != null) {
        configurationProperties.put(pair.getKey(), pair);
      }
    }
  }

  /**
   * Apply {@code references}, returning the candidate configuration and full-length results.
   *
   * @param references the {@code ConfigurationReferences} argument (already checked non-empty).
   * @param configurationVersion the VersionTime to stamp on the candidate.
   */
  Result apply(PubSubConfigurationRefDataType[] references, UInteger configurationVersion) {
    applyTopLevelFileFields();

    var results = new StatusCode[references.length];
    Arrays.fill(results, StatusCode.GOOD);
    var values = new ArrayList<PubSubConfigurationValueDataType>();
    // an empty path denotes "no object" (removed element, or a failed ref)
    var objectPaths = new String[references.length];
    Arrays.fill(objectPaths, "");

    // stable processing order: removes first, then parents-before-children; original index kept
    List<Integer> order = new ArrayList<>();
    for (int i = 0; i < references.length; i++) {
      order.add(i);
    }
    order.sort(Comparator.comparingInt(i -> processingRank(references[i].getConfigurationMask())));

    boolean allGood = true;
    boolean anyGood = false;

    for (int index : order) {
      PubSubConfigurationRefDataType ref = references[index];
      var out = new RefOutput();
      StatusCode result = processRef(ref, out);
      results[index] = result;
      if (result.isGood()) {
        anyGood = true;
        objectPaths[index] = out.objectPath != null ? out.objectPath : "";
        if (out.value != null) {
          values.add(out.value);
        }
      } else {
        allGood = false;
      }
    }

    PubSubConfiguration2DataType candidate = toDataType(configurationVersion);

    return new Result(
        candidate,
        results,
        values.toArray(PubSubConfigurationValueDataType[]::new),
        objectPaths,
        allGood,
        anyGood);
  }

  // region top-level fields (§9.1.3.7.6)

  private void applyTopLevelFileFields() {
    // Enable and DataSetClasses ignored. DefaultSecurityKeyServices replaced iff non-empty.
    EndpointDescription[] fileKeyServices = fileConfig.getDefaultSecurityKeyServices();
    if (fileKeyServices != null && fileKeyServices.length > 0) {
      defaultSecurityKeyServices = fileKeyServices;
    }

    // ConfigurationProperties merged: non-null value inserts/replaces, null value deletes.
    KeyValuePair[] fileProperties = fileConfig.getConfigurationProperties();
    if (fileProperties != null) {
      for (KeyValuePair pair : fileProperties) {
        if (pair == null || pair.getKey() == null) {
          continue;
        }
        QualifiedName key = pair.getKey();
        Variant value = pair.getValue();
        if (value == null || value.isNull()) {
          configurationProperties.remove(key);
        } else {
          configurationProperties.put(key, pair);
        }
      }
    }
  }

  // endregion

  // region per-ref dispatch

  private StatusCode processRef(PubSubConfigurationRefDataType ref, RefOutput out) {
    PubSubConfigurationRefMask mask = ref.getConfigurationMask();
    if (mask == null) {
      return new StatusCode(StatusCodes.Bad_InvalidArgument);
    }

    Op op = resolveOp(mask);
    if (op == null) {
      return new StatusCode(StatusCodes.Bad_InvalidArgument);
    }

    int referenceBits = referenceBitCount(mask);
    if (referenceBits != 1) {
      return new StatusCode(StatusCodes.Bad_InvalidArgument);
    }

    if (mask.getReferencePushTarget()) {
      // PushTarget management is unsupported: per-element rejection, never a method-level failure
      return new StatusCode(StatusCodes.Bad_InvalidArgument);
    }
    if (mask.getReferenceSecurityGroup() && !sksAdminAllowed) {
      return new StatusCode(StatusCodes.Bad_UserAccessDenied);
    }

    // Match is only legal for Connection / WriterGroup / ReaderGroup references
    if (op.match
        && !(mask.getReferenceConnection()
            || mask.getReferenceWriterGroup()
            || mask.getReferenceReaderGroup())) {
      return new StatusCode(StatusCodes.Bad_InvalidArgument);
    }

    try {
      if (mask.getReferenceConnection()) {
        return connectionRef(ref, op, out);
      } else if (mask.getReferenceWriterGroup()) {
        return writerGroupRef(ref, op, out);
      } else if (mask.getReferenceReaderGroup()) {
        return readerGroupRef(ref, op, out);
      } else if (mask.getReferenceWriter()) {
        return writerRef(ref, op, out);
      } else if (mask.getReferenceReader()) {
        return readerRef(ref, op, out);
      } else if (mask.getReferencePubDataset()) {
        return publishedDataSetRef(ref, op, out);
      } else if (mask.getReferenceSubDataset()) {
        return subscribedDataSetRef(ref, op, out);
      } else if (mask.getReferenceSecurityGroup()) {
        return securityGroupRef(ref, op, out);
      }
      return new StatusCode(StatusCodes.Bad_InvalidArgument);
    } catch (ElementException e) {
      return new StatusCode(e.statusCode);
    }
  }

  // endregion

  // region connection refs

  private StatusCode connectionRef(PubSubConfigurationRefDataType ref, Op op, RefOutput out) {
    if (op.remove) {
      PubSubConnectionDataType fileConn = fileConnection(ref);
      String name = requireName(fileConn.getName());
      int idx = indexOfConnection(name);
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      connections.remove(idx);
      return StatusCode.GOOD;
    }

    if (op.modify) {
      PubSubConnectionDataType fileConn = fileConnection(ref);
      String name = requireName(fileConn.getName());
      int idx = indexOfConnection(name);
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      connections.set(idx, fileConn);
      out.objectPath = connectionPath(name);
      return StatusCode.GOOD;
    }

    // add / match / add+match
    PubSubConnectionDataType fileConn = fileConnection(ref);
    if (op.match) {
      int matched = matchConnection(fileConn);
      if (matched >= 0) {
        PubSubConnectionDataType live = connections.get(matched);
        String name = nullToEmpty(live.getName());
        out.objectPath = connectionPath(name);
        // §9.1.3.7.6: report the resolved name/identifier for Match refs (the file element's
        // name and Id are null under Match, so the client learns them via ConfigurationValues)
        out.value =
            new PubSubConfigurationValueDataType(
                ref,
                name,
                live.getPublisherId() != null ? live.getPublisherId() : Variant.NULL_VALUE);
        return StatusCode.GOOD;
      }
      if (!op.add) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
    }

    // add
    PubSubConnectionDataType added = autoAssignConnection(fileConn);
    String name = nullToEmpty(added.getName());
    if (indexOfConnection(name) >= 0) {
      return new StatusCode(StatusCodes.Bad_BrowseNameDuplicated);
    }
    connections.add(added);
    out.objectPath = connectionPath(name);
    out.value =
        new PubSubConfigurationValueDataType(
            ref,
            name,
            added.getPublisherId() != null ? added.getPublisherId() : Variant.NULL_VALUE);
    return StatusCode.GOOD;
  }

  // endregion

  // region writer-group refs

  private StatusCode writerGroupRef(PubSubConfigurationRefDataType ref, Op op, RefOutput out) {
    int connIdx = parentConnectionIndex(ref);
    PubSubConnectionDataType conn = connections.get(connIdx);
    List<WriterGroupDataType> groups = new ArrayList<>(asList(conn.getWriterGroups()));

    if (op.remove) {
      WriterGroupDataType fileGroup = fileWriterGroup(ref);
      String name = requireName(fileGroup.getName());
      int idx = indexByName(groups, WriterGroupDataType::getName, name);
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      groups.remove(idx);
      connections.set(connIdx, connReplaceGroups(conn, groups, null));
      return StatusCode.GOOD;
    }

    if (op.modify) {
      WriterGroupDataType fileGroup = fileWriterGroup(ref);
      String name = requireName(fileGroup.getName());
      int idx = indexByName(groups, WriterGroupDataType::getName, name);
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      groups.set(idx, fileGroup);
      connections.set(connIdx, connReplaceGroups(conn, groups, null));
      out.objectPath = groupPath(nullToEmpty(conn.getName()), name);
      return StatusCode.GOOD;
    }

    WriterGroupDataType fileGroup = fileWriterGroup(ref);
    if (op.match) {
      int matched = matchWriterGroup(groups, fileGroup);
      if (matched >= 0) {
        WriterGroupDataType live = groups.get(matched);
        if (groupHeaderActive(live)) {
          return new StatusCode(StatusCodes.Bad_InvalidState);
        }
        String name = nullToEmpty(live.getName());
        out.objectPath = groupPath(nullToEmpty(conn.getName()), name);
        // §9.1.3.7.6: report the resolved name/WriterGroupId for the matched group
        out.value =
            new PubSubConfigurationValueDataType(
                ref,
                name,
                live.getWriterGroupId() != null
                    ? new Variant(live.getWriterGroupId())
                    : Variant.NULL_VALUE);
        return StatusCode.GOOD;
      }
      if (!op.add) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
    }

    WriterGroupDataType added = autoAssignWriterGroup(fileGroup);
    String name = nullToEmpty(added.getName());
    if (indexByName(groups, WriterGroupDataType::getName, name) >= 0) {
      return new StatusCode(StatusCodes.Bad_BrowseNameDuplicated);
    }
    groups.add(added);
    connections.set(connIdx, connReplaceGroups(conn, groups, null));
    out.objectPath = groupPath(nullToEmpty(conn.getName()), name);
    out.value =
        new PubSubConfigurationValueDataType(
            ref,
            name,
            added.getWriterGroupId() != null
                ? new Variant(added.getWriterGroupId())
                : Variant.NULL_VALUE);
    return StatusCode.GOOD;
  }

  // endregion

  // region reader-group refs

  private StatusCode readerGroupRef(PubSubConfigurationRefDataType ref, Op op, RefOutput out) {
    int connIdx = parentConnectionIndex(ref);
    PubSubConnectionDataType conn = connections.get(connIdx);
    List<ReaderGroupDataType> groups = new ArrayList<>(asList(conn.getReaderGroups()));

    if (op.remove) {
      ReaderGroupDataType fileGroup = fileReaderGroup(ref);
      String name = requireName(fileGroup.getName());
      int idx = indexByName(groups, ReaderGroupDataType::getName, name);
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      groups.remove(idx);
      connections.set(connIdx, connReplaceGroups(conn, null, groups));
      return StatusCode.GOOD;
    }

    if (op.modify) {
      ReaderGroupDataType fileGroup = fileReaderGroup(ref);
      String name = requireName(fileGroup.getName());
      int idx = indexByName(groups, ReaderGroupDataType::getName, name);
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      groups.set(idx, fileGroup);
      connections.set(connIdx, connReplaceGroups(conn, null, groups));
      out.objectPath = groupPath(nullToEmpty(conn.getName()), name);
      return StatusCode.GOOD;
    }

    ReaderGroupDataType fileGroup = fileReaderGroup(ref);
    if (op.match) {
      int matched = matchReaderGroup(groups, fileGroup);
      if (matched >= 0) {
        String name = nullToEmpty(groups.get(matched).getName());
        out.objectPath = groupPath(nullToEmpty(conn.getName()), name);
        // §9.1.3.7.6: report the resolved name for the matched reader group (no identifier)
        out.value = new PubSubConfigurationValueDataType(ref, name, Variant.NULL_VALUE);
        return StatusCode.GOOD;
      }
      if (!op.add) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
    }

    ReaderGroupDataType added = autoAssignReaderGroup(fileGroup);
    String name = nullToEmpty(added.getName());
    if (indexByName(groups, ReaderGroupDataType::getName, name) >= 0) {
      return new StatusCode(StatusCodes.Bad_BrowseNameDuplicated);
    }
    groups.add(added);
    connections.set(connIdx, connReplaceGroups(conn, null, groups));
    out.objectPath = groupPath(nullToEmpty(conn.getName()), name);
    out.value = new PubSubConfigurationValueDataType(ref, name, Variant.NULL_VALUE);
    return StatusCode.GOOD;
  }

  // endregion

  // region writer / reader refs

  private StatusCode writerRef(PubSubConfigurationRefDataType ref, Op op, RefOutput out) {
    int connIdx = parentConnectionIndex(ref);
    PubSubConnectionDataType conn = connections.get(connIdx);
    List<WriterGroupDataType> groups = new ArrayList<>(asList(conn.getWriterGroups()));

    // parent group identified by the file group's name
    WriterGroupDataType fileGroup = fileWriterGroup(ref);
    int groupIdx =
        indexByName(groups, WriterGroupDataType::getName, requireName(fileGroup.getName()));
    if (groupIdx < 0) {
      return new StatusCode(StatusCodes.Bad_NotFound);
    }
    WriterGroupDataType group = groups.get(groupIdx);
    List<DataSetWriterDataType> writers = new ArrayList<>(asList(group.getDataSetWriters()));

    DataSetWriterDataType fileWriter = fileWriter(ref);

    if (op.remove) {
      int idx =
          indexByName(writers, DataSetWriterDataType::getName, requireName(fileWriter.getName()));
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      writers.remove(idx);
    } else if (op.modify) {
      int idx =
          indexByName(writers, DataSetWriterDataType::getName, requireName(fileWriter.getName()));
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      writers.set(idx, fileWriter);
      out.objectPath =
          writerReaderPath(
              nullToEmpty(conn.getName()),
              nullToEmpty(group.getName()),
              nullToEmpty(fileWriter.getName()));
    } else {
      // add (Match already excluded by dispatch)
      DataSetWriterDataType added = autoAssignWriter(fileWriter);
      String name = nullToEmpty(added.getName());
      if (indexByName(writers, DataSetWriterDataType::getName, name) >= 0) {
        return new StatusCode(StatusCodes.Bad_BrowseNameDuplicated);
      }
      writers.add(added);
      out.objectPath =
          writerReaderPath(nullToEmpty(conn.getName()), nullToEmpty(group.getName()), name);
      out.value =
          new PubSubConfigurationValueDataType(
              ref,
              name,
              added.getDataSetWriterId() != null
                  ? new Variant(added.getDataSetWriterId())
                  : Variant.NULL_VALUE);
    }

    groups.set(groupIdx, groupReplaceWriters(group, writers));
    connections.set(connIdx, connReplaceGroups(conn, groups, null));
    return StatusCode.GOOD;
  }

  private StatusCode readerRef(PubSubConfigurationRefDataType ref, Op op, RefOutput out) {
    int connIdx = parentConnectionIndex(ref);
    PubSubConnectionDataType conn = connections.get(connIdx);
    List<ReaderGroupDataType> groups = new ArrayList<>(asList(conn.getReaderGroups()));

    ReaderGroupDataType fileGroup = fileReaderGroup(ref);
    int groupIdx =
        indexByName(groups, ReaderGroupDataType::getName, requireName(fileGroup.getName()));
    if (groupIdx < 0) {
      return new StatusCode(StatusCodes.Bad_NotFound);
    }
    ReaderGroupDataType group = groups.get(groupIdx);
    List<DataSetReaderDataType> readers = new ArrayList<>(asList(group.getDataSetReaders()));

    DataSetReaderDataType fileReader = fileReader(ref);

    if (op.remove) {
      int idx =
          indexByName(readers, DataSetReaderDataType::getName, requireName(fileReader.getName()));
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      readers.remove(idx);
    } else if (op.modify) {
      int idx =
          indexByName(readers, DataSetReaderDataType::getName, requireName(fileReader.getName()));
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      readers.set(idx, fileReader);
      out.objectPath =
          writerReaderPath(
              nullToEmpty(conn.getName()),
              nullToEmpty(group.getName()),
              nullToEmpty(fileReader.getName()));
    } else {
      DataSetReaderDataType added = autoAssignReader(fileReader);
      String name = nullToEmpty(added.getName());
      if (indexByName(readers, DataSetReaderDataType::getName, name) >= 0) {
        return new StatusCode(StatusCodes.Bad_BrowseNameDuplicated);
      }
      readers.add(added);
      out.objectPath =
          writerReaderPath(nullToEmpty(conn.getName()), nullToEmpty(group.getName()), name);
      out.value = new PubSubConfigurationValueDataType(ref, name, Variant.NULL_VALUE);
    }

    groups.set(groupIdx, groupReplaceReaders(group, readers));
    connections.set(connIdx, connReplaceGroups(conn, null, groups));
    return StatusCode.GOOD;
  }

  // endregion

  // region top-level dataset / security-group refs

  private StatusCode publishedDataSetRef(PubSubConfigurationRefDataType ref, Op op, RefOutput out) {
    PublishedDataSetDataType fileDataSet =
        elementAt(fileConfig.getPublishedDataSets(), ref.getElementIndex());
    return topLevelOp(
        op,
        publishedDataSets,
        PublishedDataSetDataType::getName,
        fileDataSet,
        out,
        this::publishedDataSetPath,
        ref,
        "PublishedDataSet",
        RemoteConfigurationApplier::publishedDataSetWithName);
  }

  private StatusCode subscribedDataSetRef(
      PubSubConfigurationRefDataType ref, Op op, RefOutput out) {
    StandaloneSubscribedDataSetDataType fileDataSet =
        elementAt(fileConfig.getSubscribedDataSets(), ref.getElementIndex());
    return topLevelOp(
        op,
        subscribedDataSets,
        StandaloneSubscribedDataSetDataType::getName,
        fileDataSet,
        out,
        this::subscribedDataSetPath,
        ref,
        "SubscribedDataSet",
        RemoteConfigurationApplier::subscribedDataSetWithName);
  }

  private StatusCode securityGroupRef(PubSubConfigurationRefDataType ref, Op op, RefOutput out) {
    SecurityGroupDataType fileGroup =
        elementAt(fileConfig.getSecurityGroups(), ref.getElementIndex());
    return topLevelOp(
        op,
        securityGroups,
        SecurityGroupDataType::getName,
        fileGroup,
        out,
        this::securityGroupPath,
        ref,
        "SecurityGroup",
        RemoteConfigurationApplier::securityGroupWithName);
  }

  /**
   * Generic add/modify/remove for a top-level, name-keyed element list (Match not allowed here). On
   * Add, a null/empty name is auto-assigned per §9.1.3.7.2 Table 239 (ElementAdd is unconditional
   * about name assignment); the element's identifiers are not auto-assigned.
   */
  private <T> StatusCode topLevelOp(
      Op op,
      List<T> list,
      NameGetter<T> nameGetter,
      T fileElement,
      RefOutput out,
      UnaryOperator<String> pathFn,
      PubSubConfigurationRefDataType ref,
      String kind,
      BiFunction<T, String, T> withName) {

    if (op.match) {
      return new StatusCode(StatusCodes.Bad_InvalidArgument);
    }

    if (op.remove) {
      int idx = indexByName(list, nameGetter, requireName(nameGetter.name(fileElement)));
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      list.remove(idx);
      return StatusCode.GOOD;
    }
    if (op.modify) {
      String name = requireName(nameGetter.name(fileElement));
      int idx = indexByName(list, nameGetter, name);
      if (idx < 0) {
        return new StatusCode(StatusCodes.Bad_NoMatch);
      }
      list.set(idx, fileElement);
      out.objectPath = pathFn.apply(name);
      return StatusCode.GOOD;
    }

    // add: assign a name if null/empty (Table 239 ElementAdd); ids are not auto-assigned
    String provided = nameGetter.name(fileElement);
    T added;
    String name;
    if (provided != null && !provided.isEmpty()) {
      name = provided;
      added = fileElement;
    } else {
      name = assignName(null, kind, n -> indexByName(list, nameGetter, n) < 0);
      added = withName.apply(fileElement, name);
    }
    if (indexByName(list, nameGetter, name) >= 0) {
      return new StatusCode(StatusCodes.Bad_BrowseNameDuplicated);
    }
    list.add(added);
    out.objectPath = pathFn.apply(name);
    out.value = new PubSubConfigurationValueDataType(ref, name, Variant.NULL_VALUE);
    return StatusCode.GOOD;
  }

  private static PublishedDataSetDataType publishedDataSetWithName(
      PublishedDataSetDataType dataSet, String name) {
    return new PublishedDataSetDataType(
        name,
        dataSet.getDataSetFolder(),
        dataSet.getDataSetMetaData(),
        dataSet.getExtensionFields(),
        dataSet.getDataSetSource());
  }

  private static StandaloneSubscribedDataSetDataType subscribedDataSetWithName(
      StandaloneSubscribedDataSetDataType dataSet, String name) {
    return new StandaloneSubscribedDataSetDataType(
        name,
        dataSet.getDataSetFolder(),
        dataSet.getDataSetMetaData(),
        dataSet.getSubscribedDataSet());
  }

  private static SecurityGroupDataType securityGroupWithName(
      SecurityGroupDataType group, String name) {
    return new SecurityGroupDataType(
        name,
        group.getSecurityGroupFolder(),
        group.getKeyLifetime(),
        group.getSecurityPolicyUri(),
        group.getMaxFutureKeyCount(),
        group.getMaxPastKeyCount(),
        group.getSecurityGroupId(),
        group.getRolePermissions(),
        group.getGroupProperties());
  }

  // endregion

  // region matching (§9.1.3.7.2 Table 239 field-sets)

  private int matchConnection(PubSubConnectionDataType file) {
    for (int i = 0; i < connections.size(); i++) {
      PubSubConnectionDataType c = connections.get(i);
      if (Objects.equals(c.getTransportProfileUri(), file.getTransportProfileUri())
          && Objects.equals(c.getAddress(), file.getAddress())
          && Objects.equals(c.getTransportSettings(), file.getTransportSettings())) {
        return i;
      }
    }
    return -1;
  }

  private int matchWriterGroup(List<WriterGroupDataType> groups, WriterGroupDataType file) {
    for (int i = 0; i < groups.size(); i++) {
      WriterGroupDataType g = groups.get(i);
      if (g.getSecurityMode() == file.getSecurityMode()
          && Objects.equals(g.getSecurityGroupId(), file.getSecurityGroupId())
          && Arrays.equals(g.getSecurityKeyServices(), file.getSecurityKeyServices())
          && Objects.equals(g.getMaxNetworkMessageSize(), file.getMaxNetworkMessageSize())
          && Objects.equals(g.getPublishingInterval(), file.getPublishingInterval())
          && Objects.equals(g.getKeepAliveTime(), file.getKeepAliveTime())
          && Objects.equals(g.getPriority(), file.getPriority())
          && Objects.equals(g.getHeaderLayoutUri(), file.getHeaderLayoutUri())
          && Objects.equals(g.getTransportSettings(), file.getTransportSettings())
          && Objects.equals(g.getMessageSettings(), file.getMessageSettings())) {
        return i;
      }
    }
    return -1;
  }

  private int matchReaderGroup(List<ReaderGroupDataType> groups, ReaderGroupDataType file) {
    for (int i = 0; i < groups.size(); i++) {
      ReaderGroupDataType g = groups.get(i);
      if (g.getSecurityMode() == file.getSecurityMode()
          && Objects.equals(g.getSecurityGroupId(), file.getSecurityGroupId())
          && Arrays.equals(g.getSecurityKeyServices(), file.getSecurityKeyServices())
          && Objects.equals(g.getMaxNetworkMessageSize(), file.getMaxNetworkMessageSize())
          && Objects.equals(g.getTransportSettings(), file.getTransportSettings())
          && Objects.equals(g.getMessageSettings(), file.getMessageSettings())) {
        return i;
      }
    }
    return -1;
  }

  private static boolean groupHeaderActive(WriterGroupDataType group) {
    if (group.getMessageSettings() instanceof UadpWriterGroupMessageDataType uadp) {
      return uadp.getNetworkMessageContentMask() != null
          && uadp.getNetworkMessageContentMask().getGroupHeader();
    }
    return false;
  }

  // endregion

  // region auto-assignment

  private PubSubConnectionDataType autoAssignConnection(PubSubConnectionDataType file) {
    String name = assignName(file.getName(), "Connection", n -> indexOfConnection(n) < 0);

    Variant publisherId = file.getPublisherId();
    if (publisherId == null || publisherId.isNull()) {
      publisherId = new Variant(defaultPublisherIdFor(file.getTransportProfileUri()));
    }

    WriterGroupDataType[] writerGroups = mapWriterGroups(file.getWriterGroups());
    ReaderGroupDataType[] readerGroups = mapReaderGroups(file.getReaderGroups());

    return new PubSubConnectionDataType(
        name,
        file.getEnabled(),
        publisherId,
        file.getTransportProfileUri(),
        file.getAddress(),
        file.getConnectionProperties(),
        file.getTransportSettings(),
        writerGroups,
        readerGroups);
  }

  private WriterGroupDataType @Nullable [] mapWriterGroups(
      WriterGroupDataType @Nullable [] groups) {
    if (groups == null) {
      return null;
    }
    var out = new WriterGroupDataType[groups.length];
    for (int i = 0; i < groups.length; i++) {
      out[i] = autoAssignWriterGroup(groups[i]);
    }
    return out;
  }

  private ReaderGroupDataType @Nullable [] mapReaderGroups(
      ReaderGroupDataType @Nullable [] groups) {
    if (groups == null) {
      return null;
    }
    var out = new ReaderGroupDataType[groups.length];
    for (int i = 0; i < groups.length; i++) {
      out[i] = autoAssignReaderGroup(groups[i]);
    }
    return out;
  }

  private WriterGroupDataType autoAssignWriterGroup(WriterGroupDataType file) {
    String name = assignName(file.getName(), "WriterGroup", n -> true);
    UShort writerGroupId = file.getWriterGroupId();
    if (writerGroupId == null || writerGroupId.intValue() == 0) {
      writerGroupId = ushort(allocateId(usedWriterGroupIds));
    }
    DataSetWriterDataType @Nullable [] writers = file.getDataSetWriters();
    if (writers != null) {
      var out = new DataSetWriterDataType[writers.length];
      for (int i = 0; i < writers.length; i++) {
        out[i] = autoAssignWriter(writers[i]);
      }
      writers = out;
    }
    return new WriterGroupDataType(
        name,
        file.getEnabled(),
        file.getSecurityMode(),
        file.getSecurityGroupId(),
        file.getSecurityKeyServices(),
        file.getMaxNetworkMessageSize(),
        file.getGroupProperties(),
        writerGroupId,
        file.getPublishingInterval(),
        file.getKeepAliveTime(),
        file.getPriority(),
        file.getLocaleIds(),
        file.getHeaderLayoutUri(),
        file.getTransportSettings(),
        file.getMessageSettings(),
        writers);
  }

  private ReaderGroupDataType autoAssignReaderGroup(ReaderGroupDataType file) {
    String name = assignName(file.getName(), "ReaderGroup", n -> true);
    return new ReaderGroupDataType(
        name,
        file.getEnabled(),
        file.getSecurityMode(),
        file.getSecurityGroupId(),
        file.getSecurityKeyServices(),
        file.getMaxNetworkMessageSize(),
        file.getGroupProperties(),
        file.getTransportSettings(),
        file.getMessageSettings(),
        file.getDataSetReaders());
  }

  private DataSetWriterDataType autoAssignWriter(DataSetWriterDataType file) {
    String name = assignName(file.getName(), "DataSetWriter", n -> true);
    UShort id = file.getDataSetWriterId();
    if (id == null || id.intValue() == 0) {
      id = ushort(allocateId(usedDataSetWriterIds));
    }
    return new DataSetWriterDataType(
        name,
        file.getEnabled(),
        id,
        file.getDataSetFieldContentMask(),
        file.getKeyFrameCount(),
        file.getDataSetName(),
        file.getDataSetWriterProperties(),
        file.getTransportSettings(),
        file.getMessageSettings());
  }

  private DataSetReaderDataType autoAssignReader(DataSetReaderDataType file) {
    String name = assignName(file.getName(), "DataSetReader", n -> true);
    return new DataSetReaderDataType(
        name,
        file.getEnabled(),
        file.getPublisherId(),
        file.getWriterGroupId(),
        file.getDataSetWriterId(),
        file.getDataSetMetaData(),
        file.getDataSetFieldContentMask(),
        file.getMessageReceiveTimeout(),
        file.getKeyFrameCount(),
        file.getHeaderLayoutUri(),
        file.getSecurityMode() != null ? file.getSecurityMode() : MessageSecurityMode.Invalid,
        file.getSecurityGroupId(),
        file.getSecurityKeyServices(),
        file.getDataSetReaderProperties(),
        file.getTransportSettings(),
        file.getMessageSettings(),
        file.getSubscribedDataSet());
  }

  private String assignName(@Nullable String provided, String kind, Predicate<String> unique) {

    if (provided != null && !provided.isEmpty()) {
      return provided;
    }
    String name;
    do {
      name = kind + "_" + (++nameCounter);
    } while (!unique.test(name));
    return name;
  }

  private int allocateId(Set<Integer> used) {
    for (int id = ReserveIdRegistry.MIN_INTERNAL_ID;
        id <= ReserveIdRegistry.MAX_INTERNAL_ID;
        id++) {
      if (used.add(id)) {
        return id;
      }
    }
    throw new ElementException(StatusCodes.Bad_ResourceUnavailable);
  }

  private Object defaultPublisherIdFor(@Nullable String transportProfileUri) {
    if (ReserveIdRegistry.MQTT_JSON.equals(transportProfileUri)) {
      return defaultDatagramPublisherId.toString();
    }
    return defaultDatagramPublisherId;
  }

  // endregion

  // region file-element extraction + parent binding

  private PubSubConnectionDataType fileConnection(PubSubConfigurationRefDataType ref) {
    return elementAt(fileConfig.getConnections(), ref.getConnectionIndex());
  }

  private WriterGroupDataType fileWriterGroup(PubSubConfigurationRefDataType ref) {
    return elementAt(fileConnection(ref).getWriterGroups(), ref.getGroupIndex());
  }

  private ReaderGroupDataType fileReaderGroup(PubSubConfigurationRefDataType ref) {
    return elementAt(fileConnection(ref).getReaderGroups(), ref.getGroupIndex());
  }

  private DataSetWriterDataType fileWriter(PubSubConfigurationRefDataType ref) {
    return elementAt(fileWriterGroup(ref).getDataSetWriters(), ref.getElementIndex());
  }

  private DataSetReaderDataType fileReader(PubSubConfigurationRefDataType ref) {
    return elementAt(fileReaderGroup(ref).getDataSetReaders(), ref.getElementIndex());
  }

  /**
   * Resolve the working connection that parents a group/writer/reader ref, by the file connection's
   * name.
   */
  private int parentConnectionIndex(PubSubConfigurationRefDataType ref) {
    PubSubConnectionDataType fileConn = fileConnection(ref);
    String name = requireName(fileConn.getName());
    int idx = indexOfConnection(name);
    if (idx < 0) {
      throw new ElementException(StatusCodes.Bad_NotFound);
    }
    return idx;
  }

  // endregion

  // region working-config helpers

  private int indexOfConnection(String name) {
    return indexByName(connections, PubSubConnectionDataType::getName, name);
  }

  private static <T> int indexByName(List<T> list, NameGetter<T> nameGetter, String name) {
    for (int i = 0; i < list.size(); i++) {
      if (name.equals(nameGetter.name(list.get(i)))) {
        return i;
      }
    }
    return -1;
  }

  private static PubSubConnectionDataType connReplaceGroups(
      PubSubConnectionDataType conn,
      @Nullable List<WriterGroupDataType> writerGroups,
      @Nullable List<ReaderGroupDataType> readerGroups) {

    WriterGroupDataType @Nullable [] wgs =
        writerGroups != null
            ? writerGroups.toArray(WriterGroupDataType[]::new)
            : conn.getWriterGroups();
    ReaderGroupDataType @Nullable [] rgs =
        readerGroups != null
            ? readerGroups.toArray(ReaderGroupDataType[]::new)
            : conn.getReaderGroups();

    return new PubSubConnectionDataType(
        conn.getName(),
        conn.getEnabled(),
        conn.getPublisherId(),
        conn.getTransportProfileUri(),
        conn.getAddress(),
        conn.getConnectionProperties(),
        conn.getTransportSettings(),
        wgs,
        rgs);
  }

  private static WriterGroupDataType groupReplaceWriters(
      WriterGroupDataType group, List<DataSetWriterDataType> writers) {

    return new WriterGroupDataType(
        group.getName(),
        group.getEnabled(),
        group.getSecurityMode(),
        group.getSecurityGroupId(),
        group.getSecurityKeyServices(),
        group.getMaxNetworkMessageSize(),
        group.getGroupProperties(),
        group.getWriterGroupId(),
        group.getPublishingInterval(),
        group.getKeepAliveTime(),
        group.getPriority(),
        group.getLocaleIds(),
        group.getHeaderLayoutUri(),
        group.getTransportSettings(),
        group.getMessageSettings(),
        writers.toArray(DataSetWriterDataType[]::new));
  }

  private static ReaderGroupDataType groupReplaceReaders(
      ReaderGroupDataType group, List<DataSetReaderDataType> readers) {

    return new ReaderGroupDataType(
        group.getName(),
        group.getEnabled(),
        group.getSecurityMode(),
        group.getSecurityGroupId(),
        group.getSecurityKeyServices(),
        group.getMaxNetworkMessageSize(),
        group.getGroupProperties(),
        group.getTransportSettings(),
        group.getMessageSettings(),
        readers.toArray(DataSetReaderDataType[]::new));
  }

  private PubSubConfiguration2DataType toDataType(UInteger configurationVersion) {
    KeyValuePair[] properties = configurationProperties.values().toArray(KeyValuePair[]::new);

    return new PubSubConfiguration2DataType(
        publishedDataSets.toArray(PublishedDataSetDataType[]::new),
        connections.toArray(PubSubConnectionDataType[]::new),
        enabled,
        subscribedDataSets.toArray(StandaloneSubscribedDataSetDataType[]::new),
        dataSetClasses,
        defaultSecurityKeyServices,
        securityGroups.toArray(SecurityGroupDataType[]::new),
        // PubSubKeyPushTargets management unsupported: preserve none
        null,
        configurationVersion,
        properties.length == 0 ? null : properties);
  }

  // endregion

  // region small helpers

  private static <T> T elementAt(T @Nullable [] array, @Nullable UShort index) {
    if (array == null || index == null) {
      throw new ElementException(StatusCodes.Bad_InvalidArgument);
    }
    int i = index.intValue();
    if (i < 0 || i >= array.length) {
      throw new ElementException(StatusCodes.Bad_InvalidArgument);
    }
    T value = array[i];
    if (value == null) {
      throw new ElementException(StatusCodes.Bad_InvalidArgument);
    }
    return value;
  }

  private static String requireName(@Nullable String name) {
    if (name == null || name.isEmpty()) {
      throw new ElementException(StatusCodes.Bad_InvalidArgument);
    }
    return name;
  }

  private static <T> List<T> asList(T @Nullable [] array) {
    return array != null ? new ArrayList<>(Arrays.asList(array)) : new ArrayList<>();
  }

  private static String nullToEmpty(@Nullable String value) {
    return value != null ? value : "";
  }

  private static String connectionPath(String name) {
    return name;
  }

  private static String groupPath(String connection, String group) {
    return connection + "/" + group;
  }

  private static String writerReaderPath(String connection, String group, String leaf) {
    return connection + "/" + group + "/" + leaf;
  }

  private String publishedDataSetPath(String name) {
    return "PublishedDataSets/" + name;
  }

  private String subscribedDataSetPath(String name) {
    return "SubscribedDataSets/" + name;
  }

  private String securityGroupPath(String name) {
    return "SecurityGroups/" + name;
  }

  /**
   * Determine the operation from the mask, or {@code null} if it is not one of the five valid rows.
   */
  private static @Nullable Op resolveOp(PubSubConfigurationRefMask mask) {
    boolean add = mask.getElementAdd();
    boolean match = mask.getElementMatch();
    boolean modify = mask.getElementModify();
    boolean remove = mask.getElementRemove();

    if (add && !match && !modify && !remove) {
      return new Op(true, false, false, false);
    }
    if (match && !add && !modify && !remove) {
      return new Op(false, true, false, false);
    }
    if (add && match && !modify && !remove) {
      return new Op(true, true, false, false);
    }
    if (modify && !add && !match && !remove) {
      return new Op(false, false, true, false);
    }
    if (remove && !add && !match && !modify) {
      return new Op(false, false, false, true);
    }
    return null;
  }

  private static int referenceBitCount(PubSubConfigurationRefMask mask) {
    int count = 0;
    if (mask.getReferenceWriter()) count++;
    if (mask.getReferenceReader()) count++;
    if (mask.getReferenceWriterGroup()) count++;
    if (mask.getReferenceReaderGroup()) count++;
    if (mask.getReferenceConnection()) count++;
    if (mask.getReferencePubDataset()) count++;
    if (mask.getReferenceSubDataset()) count++;
    if (mask.getReferenceSecurityGroup()) count++;
    if (mask.getReferencePushTarget()) count++;
    return count;
  }

  /** Removes first (rank 0), then connections/top-level (1), groups (2), leaves (3). */
  private static int processingRank(@Nullable PubSubConfigurationRefMask mask) {
    if (mask == null) {
      return 4;
    }
    if (mask.getElementRemove()) {
      return 0;
    }
    if (mask.getReferenceConnection()
        || mask.getReferencePubDataset()
        || mask.getReferenceSubDataset()
        || mask.getReferenceSecurityGroup()
        || mask.getReferencePushTarget()) {
      return 1;
    }
    if (mask.getReferenceWriterGroup() || mask.getReferenceReaderGroup()) {
      return 2;
    }
    return 3;
  }

  // endregion

  private record Op(boolean add, boolean match, boolean modify, boolean remove) {}

  private static final class RefOutput {
    @Nullable PubSubConfigurationValueDataType value;
    @Nullable String objectPath;
  }

  /** Thrown internally to short-circuit a single element op to a Bad element result. */
  private static final class ElementException extends RuntimeException {
    final long statusCode;

    ElementException(long statusCode) {
      super(null, null, false, false);
      this.statusCode = statusCode;
    }
  }

  @FunctionalInterface
  private interface NameGetter<T> {
    @Nullable String name(T element);
  }
}
