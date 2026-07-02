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

import java.net.NetworkInterface;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.eclipse.milo.opcua.sdk.core.Reference;
import org.eclipse.milo.opcua.sdk.core.ValueRanks;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.ReconfigureResult;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfigFiles;
import org.eclipse.milo.opcua.sdk.server.AddressSpaceFilter;
import org.eclipse.milo.opcua.sdk.server.Lifecycle;
import org.eclipse.milo.opcua.sdk.server.ManagedAddressSpaceFragmentWithLifecycle;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.SessionListener;
import org.eclipse.milo.opcua.sdk.server.SimpleAddressSpaceFilter;
import org.eclipse.milo.opcua.sdk.server.items.DataItem;
import org.eclipse.milo.opcua.sdk.server.items.MonitoredItem;
import org.eclipse.milo.opcua.sdk.server.methods.AbstractMethodInvocationHandler.InvocationContext;
import org.eclipse.milo.opcua.sdk.server.methods.MethodInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.methods.Out;
import org.eclipse.milo.opcua.sdk.server.model.objects.FileType;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubConfigurationType;
import org.eclipse.milo.opcua.sdk.server.model.variables.PropertyTypeNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.sdk.server.util.SubscriptionModel;
import org.eclipse.milo.opcua.stack.core.NamespaceTable;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UByte;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetWriterDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationRefDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationValueDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConnectionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.WriterGroupDataType;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The opt-in remote-configuration face of {@link ServerPubSub} (WP-X, Phase 5 pin R1): implements
 * the {@code PublishSubscribe/PubSubConfiguration} FileType object ({@code i=25451}) — {@code
 * Open}/{@code Close}/{@code Read}/{@code Write}/{@code GetPosition}/{@code SetPosition} plus
 * {@code ReserveIds} and {@code CloseAndUpdate} — so a client can read and atomically update the
 * whole PubSub configuration through the normative Part 14 §9.1.3.7 file model.
 *
 * <p>Enabled by {@link ServerPubSubOptions.Builder#allowRemoteConfiguration}. On startup it binds
 * the eight handlers to the existing ns0 method nodes, creates the three missing optional
 * properties ({@code MimeType}, {@code MaxByteStringLength}, {@code LastModifiedTime}) in its own
 * node manager grafted under {@code i=25451}, initializes {@code Writable}/{@code UserWritable} to
 * {@code true} and {@code OpenCount}/{@code Size}/{@code ConfigurationVersion}, and registers a
 * {@link SessionListener} so file handles and id reservations are evicted when a session closes. On
 * shutdown it restores the ns0 method nodes to {@code Bad_NotImplemented} and unregisters.
 *
 * <p>Authorization (pin R9): every handler requires a session (session-less internal calls are
 * {@code Bad_UserAccessDenied}) and consults {@link PubSubMethodAuthorizer#checkConfigure};
 * SecurityGroup element references additionally require {@link
 * PubSubMethodAuthorizer#checkSksAdmin}. Persistence (pin R8): a successful {@code CloseAndUpdate}
 * saves through the configured {@link PubSubConfigurationStore} (a save failure is logged and
 * retried on the next mutation, and does not undo the applied change).
 */
final class RemoteConfigurationServer extends ManagedAddressSpaceFragmentWithLifecycle {

  private static final Logger LOGGER = LoggerFactory.getLogger(RemoteConfigurationServer.class);

  private static final String MIME_TYPE = "application/opcua+uabinary";
  private static final String NODE_ID_PREFIX = "PubSub";
  private static final Instant VERSION_TIME_EPOCH = Instant.parse("2000-01-01T00:00:00Z");

  private final OpcUaServer server;
  private final PubSubService service;
  private final @Nullable PubSubConfigurationStore store;
  private final PubSubMethodAuthorizer authorizer;
  private final RemoteConfigurationListener reconfigureListener;

  private final AddressSpaceFilter filter =
      SimpleAddressSpaceFilter.create(getNodeManager()::containsNode);
  private final SubscriptionModel subscriptionModel;

  private final UShort namespaceIndex;
  private final NamespaceTable namespaceTable;
  private final EncodingContext encodingContext;

  private final FileHandleManager fileHandleManager;
  private final ReserveIdRegistry reserveIdRegistry;
  private final SessionListener sessionListener;
  private final ULong defaultDatagramPublisherId;

  /**
   * Whether the information-model fragment is exposed. ConfigurationObjects NodeIds only resolve
   * when the fragment mints them (pin R4/R11: "the fragment's deterministic NodeIds or empty").
   */
  private final boolean exposeInformationModel;

  /**
   * The fragment-minted LastModifiedTime property node, updated on each successful CloseAndUpdate.
   */
  private @Nullable UaVariableNode lastModifiedTimeNode;

  /** The current configuration; the file's read snapshot and the CloseAndUpdate base. */
  private volatile PubSubConfig currentConfig;

  /**
   * The current PubSub ConfigurationVersion (VersionTime). Stamped into the materialized read file
   * and the ns0 ConfigurationVersion node so the §9.1.3.7.1 read-compare-write flow works; bumped
   * on every successful CloseAndUpdate and on programmatic reconfigures pushed in from {@link
   * ServerPubSub}.
   */
  private volatile UInteger currentVersionTime;

  RemoteConfigurationServer(
      OpcUaServer server,
      PubSubService service,
      PubSubConfig config,
      ServerPubSubOptions options,
      RemoteConfigurationListener reconfigureListener) {

    super(server);

    this.server = server;
    this.service = service;
    this.store = options.getConfigurationStore();
    this.authorizer = options.getMethodAuthorizer();
    this.reconfigureListener = reconfigureListener;
    this.currentConfig = config;
    this.exposeInformationModel = options.isExposeInformationModel();
    this.currentVersionTime = versionTimeNow();

    this.namespaceIndex = server.getServerNamespace().getNamespaceIndex();
    this.namespaceTable = server.getNamespaceTable();
    this.encodingContext = server.getStaticEncodingContext();

    this.subscriptionModel = new SubscriptionModel(server, this);
    getLifecycleManager().addLifecycle(subscriptionModel);

    this.defaultDatagramPublisherId = computeDefaultDatagramPublisherId();

    this.fileHandleManager =
        new FileHandleManager(
            FileHandleManager.DEFAULT_MAX_BYTE_STRING_LENGTH,
            this::materializeCurrentBytes,
            this::onOpenCountChanged);

    this.reserveIdRegistry =
        new ReserveIdRegistry(
            () -> currentConfig.toDataType(namespaceTable), defaultDatagramPublisherId);

    this.sessionListener =
        new SessionListener() {
          @Override
          public void onSessionClosed(Session session) {
            fileHandleManager.evictSession(session.getSessionId());
            reserveIdRegistry.evictSession(session.getSessionId());
          }
        };

    getLifecycleManager()
        .addLifecycle(
            new Lifecycle() {
              @Override
              public void startup() {
                createOptionalProperties();
                initializeProperties();
                attachHandlers();
                server.getSessionManager().addSessionListener(sessionListener);
              }

              @Override
              public void shutdown() {
                server.getSessionManager().removeSessionListener(sessionListener);
                detachHandlers();
              }
            });
  }

  @Override
  public AddressSpaceFilter getFilter() {
    return filter;
  }

  @Override
  public void onDataItemsCreated(List<DataItem> dataItems) {
    subscriptionModel.onDataItemsCreated(dataItems);
  }

  @Override
  public void onDataItemsModified(List<DataItem> dataItems) {
    subscriptionModel.onDataItemsModified(dataItems);
  }

  @Override
  public void onDataItemsDeleted(List<DataItem> dataItems) {
    subscriptionModel.onDataItemsDeleted(dataItems);
  }

  @Override
  public void onMonitoringModeChanged(List<MonitoredItem> monitoredItems) {
    subscriptionModel.onMonitoringModeChanged(monitoredItems);
  }

  // region node wiring

  /** Create the three optional FileType properties (not instantiated by the ns0 loader). */
  private void createOptionalProperties() {
    addPropertyNode("MimeType", NodeIds.String, ValueRanks.Scalar, new Variant(MIME_TYPE));
    addPropertyNode(
        "MaxByteStringLength",
        NodeIds.UInt32,
        ValueRanks.Scalar,
        new Variant(uint(FileHandleManager.DEFAULT_MAX_BYTE_STRING_LENGTH)));
    lastModifiedTimeNode =
        addPropertyNode(
            "LastModifiedTime", NodeIds.DateTime, ValueRanks.Scalar, new Variant(DateTime.now()));
  }

  private UaVariableNode addPropertyNode(
      String name, NodeId dataTypeId, int valueRank, Variant value) {
    var nodeId = new NodeId(namespaceIndex, NODE_ID_PREFIX + "/PubSubConfiguration/" + name);

    var node =
        new PropertyTypeNode(
            getNodeContext(),
            nodeId,
            new QualifiedName(0, name),
            LocalizedText.english(name),
            LocalizedText.NULL_VALUE,
            uint(0),
            uint(0),
            null,
            null,
            null,
            new DataValue(value),
            dataTypeId,
            valueRank,
            valueRank == ValueRanks.Scalar ? null : new UInteger[] {uint(0)});

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasTypeDefinition,
            NodeIds.PropertyType.expanded(),
            Reference.Direction.FORWARD));

    getNodeManager().addNode(node);

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasProperty,
            NodeIds.PublishSubscribe_PubSubConfiguration.expanded(),
            Reference.Direction.INVERSE));

    return node;
  }

  /** Initialize the mandatory FileType property values on the existing ns0 property nodes. */
  private void initializeProperties() {
    // remote configuration is enabled (this component only exists then): writable to any user;
    // per-user enforcement is via the authorizer, not these capability flags (pin R3)
    setNs0Value(NodeIds.PublishSubscribe_PubSubConfiguration_Writable, new Variant(true));
    setNs0Value(NodeIds.PublishSubscribe_PubSubConfiguration_UserWritable, new Variant(true));
    setNs0Value(NodeIds.PublishSubscribe_PubSubConfiguration_OpenCount, new Variant(ushort(0)));
    setNs0Value(
        NodeIds.PublishSubscribe_PubSubConfiguration_Size,
        new Variant(ulong(materializeCurrentBytes().length)));
    // publish the initial VersionTime (retire the mapper's uint(0) placeholder, pin R8) so it
    // agrees with the materialized read file's ConfigurationVersion
    setNs0Value(NodeIds.PublishSubscribe_ConfigurationVersion, new Variant(currentVersionTime));
  }

  private void attachHandlers() {
    setHandler(NodeIds.PublishSubscribe_PubSubConfiguration_Open, node -> new OpenMethodImpl(node));
    setHandler(
        NodeIds.PublishSubscribe_PubSubConfiguration_Close, node -> new CloseMethodImpl(node));
    setHandler(NodeIds.PublishSubscribe_PubSubConfiguration_Read, node -> new ReadMethodImpl(node));
    setHandler(
        NodeIds.PublishSubscribe_PubSubConfiguration_Write, node -> new WriteMethodImpl(node));
    setHandler(
        NodeIds.PublishSubscribe_PubSubConfiguration_GetPosition,
        node -> new GetPositionMethodImpl(node));
    setHandler(
        NodeIds.PublishSubscribe_PubSubConfiguration_SetPosition,
        node -> new SetPositionMethodImpl(node));
    setHandler(
        NodeIds.PublishSubscribe_PubSubConfiguration_ReserveIds,
        node -> new ReserveIdsMethodImpl(node));
    setHandler(
        NodeIds.PublishSubscribe_PubSubConfiguration_CloseAndUpdate,
        node -> new CloseAndUpdateMethodImpl(node));
  }

  private void detachHandlers() {
    for (NodeId methodId :
        List.of(
            NodeIds.PublishSubscribe_PubSubConfiguration_Open,
            NodeIds.PublishSubscribe_PubSubConfiguration_Close,
            NodeIds.PublishSubscribe_PubSubConfiguration_Read,
            NodeIds.PublishSubscribe_PubSubConfiguration_Write,
            NodeIds.PublishSubscribe_PubSubConfiguration_GetPosition,
            NodeIds.PublishSubscribe_PubSubConfiguration_SetPosition,
            NodeIds.PublishSubscribe_PubSubConfiguration_ReserveIds,
            NodeIds.PublishSubscribe_PubSubConfiguration_CloseAndUpdate)) {

      server
          .getAddressSpaceManager()
          .getManagedNode(methodId)
          .filter(UaMethodNode.class::isInstance)
          .map(UaMethodNode.class::cast)
          .ifPresent(node -> node.setInvocationHandler(MethodInvocationHandler.NOT_IMPLEMENTED));
    }
  }

  private void setHandler(NodeId methodId, HandlerFactory factory) {
    Optional<UaNode> node = server.getAddressSpaceManager().getManagedNode(methodId);
    if (node.orElse(null) instanceof UaMethodNode methodNode) {
      methodNode.setInvocationHandler(factory.apply(methodNode));
    } else {
      LOGGER.warn("ns0 PubSubConfiguration method node not found: {}", methodId);
    }
  }

  private void setNs0Value(NodeId nodeId, Variant value) {
    server
        .getAddressSpaceManager()
        .getManagedNode(nodeId)
        .filter(UaVariableNode.class::isInstance)
        .map(UaVariableNode.class::cast)
        .ifPresent(node -> node.setValue(new DataValue(value)));
  }

  private void onOpenCountChanged(int openCount) {
    setNs0Value(
        NodeIds.PublishSubscribe_PubSubConfiguration_OpenCount, new Variant(ushort(openCount)));
  }

  // endregion

  // region delegates called by the method handlers

  private byte[] materializeCurrentBytes() {
    // stamp the current VersionTime into the read file body so a client can compare the file's
    // ConfigurationVersion against the ns0 node before writing (§9.1.3.7.1); the mapper otherwise
    // emits ConfigurationVersion as 0
    PubSubConfiguration2DataType dataType =
        withVersion(currentConfig.toDataType(namespaceTable), currentVersionTime);
    return PubSubConfigFiles.write(dataType, encodingContext);
  }

  private static PubSubConfiguration2DataType withVersion(
      PubSubConfiguration2DataType dataType, UInteger configurationVersion) {
    return new PubSubConfiguration2DataType(
        dataType.getPublishedDataSets(),
        dataType.getConnections(),
        dataType.getEnabled(),
        dataType.getSubscribedDataSets(),
        dataType.getDataSetClasses(),
        dataType.getDefaultSecurityKeyServices(),
        dataType.getSecurityGroups(),
        dataType.getPubSubKeyPushTargets(),
        configurationVersion,
        dataType.getConfigurationProperties());
  }

  /** Extract the session for a client call, or reject internal/unauthorized calls (pin R9). */
  private Session requireConfigureSession(InvocationContext context) throws UaException {
    Session session = context.getSession().orElse(null);
    if (session == null) {
      // the file model is a client-driven surface; there is no privileged internal path
      throw new UaException(StatusCodes.Bad_UserAccessDenied, "no session");
    }
    if (authorizer.checkConfigure(session) != PubSubMethodAuthorizer.Decision.ALLOW) {
      throw new UaException(StatusCodes.Bad_UserAccessDenied);
    }
    return session;
  }

  private void reserveIds(
      InvocationContext context,
      String transportProfileUri,
      UShort numWriterGroupIds,
      UShort numDataSetWriterIds,
      Out<Object> defaultPublisherId,
      Out<UShort[]> writerGroupIds,
      Out<UShort[]> dataSetWriterIds)
      throws UaException {

    Session session = requireConfigureSession(context);

    ReserveIdRegistry.Reservation reservation =
        reserveIdRegistry.reserve(
            session.getSessionId(),
            transportProfileUri,
            numWriterGroupIds != null ? numWriterGroupIds.intValue() : 0,
            numDataSetWriterIds != null ? numDataSetWriterIds.intValue() : 0);

    defaultPublisherId.set(reservation.defaultPublisherId());
    writerGroupIds.set(reservation.writerGroupIds());
    dataSetWriterIds.set(reservation.dataSetWriterIds());
  }

  private synchronized void closeAndUpdate(
      InvocationContext context,
      UInteger fileHandle,
      Boolean requireCompleteUpdate,
      PubSubConfigurationRefDataType[] references,
      Out<Boolean> changesApplied,
      Out<StatusCode[]> referencesResults,
      Out<PubSubConfigurationValueDataType[]> configurationValues,
      Out<NodeId[]> configurationObjects)
      throws UaException {

    Session session = requireConfigureSession(context);
    boolean sksAdminAllowed =
        authorizer.checkSksAdmin(session) == PubSubMethodAuthorizer.Decision.ALLOW;

    // validate the handle + write mode and close the file (CloseAndUpdate always closes)
    byte[] fileBytes = fileHandleManager.closeForUpdate(session.getSessionId(), fileHandle);

    if (references == null || references.length == 0) {
      throw new UaException(StatusCodes.Bad_NothingToDo, "ConfigurationReferences is empty");
    }

    // decode the written file; a bad body is Bad_TypeMismatch
    PubSubConfiguration2DataType fileConfig = PubSubConfigFiles.read(fileBytes, encodingContext);

    PubSubConfiguration2DataType currentDataType = currentConfig.toDataType(namespaceTable);

    Set<Integer> usedWriterGroupIds = new HashSet<>(reserveIdRegistry.allReservedWriterGroupIds());
    Set<Integer> usedDataSetWriterIds =
        new HashSet<>(reserveIdRegistry.allReservedDataSetWriterIds());
    collectConfigIds(currentDataType, usedWriterGroupIds, usedDataSetWriterIds);

    UInteger versionTime = versionTimeNow();

    var applier =
        new RemoteConfigurationApplier(
            currentDataType,
            fileConfig,
            sksAdminAllowed,
            defaultDatagramPublisherId,
            usedWriterGroupIds,
            usedDataSetWriterIds);

    RemoteConfigurationApplier.Result result = applier.apply(references, versionTime);

    // pin R4: atomic mode applies only if every ref succeeded; partial mode applies survivors
    boolean apply =
        Boolean.TRUE.equals(requireCompleteUpdate) ? result.allGood() : result.anyGood();

    boolean applied = false;
    if (apply) {
      // whole-config validity (id uniqueness, publisher ids, ...) is enforced here; a failure
      // surfaces as the method-level status and leaves the live configuration unchanged
      PubSubConfig newConfig = PubSubConfig.fromDataType(result.candidate(), namespaceTable);
      ReconfigureResult reconfigureResult =
          service.reconfigure(newConfig, PubSubService.ReconfigureMode.DISABLE_AFFECTED);

      currentConfig = newConfig;
      currentVersionTime = versionTime;
      applied = true;

      reserveIdRegistry.releaseUsed(session.getSessionId(), result.candidate());
      persist(newConfig);
      setNs0Value(NodeIds.PublishSubscribe_ConfigurationVersion, new Variant(versionTime));
      setNs0Value(
          NodeIds.PublishSubscribe_PubSubConfiguration_Size,
          new Variant(ulong(materializeCurrentBytes().length)));
      if (lastModifiedTimeNode != null) {
        lastModifiedTimeNode.setValue(new DataValue(new Variant(DateTime.now())));
      }

      try {
        reconfigureListener.onReconfigured(newConfig, reconfigureResult);
      } catch (Exception e) {
        LOGGER.warn("reconfigure listener failed", e);
      }
    }

    changesApplied.set(applied);
    referencesResults.set(result.referencesResults());
    configurationValues.set(result.configurationValues());
    configurationObjects.set(toConfigurationObjects(result.objectPaths()));
  }

  /**
   * Map the applier's name paths to deterministic ns-app NodeIds (pin R11); empty path → NULL.
   *
   * <p>Only the exposed {@link PubSubInfoModelFragment} mints these {@code PubSub/<path>} Objects,
   * so when the information model is not exposed the array is empty — a client browsing a returned
   * NodeId would otherwise get {@code Bad_NodeIdUnknown} (§9.1.3.7.6: "If the Server does not
   * support the creation of NodeIds, the array is null or empty").
   */
  private NodeId[] toConfigurationObjects(String[] objectPaths) {
    if (!exposeInformationModel) {
      return new NodeId[0];
    }
    var objects = new NodeId[objectPaths.length];
    for (int i = 0; i < objectPaths.length; i++) {
      objects[i] =
          objectPaths[i].isEmpty()
              ? NodeId.NULL_VALUE
              : new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + objectPaths[i]);
    }
    return objects;
  }

  /**
   * Adopt a configuration applied out-of-band by {@link ServerPubSub#reconfigure} so the file
   * model, its VersionTime, and the {@code Size}/{@code ConfigurationVersion}/{@code
   * LastModifiedTime} nodes track the live configuration. Without this the read file and the
   * CloseAndUpdate base would remain the last file-model value and a subsequent CloseAndUpdate
   * would silently revert the programmatic change.
   *
   * <p>Synchronized against {@link #closeAndUpdate} so the two mutation paths cannot interleave.
   */
  synchronized void onExternalReconfigure(PubSubConfig newConfig) {
    currentConfig = newConfig;
    currentVersionTime = versionTimeNow();
    setNs0Value(NodeIds.PublishSubscribe_ConfigurationVersion, new Variant(currentVersionTime));
    setNs0Value(
        NodeIds.PublishSubscribe_PubSubConfiguration_Size,
        new Variant(ulong(materializeCurrentBytes().length)));
    if (lastModifiedTimeNode != null) {
      lastModifiedTimeNode.setValue(new DataValue(new Variant(DateTime.now())));
    }
  }

  /** Persist the applied configuration (pin R8); a failure is logged and retried next mutation. */
  private void persist(PubSubConfig config) {
    if (store == null) {
      return;
    }
    try {
      store.save(config.toDataType(namespaceTable));
    } catch (Exception e) {
      // pin R8: a save failure does not undo the applied change; the next successful mutation
      // re-runs persist() and thus retries the save
      LOGGER.warn("Error saving configuration after CloseAndUpdate; will retry next mutation", e);
    }
  }

  // endregion

  private static void collectConfigIds(
      PubSubConfiguration2DataType config,
      Set<Integer> writerGroupIds,
      Set<Integer> dataSetWriterIds) {

    PubSubConnectionDataType[] connections = config.getConnections();
    if (connections == null) {
      return;
    }
    for (PubSubConnectionDataType connection : connections) {
      if (connection == null || connection.getWriterGroups() == null) {
        continue;
      }
      for (WriterGroupDataType group : connection.getWriterGroups()) {
        if (group == null) {
          continue;
        }
        if (group.getWriterGroupId() != null) {
          writerGroupIds.add(group.getWriterGroupId().intValue());
        }
        if (group.getDataSetWriters() != null) {
          for (DataSetWriterDataType writer : group.getDataSetWriters()) {
            if (writer != null && writer.getDataSetWriterId() != null) {
              dataSetWriterIds.add(writer.getDataSetWriterId().intValue());
            }
          }
        }
      }
    }
  }

  private UInteger versionTimeNow() {
    long seconds = Instant.now().getEpochSecond() - VERSION_TIME_EPOCH.getEpochSecond();
    return uint(seconds & 0xFFFFFFFFL);
  }

  private ULong computeDefaultDatagramPublisherId() {
    try {
      var interfaces = NetworkInterface.getNetworkInterfaces();
      while (interfaces != null && interfaces.hasMoreElements()) {
        NetworkInterface ni = interfaces.nextElement();
        byte[] mac = ni.getHardwareAddress();
        if (mac != null && mac.length == 6) {
          long value = 0L;
          for (byte b : mac) {
            value = (value << 8) | (b & 0xFFL);
          }
          // shift the 6-byte MAC into the high bytes, leaving the low 2 bytes for the port (0)
          value = value << 16;
          return ulong(value != 0 ? value : 1L);
        }
      }
    } catch (Exception e) {
      LOGGER.debug("could not derive a MAC-based default PublisherId", e);
    }
    return ulong(1L);
  }

  @FunctionalInterface
  private interface HandlerFactory {
    MethodInvocationHandler apply(UaMethodNode node);
  }

  // region method handlers (bound to the ns0 PubSubConfiguration method nodes)

  private final class OpenMethodImpl extends FileType.OpenMethod {
    OpenMethodImpl(UaMethodNode node) {
      super(node);
    }

    @Override
    protected void invoke(InvocationContext context, UByte mode, Out<UInteger> fileHandle)
        throws UaException {
      Session session = requireConfigureSession(context);
      fileHandle.set(fileHandleManager.open(session.getSessionId(), mode));
    }
  }

  private final class CloseMethodImpl extends FileType.CloseMethod {
    CloseMethodImpl(UaMethodNode node) {
      super(node);
    }

    @Override
    protected void invoke(InvocationContext context, UInteger fileHandle) throws UaException {
      Session session = requireConfigureSession(context);
      fileHandleManager.close(session.getSessionId(), fileHandle);
    }
  }

  private final class ReadMethodImpl extends FileType.ReadMethod {
    ReadMethodImpl(UaMethodNode node) {
      super(node);
    }

    @Override
    protected void invoke(
        InvocationContext context, UInteger fileHandle, Integer length, Out<ByteString> data)
        throws UaException {
      Session session = requireConfigureSession(context);
      data.set(fileHandleManager.read(session.getSessionId(), fileHandle, length));
    }
  }

  private final class WriteMethodImpl extends FileType.WriteMethod {
    WriteMethodImpl(UaMethodNode node) {
      super(node);
    }

    @Override
    protected void invoke(InvocationContext context, UInteger fileHandle, ByteString data)
        throws UaException {
      Session session = requireConfigureSession(context);
      fileHandleManager.write(session.getSessionId(), fileHandle, data);
    }
  }

  private final class GetPositionMethodImpl extends FileType.GetPositionMethod {
    GetPositionMethodImpl(UaMethodNode node) {
      super(node);
    }

    @Override
    protected void invoke(InvocationContext context, UInteger fileHandle, Out<ULong> position)
        throws UaException {
      Session session = requireConfigureSession(context);
      position.set(fileHandleManager.getPosition(session.getSessionId(), fileHandle));
    }
  }

  private final class SetPositionMethodImpl extends FileType.SetPositionMethod {
    SetPositionMethodImpl(UaMethodNode node) {
      super(node);
    }

    @Override
    protected void invoke(InvocationContext context, UInteger fileHandle, ULong position)
        throws UaException {
      Session session = requireConfigureSession(context);
      fileHandleManager.setPosition(session.getSessionId(), fileHandle, position);
    }
  }

  private final class ReserveIdsMethodImpl extends PubSubConfigurationType.ReserveIdsMethod {
    ReserveIdsMethodImpl(UaMethodNode node) {
      super(node);
    }

    @Override
    protected void invoke(
        InvocationContext context,
        String transportProfileUri,
        UShort numReqWriterGroupIds,
        UShort numReqDataSetWriterIds,
        Out<Object> defaultPublisherId,
        Out<UShort[]> writerGroupIds,
        Out<UShort[]> dataSetWriterIds)
        throws UaException {
      reserveIds(
          context,
          transportProfileUri,
          numReqWriterGroupIds,
          numReqDataSetWriterIds,
          defaultPublisherId,
          writerGroupIds,
          dataSetWriterIds);
    }
  }

  private final class CloseAndUpdateMethodImpl
      extends PubSubConfigurationType.CloseAndUpdateMethod {
    CloseAndUpdateMethodImpl(UaMethodNode node) {
      super(node);
    }

    @Override
    protected void invoke(
        InvocationContext context,
        UInteger fileHandle,
        Boolean requireCompleteUpdate,
        PubSubConfigurationRefDataType[] configurationReferences,
        Out<Boolean> changesApplied,
        Out<StatusCode[]> referencesResults,
        Out<PubSubConfigurationValueDataType[]> configurationValues,
        Out<NodeId[]> configurationObjects)
        throws UaException {
      closeAndUpdate(
          context,
          fileHandle,
          requireCompleteUpdate,
          configurationReferences,
          changesApplied,
          referencesResults,
          configurationValues,
          configurationObjects);
    }
  }

  // endregion
}
