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
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;

import java.net.InetAddress;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.function.IntSupplier;
import java.util.function.Supplier;
import org.eclipse.milo.opcua.sdk.core.Reference;
import org.eclipse.milo.opcua.sdk.core.ValueRanks;
import org.eclipse.milo.opcua.sdk.core.nodes.VariableNode;
import org.eclipse.milo.opcua.sdk.pubsub.ComponentType;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.ComponentDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.Counter;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubHandle;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.transport.udp.UdpTransportProvider;
import org.eclipse.milo.opcua.sdk.server.AddressSpaceFilter;
import org.eclipse.milo.opcua.sdk.server.Lifecycle;
import org.eclipse.milo.opcua.sdk.server.ManagedAddressSpaceFragmentWithLifecycle;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.SimpleAddressSpaceFilter;
import org.eclipse.milo.opcua.sdk.server.items.DataItem;
import org.eclipse.milo.opcua.sdk.server.items.MonitoredItem;
import org.eclipse.milo.opcua.sdk.server.methods.AbstractMethodInvocationHandler.InvocationContext;
import org.eclipse.milo.opcua.sdk.server.methods.MethodInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.model.objects.BaseObjectTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.DataSetReaderTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.DataSetWriterTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.NetworkAddressUrlTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubConnectionTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubDiagnosticsConnectionTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubDiagnosticsDataSetReaderTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubDiagnosticsDataSetWriterTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubDiagnosticsReaderGroupTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubDiagnosticsType;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubDiagnosticsWriterGroupTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubStatusType;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubStatusTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PublishSubscribeType;
import org.eclipse.milo.opcua.sdk.server.model.objects.PublishedDataItemsTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.ReaderGroupTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.SubscribedDataSetTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.TargetVariablesTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.UadpDataSetReaderMessageTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.UadpDataSetWriterMessageTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.UadpWriterGroupMessageTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.WriterGroupTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.variables.BaseDataVariableTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.variables.PropertyTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.variables.PubSubDiagnosticsCounterTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.variables.SelectionListTypeNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaNodeContext;
import org.eclipse.milo.opcua.sdk.server.nodes.UaObjectNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.sdk.server.nodes.filters.AttributeFilter;
import org.eclipse.milo.opcua.sdk.server.nodes.filters.AttributeFilters;
import org.eclipse.milo.opcua.sdk.server.util.SubscriptionModel;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.DiagnosticsLevel;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubDiagnosticsCounterClassification;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.eclipse.milo.opcua.stack.core.types.structured.AccessRestrictionType;
import org.eclipse.milo.opcua.stack.core.types.structured.ConfigurationVersionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetMetaDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetReaderDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetWriterDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.FieldTargetDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.KeyValuePair;
import org.eclipse.milo.opcua.stack.core.types.structured.NetworkAddressDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.NetworkAddressUrlDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConnectionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubGroupDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PublishedDataItemsDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PublishedDataSetDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PublishedVariableDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.ReaderGroupDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.RolePermissionType;
import org.eclipse.milo.opcua.stack.core.types.structured.TargetVariablesDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetReaderMessageDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetWriterMessageDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpWriterGroupMessageDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.WriterGroupDataType;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exposes the read-only PublishSubscribe information model for an attached PubSub runtime:
 * populates and animates the ns0 PublishSubscribe subtree and grafts connection, group, writer,
 * reader, and published-dataset objects reflecting the attach-time configuration.
 *
 * <p>The fragment is a {@link ManagedAddressSpaceFragmentWithLifecycle} with its own {@code
 * UaNodeManager} and {@link SubscriptionModel}, registered with the server's {@code
 * AddressSpaceManager} on startup and unregistered on shutdown. References grafting the new
 * subtrees onto ns0 nodes (PublishSubscribe {@code i=14443} via HasPubSubConnection, the
 * PublishedDataSets folder {@code i=17371} via HasComponent) are stored, with their inverses, in
 * this fragment's node manager only; ns0's node manager is never structurally modified.
 *
 * <p>Node identity: every node created by this fragment has a deterministic string {@link NodeId}
 * in the server application namespace, {@code "PubSub/<connection>[/<group>[/<writer|reader>]]"}
 * for runtime components and {@code "PubSub/PublishedDataSets/<name>"} for published datasets, with
 * member children appended as further {@code "/"}-separated segments (e.g. {@code
 * "PubSub/conn/Status/State"}). The ids are stable across server restarts for an unchanged
 * configuration.
 *
 * <p>All variables are read-only ({@code AccessLevel.CurrentRead}, the {@code UaVariableNode}
 * default) and no method nodes are created. Pre-existing ns0 method nodes (AddConnection,
 * RemoveConnection, the SKS methods, ...) and unbacked optional ns0 components (Diagnostics,
 * PubSubConfiguration, PubSubCapablities, ...) are left exactly as the ns0 loader created them.
 * PublishedDataSet nodes carry no Status child (Part 14 defines none); published-dataset runtime
 * state is not surfaced.
 *
 * <p>Values are populated from the attach-time {@link PubSubConfig}, normalized through {@code
 * PubSubConfig.toDataType} so defaults, transport profile URIs, and derived DataSetMetaData match
 * what the runtime publishes. Existing ns0 children of PublishSubscribe (Status/State {@code
 * i=17406}, SupportedTransportProfiles {@code i=17481}, ConfigurationVersion, and
 * ConfigurationProperties) are populated by looking up the existing nodes and setting values only;
 * property create-on-set against ns0 parents is never triggered.
 *
 * <p>Live state: component Status/State variables are updated from {@link
 * PubSubService#addStateListener}, keyed by component name path so that reconfiguration (which
 * invalidates handles) does not break tracking; reader DataSetMetaData values are updated from
 * {@link PubSubService#addMetaDataListener}.
 *
 * <p>Config-derived rebuild: {@link #onConfigurationApplied(PubSubConfig)} reconciles the
 * config-derived subtrees against a newly applied configuration, keyed by component name path, so a
 * reconfigure no longer desyncs the model from the configuration. It is invoked after a remote
 * {@code CloseAndUpdate} (via the {@link RemoteConfigurationListener} hand-off {@link ServerPubSub}
 * wires in) and after {@link ServerPubSub#reconfigure}. Reconciliation is incremental at connection
 * and top-level (PublishedDataSet) granularity: only connections and datasets whose normalized
 * configuration differs (or that reference a changed dataset) are torn down and rebuilt, leaving
 * unaffected subtrees — and any client subscriptions to them — untouched. A bare {@code
 * ServerPubSub.runtime()} reconfigure still bypasses this hook (there is no engine-level
 * reconfigure notification): callers that need the model kept in sync should reconfigure through
 * {@link ServerPubSub#reconfigure} or the remote-configuration file model.
 *
 * <p>Enable/Disable (§9.1.10): when remote configuration is enabled ({@link
 * ServerPubSubOptions#isAllowRemoteConfiguration()}), each config-derived Status object also
 * carries callable {@code Enable} and {@code Disable} methods that delegate to {@link
 * PubSubService#enable} / {@link PubSubService#disable} for the component, after consulting {@link
 * PubSubMethodAuthorizer#checkConfigure}. They enforce the §9.1.10 current-state rules ({@code
 * Bad_InvalidState} when Enable is called on a non-Disabled component or Disable on a Disabled one)
 * and are not configuration mutations (no store save). When remote configuration is off the Status
 * objects stay read-only (State variable only), preserving the read-only posture.
 *
 * <p>Created by {@link ServerPubSub} when {@link ServerPubSubOptions#isExposeInformationModel()} is
 * {@code true}; {@link #startup()} and {@link #shutdown()} are driven by the owning {@link
 * ServerPubSub}'s lifecycle.
 */
final class PubSubInfoModelFragment extends ManagedAddressSpaceFragmentWithLifecycle {

  private static final Logger LOGGER = LoggerFactory.getLogger(PubSubInfoModelFragment.class);

  /** Prefix shared by every NodeId identifier minted by this fragment. */
  private static final String NODE_ID_PREFIX = "PubSub";

  /** The epoch of the OPC UA VersionTime data type: 2000-01-01T00:00:00 UTC. */
  private static final Instant VERSION_TIME_EPOCH = Instant.parse("2000-01-01T00:00:00Z");

  private final AddressSpaceFilter filter =
      SimpleAddressSpaceFilter.create(getNodeManager()::containsNode);

  private final SubscriptionModel subscriptionModel;

  /**
   * Status/State variable nodes, keyed by component name path, e.g. {@code "conn/group/writer"}.
   */
  private final Map<String, UaVariableNode> stateVariables = new ConcurrentHashMap<>();

  /** Reader DataSetMetaData property nodes, keyed by reader name path. */
  private final Map<String, UaVariableNode> metaDataVariables = new ConcurrentHashMap<>();

  /**
   * Last-received DataSetMessage sequence number per DataSetReader name path, backing the Optional
   * §9.1.11.12 {@code MessageSequenceNumber} LiveValue. An entry exists only while the reader's
   * diagnostics node is built; it is fed from {@link PubSubService#addDataSetListener} deliveries
   * and read at browse time. UInt16 to match Table 331 — the public event spans UInt32 for the JSON
   * mapping, so a value is truncated to its low 16 bits, matching the UADP GroupHeader width.
   */
  private final Map<String, UShort> lastReaderMessageSeq = new ConcurrentHashMap<>();

  /**
   * Guards listener callbacks; set on startup, cleared on shutdown. Listeners cannot be removed.
   */
  private volatile boolean active = false;

  private final PubSubConfig config;
  private final PubSubService service;
  private final UShort namespaceIndex;

  /** Authorizes Enable/Disable calls; reused from the message-security SPI. */
  private final PubSubMethodAuthorizer authorizer;

  /**
   * Whether the config-derived Status objects host callable Enable/Disable methods. Gated on {@link
   * ServerPubSubOptions#isAllowRemoteConfiguration()} so the read-only exposure stays read-only.
   */
  private final boolean enableDisableSupported;

  /**
   * Whether the §9.1.11 diagnostics model is exposed. Gated on {@link
   * ServerPubSubOptions#isDiagnosticsEnabled()}; when {@code false} the ns0 Diagnostics ({@code
   * i=17409}) and PubSubCapabilities ({@code i=23678}) skeletons are left exactly as the loader
   * created them and no per-component Diagnostics objects are minted. Diagnostics requires the
   * information model to be exposed (this fragment only exists when {@link
   * ServerPubSubOptions#isExposeInformationModel()}), so both flags must be set to expose it.
   */
  private final boolean diagnosticsEnabled;

  /** Whether the server hosts the SKS pull face ({@code SupportSecurityKeyServer}). */
  private final boolean sksServerEnabled;

  /**
   * Cleanup actions for the ns0 diagnostics exposure — getValue-filter removals and the {@code
   * Reset} method-handler restore — run on shutdown so the ns0 skeleton is left inert. Only touched
   * on startup and shutdown, which {@link ServerPubSub} serializes.
   */
  private final List<Runnable> ns0DiagnosticsCleanup = new ArrayList<>();

  /**
   * DataSet {@code ConfigurationVersion} by PublishedDataSet name for the configuration currently
   * being built; consulted by {@link #buildDataSetWriterNodes} to back a writer diagnostics
   * MajorVersion/MinorVersion. Set at the start of each build pass ({@link #buildNodes} / {@link
   * #onConfigurationApplied}), which run single-threaded.
   */
  private Map<String, ConfigurationVersionDataType> dataSetVersionsByName = Map.of();

  /**
   * Serializes {@link #onConfigurationApplied(PubSubConfig)} and guards {@link
   * #builtConfiguration}.
   */
  private final Object rebuildLock = new Object();

  /**
   * The last-built normalized configuration; the baseline the rebuild diffs against. Null until the
   * fragment has started and built its initial nodes.
   */
  private volatile @Nullable PubSubConfiguration2DataType builtConfiguration;

  PubSubInfoModelFragment(
      OpcUaServer server, PubSubConfig config, PubSubService service, ServerPubSubOptions options) {

    super(server);

    this.config = config;
    this.service = service;
    this.authorizer = options.getMethodAuthorizer();
    this.enableDisableSupported = options.isAllowRemoteConfiguration();
    this.diagnosticsEnabled = options.isDiagnosticsEnabled();
    this.sksServerEnabled = options.isSksServerEnabled();

    namespaceIndex = server.getServerNamespace().getNamespaceIndex();

    subscriptionModel = new SubscriptionModel(server, this);
    getLifecycleManager().addLifecycle(subscriptionModel);

    getLifecycleManager()
        .addLifecycle(
            new Lifecycle() {
              @Override
              public void startup() {
                PubSubConfiguration2DataType configuration =
                    config.toDataType(getServer().getNamespaceTable());

                buildNodes(configuration);
                populateExistingNs0Nodes(configuration);

                builtConfiguration = configuration;
                active = true;
                if (diagnosticsEnabled) {
                  exposeNs0Diagnostics();
                }
                registerListeners();
              }

              @Override
              public void shutdown() {
                active = false;
                teardownNs0Diagnostics();
                setRootState(PubSubState.Disabled);
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

  // region node construction

  private void buildNodes(PubSubConfiguration2DataType configuration) {
    dataSetVersionsByName = dataSetVersions(configuration);

    var dataSetNodeIds = new HashMap<String, NodeId>();

    PublishedDataSetDataType[] publishedDataSets =
        orEmpty(configuration.getPublishedDataSets(), PublishedDataSetDataType[]::new);

    for (PublishedDataSetDataType dataSet : publishedDataSets) {
      NodeId nodeId = buildPublishedDataSetNodes(dataSet);
      if (dataSet.getName() != null) {
        dataSetNodeIds.put(dataSet.getName(), nodeId);
      }
    }

    PubSubConnectionDataType[] connections =
        orEmpty(configuration.getConnections(), PubSubConnectionDataType[]::new);

    for (PubSubConnectionDataType connection : connections) {
      buildConnectionNodes(connection, dataSetNodeIds);
    }
  }

  private NodeId buildPublishedDataSetNodes(PublishedDataSetDataType dataSet) {
    String name = nullToEmpty(dataSet.getName());

    var nodeId = new NodeId(namespaceIndex, NODE_ID_PREFIX + "/PublishedDataSets/" + name);

    PublishedDataItemsTypeNode node =
        addObjectNode(
            PublishedDataItemsTypeNode::new,
            nodeId,
            new QualifiedName(namespaceIndex, name),
            NodeIds.PublishedDataItemsType,
            NodeIds.HasComponent,
            NodeIds.PublishSubscribe_PublishedDataSets);

    DataSetMetaDataType metaData = dataSet.getDataSetMetaData();

    addPropertyNode(
        node,
        "ConfigurationVersion",
        NodeIds.ConfigurationVersionDataType,
        ValueRanks.Scalar,
        new Variant(metaData != null ? metaData.getConfigurationVersion() : null));

    addPropertyNode(
        node,
        "DataSetMetaData",
        NodeIds.DataSetMetaDataType,
        ValueRanks.Scalar,
        new Variant(metaData));

    PublishedVariableDataType[] publishedData =
        dataSet.getDataSetSource() instanceof PublishedDataItemsDataType items
            ? orEmpty(items.getPublishedData(), PublishedVariableDataType[]::new)
            : new PublishedVariableDataType[0];

    addPropertyNode(
        node,
        "PublishedData",
        NodeIds.PublishedVariableDataType,
        ValueRanks.OneDimension,
        new Variant(publishedData));

    UUID dataSetClassId = metaData != null ? metaData.getDataSetClassId() : null;
    if (dataSetClassId != null
        && (dataSetClassId.getMostSignificantBits() != 0L
            || dataSetClassId.getLeastSignificantBits() != 0L)) {

      addPropertyNode(
          node, "DataSetClassId", NodeIds.Guid, ValueRanks.Scalar, new Variant(dataSetClassId));
    }

    return nodeId;
  }

  private void buildConnectionNodes(
      PubSubConnectionDataType connection, Map<String, NodeId> dataSetNodeIds) {

    String name = nullToEmpty(connection.getName());

    var nodeId = new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + name);

    PubSubConnectionTypeNode node =
        addObjectNode(
            PubSubConnectionTypeNode::new,
            nodeId,
            new QualifiedName(namespaceIndex, name),
            NodeIds.PubSubConnectionType,
            NodeIds.HasPubSubConnection,
            NodeIds.PublishSubscribe);

    Variant publisherId =
        connection.getPublisherId() != null ? connection.getPublisherId() : Variant.NULL_VALUE;

    addPropertyNode(node, "PublisherId", NodeIds.BaseDataType, ValueRanks.Scalar, publisherId);

    addSelectionListNode(
        node,
        "TransportProfileUri",
        connection.getTransportProfileUri(),
        new String[] {UdpTransportProvider.TRANSPORT_PROFILE_URI});

    addPropertyNode(
        node,
        "ConnectionProperties",
        NodeIds.KeyValuePair,
        ValueRanks.OneDimension,
        new Variant(orEmpty(connection.getConnectionProperties(), KeyValuePair[]::new)));

    buildAddressNodes(node, connection.getAddress());

    addStatusNodes(node, name, () -> service.components().connection(name));

    if (diagnosticsEnabled) {
      BaseObjectTypeNode liveValues =
          buildComponentDiagnostics(node, name, DiagnosticsKind.CONNECTION);
      // ResolvedAddress: best-effort at exposure time; a documented approximation
      addVariableNode(
          liveValues, "ResolvedAddress", NodeIds.String, new Variant(resolveAddress(connection)));
    }

    WriterGroupDataType[] writerGroups =
        orEmpty(connection.getWriterGroups(), WriterGroupDataType[]::new);

    for (WriterGroupDataType group : writerGroups) {
      buildWriterGroupNodes(node, name, group, dataSetNodeIds);
    }

    ReaderGroupDataType[] readerGroups =
        orEmpty(connection.getReaderGroups(), ReaderGroupDataType[]::new);

    for (ReaderGroupDataType group : readerGroups) {
      buildReaderGroupNodes(node, name, group);
    }
  }

  /**
   * Build the Mandatory Address child as a concrete NetworkAddressUrlType instance with Url and
   * NetworkInterface variables (the declared NetworkAddressType is abstract and has no Url).
   */
  private void buildAddressNodes(
      PubSubConnectionTypeNode connectionNode, @Nullable NetworkAddressDataType address) {

    NetworkAddressUrlTypeNode addressNode =
        addObjectNode(
            NetworkAddressUrlTypeNode::new,
            childNodeId(connectionNode, "Address"),
            new QualifiedName(0, "Address"),
            NodeIds.NetworkAddressUrlType,
            NodeIds.HasComponent,
            connectionNode.getNodeId());

    String networkInterface = address != null ? nullToEmpty(address.getNetworkInterface()) : "";

    addSelectionListNode(addressNode, "NetworkInterface", networkInterface, new String[0]);

    String url =
        address instanceof NetworkAddressUrlDataType urlAddress ? urlAddress.getUrl() : null;

    addVariableNode(addressNode, "Url", NodeIds.String, new Variant(url));
  }

  private void buildWriterGroupNodes(
      PubSubConnectionTypeNode connectionNode,
      String connectionName,
      WriterGroupDataType group,
      Map<String, NodeId> dataSetNodeIds) {

    String name = nullToEmpty(group.getName());
    String path = connectionName + "/" + name;

    var nodeId = new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + path);

    WriterGroupTypeNode node =
        addObjectNode(
            WriterGroupTypeNode::new,
            nodeId,
            new QualifiedName(namespaceIndex, name),
            NodeIds.WriterGroupType,
            NodeIds.HasWriterGroup,
            connectionNode.getNodeId());

    addGroupPropertyNodes(node, group);

    addPropertyNode(
        node,
        "WriterGroupId",
        NodeIds.UInt16,
        ValueRanks.Scalar,
        new Variant(group.getWriterGroupId()));

    addPropertyNode(
        node,
        "PublishingInterval",
        NodeIds.Duration,
        ValueRanks.Scalar,
        new Variant(group.getPublishingInterval()));

    addPropertyNode(
        node,
        "KeepAliveTime",
        NodeIds.Duration,
        ValueRanks.Scalar,
        new Variant(group.getKeepAliveTime()));

    addPropertyNode(
        node, "Priority", NodeIds.Byte, ValueRanks.Scalar, new Variant(group.getPriority()));

    addPropertyNode(
        node,
        "LocaleIds",
        NodeIds.LocaleId,
        ValueRanks.OneDimension,
        new Variant(orEmpty(group.getLocaleIds(), String[]::new)));

    addPropertyNode(
        node,
        "HeaderLayoutUri",
        NodeIds.String,
        ValueRanks.Scalar,
        new Variant(nullToEmpty(group.getHeaderLayoutUri())));

    addStatusNodes(node, path, () -> service.components().writerGroup(connectionName, name));

    if (diagnosticsEnabled) {
      BaseObjectTypeNode liveValues =
          buildComponentDiagnostics(node, path, DiagnosticsKind.WRITER_GROUP);
      addCountLiveValue(
          liveValues, "ConfiguredDataSetWriters", () -> writerCounts(connectionName, name)[0]);
      addCountLiveValue(
          liveValues, "OperationalDataSetWriters", () -> writerCounts(connectionName, name)[1]);
    }

    if (group.getMessageSettings() instanceof UadpWriterGroupMessageDataType uadp) {
      UadpWriterGroupMessageTypeNode messageSettings =
          addObjectNode(
              UadpWriterGroupMessageTypeNode::new,
              childNodeId(node, "MessageSettings"),
              new QualifiedName(0, "MessageSettings"),
              NodeIds.UadpWriterGroupMessageType,
              NodeIds.HasComponent,
              nodeId);

      addPropertyNode(
          messageSettings,
          "GroupVersion",
          NodeIds.VersionTime,
          ValueRanks.Scalar,
          new Variant(uadp.getGroupVersion()));

      addPropertyNode(
          messageSettings,
          "DataSetOrdering",
          NodeIds.DataSetOrderingType,
          ValueRanks.Scalar,
          new Variant(uadp.getDataSetOrdering()));

      addPropertyNode(
          messageSettings,
          "NetworkMessageContentMask",
          NodeIds.UadpNetworkMessageContentMask,
          ValueRanks.Scalar,
          new Variant(uadp.getNetworkMessageContentMask()));

      addPropertyNode(
          messageSettings,
          "PublishingOffset",
          NodeIds.Duration,
          ValueRanks.OneDimension,
          new Variant(orEmpty(uadp.getPublishingOffset(), Double[]::new)));
    }

    DataSetWriterDataType[] writers =
        orEmpty(group.getDataSetWriters(), DataSetWriterDataType[]::new);

    for (DataSetWriterDataType writer : writers) {
      buildDataSetWriterNodes(node, connectionName, name, writer, dataSetNodeIds);
    }
  }

  private void buildDataSetWriterNodes(
      WriterGroupTypeNode groupNode,
      String connectionName,
      String groupName,
      DataSetWriterDataType writer,
      Map<String, NodeId> dataSetNodeIds) {

    String name = nullToEmpty(writer.getName());
    String path = connectionName + "/" + groupName + "/" + name;

    var nodeId = new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + path);

    DataSetWriterTypeNode node =
        addObjectNode(
            DataSetWriterTypeNode::new,
            nodeId,
            new QualifiedName(namespaceIndex, name),
            NodeIds.DataSetWriterType,
            NodeIds.HasDataSetWriter,
            groupNode.getNodeId());

    addPropertyNode(
        node,
        "DataSetWriterId",
        NodeIds.UInt16,
        ValueRanks.Scalar,
        new Variant(writer.getDataSetWriterId()));

    addPropertyNode(
        node,
        "DataSetFieldContentMask",
        NodeIds.DataSetFieldContentMask,
        ValueRanks.Scalar,
        new Variant(writer.getDataSetFieldContentMask()));

    addPropertyNode(
        node,
        "KeyFrameCount",
        NodeIds.UInt32,
        ValueRanks.Scalar,
        new Variant(writer.getKeyFrameCount()));

    addPropertyNode(
        node,
        "DataSetWriterProperties",
        NodeIds.KeyValuePair,
        ValueRanks.OneDimension,
        new Variant(orEmpty(writer.getDataSetWriterProperties(), KeyValuePair[]::new)));

    addStatusNodes(
        node, path, () -> service.components().dataSetWriter(connectionName, groupName, name));

    if (diagnosticsEnabled) {
      BaseObjectTypeNode liveValues =
          buildComponentDiagnostics(node, path, DiagnosticsKind.DATA_SET_WRITER);
      // MajorVersion/MinorVersion (Optional/Info) from the referenced PublishedDataSet's version
      addDataSetVersionLiveValues(liveValues, dataSetVersionsByName.get(writer.getDataSetName()));
    }

    if (writer.getMessageSettings() instanceof UadpDataSetWriterMessageDataType uadp) {
      UadpDataSetWriterMessageTypeNode messageSettings =
          addObjectNode(
              UadpDataSetWriterMessageTypeNode::new,
              childNodeId(node, "MessageSettings"),
              new QualifiedName(0, "MessageSettings"),
              NodeIds.UadpDataSetWriterMessageType,
              NodeIds.HasComponent,
              nodeId);

      addPropertyNode(
          messageSettings,
          "DataSetMessageContentMask",
          NodeIds.UadpDataSetMessageContentMask,
          ValueRanks.Scalar,
          new Variant(uadp.getDataSetMessageContentMask()));

      addPropertyNode(
          messageSettings,
          "ConfiguredSize",
          NodeIds.UInt16,
          ValueRanks.Scalar,
          new Variant(uadp.getConfiguredSize()));

      addPropertyNode(
          messageSettings,
          "NetworkMessageNumber",
          NodeIds.UInt16,
          ValueRanks.Scalar,
          new Variant(uadp.getNetworkMessageNumber()));

      addPropertyNode(
          messageSettings,
          "DataSetOffset",
          NodeIds.UInt16,
          ValueRanks.Scalar,
          new Variant(uadp.getDataSetOffset()));
    }

    NodeId dataSetNodeId =
        writer.getDataSetName() != null ? dataSetNodeIds.get(writer.getDataSetName()) : null;

    if (dataSetNodeId != null) {
      // stored with its invert, so the dataset node browses a forward DataSetToWriter reference
      node.addReference(
          new Reference(
              nodeId,
              NodeIds.DataSetToWriter,
              dataSetNodeId.expanded(),
              Reference.Direction.INVERSE));
    }
  }

  private void buildReaderGroupNodes(
      PubSubConnectionTypeNode connectionNode, String connectionName, ReaderGroupDataType group) {

    String name = nullToEmpty(group.getName());
    String path = connectionName + "/" + name;

    var nodeId = new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + path);

    ReaderGroupTypeNode node =
        addObjectNode(
            ReaderGroupTypeNode::new,
            nodeId,
            new QualifiedName(namespaceIndex, name),
            NodeIds.ReaderGroupType,
            NodeIds.HasReaderGroup,
            connectionNode.getNodeId());

    addGroupPropertyNodes(node, group);

    addStatusNodes(node, path, () -> service.components().readerGroup(connectionName, name));

    if (diagnosticsEnabled) {
      BaseObjectTypeNode liveValues =
          buildComponentDiagnostics(node, path, DiagnosticsKind.READER_GROUP);
      addCountLiveValue(
          liveValues, "ConfiguredDataSetReaders", () -> readerCounts(connectionName, name)[0]);
      addCountLiveValue(
          liveValues, "OperationalDataSetReaders", () -> readerCounts(connectionName, name)[1]);
    }

    DataSetReaderDataType[] readers =
        orEmpty(group.getDataSetReaders(), DataSetReaderDataType[]::new);

    for (DataSetReaderDataType reader : readers) {
      buildDataSetReaderNodes(node, connectionName, name, reader);
    }
  }

  private void buildDataSetReaderNodes(
      ReaderGroupTypeNode groupNode,
      String connectionName,
      String groupName,
      DataSetReaderDataType reader) {

    String name = nullToEmpty(reader.getName());
    String path = connectionName + "/" + groupName + "/" + name;

    var nodeId = new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + path);

    DataSetReaderTypeNode node =
        addObjectNode(
            DataSetReaderTypeNode::new,
            nodeId,
            new QualifiedName(namespaceIndex, name),
            NodeIds.DataSetReaderType,
            NodeIds.HasDataSetReader,
            groupNode.getNodeId());

    Variant publisherId =
        reader.getPublisherId() != null ? reader.getPublisherId() : Variant.NULL_VALUE;

    addPropertyNode(node, "PublisherId", NodeIds.BaseDataType, ValueRanks.Scalar, publisherId);

    addPropertyNode(
        node,
        "WriterGroupId",
        NodeIds.UInt16,
        ValueRanks.Scalar,
        new Variant(reader.getWriterGroupId()));

    addPropertyNode(
        node,
        "DataSetWriterId",
        NodeIds.UInt16,
        ValueRanks.Scalar,
        new Variant(reader.getDataSetWriterId()));

    PropertyTypeNode metaDataNode =
        addPropertyNode(
            node,
            "DataSetMetaData",
            NodeIds.DataSetMetaDataType,
            ValueRanks.Scalar,
            new Variant(reader.getDataSetMetaData()));

    metaDataVariables.put(path, metaDataNode);

    addPropertyNode(
        node,
        "DataSetFieldContentMask",
        NodeIds.DataSetFieldContentMask,
        ValueRanks.Scalar,
        new Variant(reader.getDataSetFieldContentMask()));

    addPropertyNode(
        node,
        "MessageReceiveTimeout",
        NodeIds.Duration,
        ValueRanks.Scalar,
        new Variant(reader.getMessageReceiveTimeout()));

    addPropertyNode(
        node,
        "KeyFrameCount",
        NodeIds.UInt32,
        ValueRanks.Scalar,
        new Variant(reader.getKeyFrameCount()));

    addPropertyNode(
        node,
        "HeaderLayoutUri",
        NodeIds.String,
        ValueRanks.Scalar,
        new Variant(nullToEmpty(reader.getHeaderLayoutUri())));

    addPropertyNode(
        node,
        "DataSetReaderProperties",
        NodeIds.KeyValuePair,
        ValueRanks.OneDimension,
        new Variant(orEmpty(reader.getDataSetReaderProperties(), KeyValuePair[]::new)));

    // reader-level security members are all Optional; omitted unless security is configured
    // (Invalid is the Part 14 §6.2.9.9 "no override" sentinel emitted for readers without a
    // MessageSecurityConfig override)
    if (reader.getSecurityMode() != null
        && reader.getSecurityMode() != MessageSecurityMode.None
        && reader.getSecurityMode() != MessageSecurityMode.Invalid) {
      addPropertyNode(
          node,
          "SecurityMode",
          NodeIds.MessageSecurityMode,
          ValueRanks.Scalar,
          new Variant(reader.getSecurityMode()));
    }
    if (reader.getSecurityGroupId() != null) {
      addPropertyNode(
          node,
          "SecurityGroupId",
          NodeIds.String,
          ValueRanks.Scalar,
          new Variant(reader.getSecurityGroupId()));
    }
    EndpointDescription[] securityKeyServices = reader.getSecurityKeyServices();
    if (securityKeyServices != null && securityKeyServices.length > 0) {
      addPropertyNode(
          node,
          "SecurityKeyServices",
          NodeIds.EndpointDescription,
          ValueRanks.OneDimension,
          new Variant(securityKeyServices));
    }

    addStatusNodes(
        node, path, () -> service.components().dataSetReader(connectionName, groupName, name));

    if (diagnosticsEnabled) {
      BaseObjectTypeNode liveValues =
          buildComponentDiagnostics(node, path, DiagnosticsKind.DATA_SET_READER);
      DataSetMetaDataType readerMetaData = reader.getDataSetMetaData();
      addDataSetVersionLiveValues(
          liveValues, readerMetaData != null ? readerMetaData.getConfigurationVersion() : null);
      // seed tracking so the DataSetListener updates this reader; reads 0 until a DataSet arrives
      lastReaderMessageSeq.putIfAbsent(path, ushort(0));
      addMessageSequenceNumberLiveValue(liveValues, path);
    }

    if (reader.getMessageSettings() instanceof UadpDataSetReaderMessageDataType uadp) {
      buildReaderMessageSettingsNodes(node, nodeId, uadp);
    }

    buildSubscribedDataSetNodes(node, nodeId, reader);
  }

  private void buildReaderMessageSettingsNodes(
      DataSetReaderTypeNode readerNode,
      NodeId readerNodeId,
      UadpDataSetReaderMessageDataType uadp) {

    UadpDataSetReaderMessageTypeNode messageSettings =
        addObjectNode(
            UadpDataSetReaderMessageTypeNode::new,
            childNodeId(readerNode, "MessageSettings"),
            new QualifiedName(0, "MessageSettings"),
            NodeIds.UadpDataSetReaderMessageType,
            NodeIds.HasComponent,
            readerNodeId);

    addPropertyNode(
        messageSettings,
        "GroupVersion",
        NodeIds.VersionTime,
        ValueRanks.Scalar,
        new Variant(uadp.getGroupVersion()));

    addPropertyNode(
        messageSettings,
        "NetworkMessageNumber",
        NodeIds.UInt16,
        ValueRanks.Scalar,
        new Variant(uadp.getNetworkMessageNumber()));

    addPropertyNode(
        messageSettings,
        "DataSetOffset",
        NodeIds.UInt16,
        ValueRanks.Scalar,
        new Variant(uadp.getDataSetOffset()));

    addPropertyNode(
        messageSettings,
        "DataSetClassId",
        NodeIds.Guid,
        ValueRanks.Scalar,
        new Variant(uadp.getDataSetClassId()));

    addPropertyNode(
        messageSettings,
        "NetworkMessageContentMask",
        NodeIds.UadpNetworkMessageContentMask,
        ValueRanks.Scalar,
        new Variant(uadp.getNetworkMessageContentMask()));

    addPropertyNode(
        messageSettings,
        "DataSetMessageContentMask",
        NodeIds.UadpDataSetMessageContentMask,
        ValueRanks.Scalar,
        new Variant(uadp.getDataSetMessageContentMask()));

    addPropertyNode(
        messageSettings,
        "PublishingInterval",
        NodeIds.Duration,
        ValueRanks.Scalar,
        new Variant(uadp.getPublishingInterval()));

    addPropertyNode(
        messageSettings,
        "ProcessingOffset",
        NodeIds.Duration,
        ValueRanks.Scalar,
        new Variant(uadp.getProcessingOffset()));

    addPropertyNode(
        messageSettings,
        "ReceiveOffset",
        NodeIds.Duration,
        ValueRanks.Scalar,
        new Variant(uadp.getReceiveOffset()));
  }

  /**
   * Build the Mandatory SubscribedDataSet child: a TargetVariablesType instance when the reader is
   * configured with TargetVariables, otherwise the member-less SubscribedDataSetType base.
   */
  private void buildSubscribedDataSetNodes(
      DataSetReaderTypeNode readerNode, NodeId readerNodeId, DataSetReaderDataType reader) {

    if (reader.getSubscribedDataSet() instanceof TargetVariablesDataType targetVariables) {
      TargetVariablesTypeNode subscribedDataSet =
          addObjectNode(
              TargetVariablesTypeNode::new,
              childNodeId(readerNode, "SubscribedDataSet"),
              new QualifiedName(0, "SubscribedDataSet"),
              NodeIds.TargetVariablesType,
              NodeIds.HasComponent,
              readerNodeId);

      addPropertyNode(
          subscribedDataSet,
          "TargetVariables",
          NodeIds.FieldTargetDataType,
          ValueRanks.OneDimension,
          new Variant(orEmpty(targetVariables.getTargetVariables(), FieldTargetDataType[]::new)));
    } else {
      addObjectNode(
          SubscribedDataSetTypeNode::new,
          childNodeId(readerNode, "SubscribedDataSet"),
          new QualifiedName(0, "SubscribedDataSet"),
          NodeIds.SubscribedDataSetType,
          NodeIds.HasComponent,
          readerNodeId);
    }
  }

  /** Add the PubSubGroupType members shared by WriterGroupType and ReaderGroupType instances. */
  private void addGroupPropertyNodes(UaNode node, PubSubGroupDataType group) {
    addPropertyNode(
        node,
        "SecurityMode",
        NodeIds.MessageSecurityMode,
        ValueRanks.Scalar,
        new Variant(group.getSecurityMode()));

    addPropertyNode(
        node,
        "MaxNetworkMessageSize",
        NodeIds.UInt32,
        ValueRanks.Scalar,
        new Variant(group.getMaxNetworkMessageSize()));

    addPropertyNode(
        node,
        "GroupProperties",
        NodeIds.KeyValuePair,
        ValueRanks.OneDimension,
        new Variant(orEmpty(group.getGroupProperties(), KeyValuePair[]::new)));

    if (group.getSecurityGroupId() != null) {
      addPropertyNode(
          node,
          "SecurityGroupId",
          NodeIds.String,
          ValueRanks.Scalar,
          new Variant(group.getSecurityGroupId()));
    }

    EndpointDescription[] securityKeyServices = group.getSecurityKeyServices();
    if (securityKeyServices != null && securityKeyServices.length > 0) {
      addPropertyNode(
          node,
          "SecurityKeyServices",
          NodeIds.EndpointDescription,
          ValueRanks.OneDimension,
          new Variant(securityKeyServices));
    }
  }

  /**
   * Add a Status object with a State variable to {@code parent} and register the State variable
   * under {@code componentPath} for live updates. When Enable/Disable are supported, also mints the
   * two Optional §9.1.10 methods on the Status object, resolving the component handle live through
   * {@code handleSupplier} on each call.
   */
  private void addStatusNodes(
      UaNode parent, String componentPath, Supplier<Optional<PubSubHandle>> handleSupplier) {

    PubSubStatusTypeNode statusNode =
        addObjectNode(
            PubSubStatusTypeNode::new,
            childNodeId(parent, "Status"),
            new QualifiedName(0, "Status"),
            NodeIds.PubSubStatusType,
            NodeIds.HasComponent,
            parent.getNodeId());

    BaseDataVariableTypeNode stateNode =
        addVariableNode(
            statusNode,
            "State",
            NodeIds.PubSubState,
            new Variant(initialState(handleSupplier.get())));

    stateVariables.put(componentPath, stateNode);

    if (enableDisableSupported) {
      UaMethodNode enable = addMethodNode(statusNode, "Enable");
      enable.setInvocationHandler(new EnableMethodImpl(enable, handleSupplier));

      UaMethodNode disable = addMethodNode(statusNode, "Disable");
      disable.setInvocationHandler(new DisableMethodImpl(disable, handleSupplier));
    }
  }

  /**
   * Mint an argument-less method node under {@code parent} (HasComponent), added to this fragment's
   * node manager with the inverse reference so the parent browses the forward HasComponent.
   */
  private UaMethodNode addMethodNode(UaNode parent, String name) {
    NodeId nodeId = childNodeId(parent, name);

    UaMethodNode node =
        UaMethodNode.builder(getNodeContext())
            .setNodeId(nodeId)
            .setBrowseName(new QualifiedName(0, name))
            .setDisplayName(LocalizedText.english(name))
            .build();

    getNodeManager().addNode(node);

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasComponent,
            parent.getNodeId().expanded(),
            Reference.Direction.INVERSE));

    return node;
  }

  // endregion

  // region Enable/Disable method handlers

  private final class EnableMethodImpl extends PubSubStatusType.EnableMethod {

    private final Supplier<Optional<PubSubHandle>> handleSupplier;

    EnableMethodImpl(UaMethodNode node, Supplier<Optional<PubSubHandle>> handleSupplier) {
      super(node);
      this.handleSupplier = handleSupplier;
    }

    @Override
    protected void invoke(InvocationContext context) throws UaException {
      requireConfigureSession(context);
      PubSubHandle handle = requireHandle();

      // §9.1.10.2: Enable is rejected unless the current State is Disabled.
      if (currentState(handle) != PubSubState.Disabled) {
        throw new UaException(
            StatusCodes.Bad_InvalidState, "Enable requires the current State to be Disabled");
      }
      service.enable(handle);
    }

    private PubSubHandle requireHandle() throws UaException {
      return handleSupplier
          .get()
          .orElseThrow(
              () -> new UaException(StatusCodes.Bad_InvalidState, "component is not available"));
    }
  }

  private final class DisableMethodImpl extends PubSubStatusType.DisableMethod {

    private final Supplier<Optional<PubSubHandle>> handleSupplier;

    DisableMethodImpl(UaMethodNode node, Supplier<Optional<PubSubHandle>> handleSupplier) {
      super(node);
      this.handleSupplier = handleSupplier;
    }

    @Override
    protected void invoke(InvocationContext context) throws UaException {
      requireConfigureSession(context);
      PubSubHandle handle =
          handleSupplier
              .get()
              .orElseThrow(
                  () ->
                      new UaException(StatusCodes.Bad_InvalidState, "component is not available"));

      // §9.1.10.3: Disable is rejected if the current State is already Disabled.
      if (currentState(handle) == PubSubState.Disabled) {
        throw new UaException(
            StatusCodes.Bad_InvalidState, "Disable requires the current State to not be Disabled");
      }
      service.disable(handle);
    }
  }

  /**
   * Enforce the authorization posture for the Enable/Disable methods: a client session is required
   * (session-less internal calls are {@code Bad_UserAccessDenied}) and {@link
   * PubSubMethodAuthorizer#checkConfigure} must allow.
   */
  private void requireConfigureSession(InvocationContext context) throws UaException {
    Session session = context.getSession().orElse(null);
    if (session == null) {
      throw new UaException(StatusCodes.Bad_UserAccessDenied, "no session");
    }
    if (authorizer.checkConfigure(session) != PubSubMethodAuthorizer.Decision.ALLOW) {
      throw new UaException(StatusCodes.Bad_UserAccessDenied);
    }
  }

  /**
   * Read the live state of {@code handle}, mapping an invalidated handle to {@code
   * Bad_InvalidState}.
   */
  private PubSubState currentState(PubSubHandle handle) throws UaException {
    try {
      return service.state(handle);
    } catch (IllegalArgumentException e) {
      throw new UaException(StatusCodes.Bad_InvalidState, "component handle is invalid");
    }
  }

  // endregion

  // region node helpers

  /** The shared shape of the generated object TypeNode constructors (without event notifier). */
  @FunctionalInterface
  private interface ObjectNodeConstructor<T extends UaObjectNode> {
    T create(
        UaNodeContext context,
        NodeId nodeId,
        QualifiedName browseName,
        LocalizedText displayName,
        LocalizedText description,
        UInteger writeMask,
        UInteger userWriteMask,
        RolePermissionType @Nullable [] rolePermissions,
        RolePermissionType @Nullable [] userRolePermissions,
        @Nullable AccessRestrictionType accessRestrictions);
  }

  /**
   * Create an object node, type-define it, add it to this fragment's node manager, and graft it
   * under {@code parentNodeId} with an inverse {@code referenceTypeId} reference (the node manager
   * stores both directions, so the parent browses the forward reference without being modified).
   */
  private <T extends UaObjectNode> T addObjectNode(
      ObjectNodeConstructor<T> constructor,
      NodeId nodeId,
      QualifiedName browseName,
      NodeId typeDefinitionId,
      NodeId referenceTypeId,
      NodeId parentNodeId) {

    T node =
        constructor.create(
            getNodeContext(),
            nodeId,
            browseName,
            LocalizedText.english(browseName.name()),
            LocalizedText.NULL_VALUE,
            uint(0),
            uint(0),
            null,
            null,
            null);

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasTypeDefinition,
            typeDefinitionId.expanded(),
            Reference.Direction.FORWARD));

    getNodeManager().addNode(node);

    node.addReference(
        new Reference(
            nodeId, referenceTypeId, parentNodeId.expanded(), Reference.Direction.INVERSE));

    return node;
  }

  /**
   * Create a PropertyType variable node under {@code parent} (HasProperty), pre-created explicitly
   * so the typed-setter create-on-set path is never exercised. Read-only by default.
   */
  private PropertyTypeNode addPropertyNode(
      UaNode parent, String name, NodeId dataTypeId, int valueRank, Variant value) {

    NodeId nodeId = childNodeId(parent, name);

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
            parent.getNodeId().expanded(),
            Reference.Direction.INVERSE));

    return node;
  }

  /**
   * Create a scalar BaseDataVariableType component variable under {@code parent} (HasComponent).
   */
  private BaseDataVariableTypeNode addVariableNode(
      UaNode parent, String name, NodeId dataTypeId, Variant value) {

    NodeId nodeId = childNodeId(parent, name);

    var node =
        new BaseDataVariableTypeNode(
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
            ValueRanks.Scalar,
            null);

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasTypeDefinition,
            NodeIds.BaseDataVariableType.expanded(),
            Reference.Direction.FORWARD));

    getNodeManager().addNode(node);

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasComponent,
            parent.getNodeId().expanded(),
            Reference.Direction.INVERSE));

    return node;
  }

  /**
   * Create a scalar String SelectionListType component variable under {@code parent} with its
   * Mandatory Selections property.
   */
  private SelectionListTypeNode addSelectionListNode(
      UaNode parent, String name, @Nullable String value, Object[] selections) {

    NodeId nodeId = childNodeId(parent, name);

    var node =
        new SelectionListTypeNode(
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
            new DataValue(new Variant(value)),
            NodeIds.String,
            ValueRanks.Scalar,
            null);

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasTypeDefinition,
            NodeIds.SelectionListType.expanded(),
            Reference.Direction.FORWARD));

    getNodeManager().addNode(node);

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasComponent,
            parent.getNodeId().expanded(),
            Reference.Direction.INVERSE));

    addPropertyNode(
        node, "Selections", NodeIds.BaseDataType, ValueRanks.OneDimension, new Variant(selections));

    return node;
  }

  private NodeId childNodeId(UaNode parent, String name) {
    return new NodeId(namespaceIndex, parent.getNodeId().getIdentifier().toString() + "/" + name);
  }

  // endregion

  // region ns0 population and live state

  /**
   * Populate values on the existing ns0 children of the PublishSubscribe object. Existing nodes are
   * looked up and their values set; nothing is created (and absent nodes are only logged), so the
   * ns0 node manager is never modified.
   */
  private void populateExistingNs0Nodes(PubSubConfiguration2DataType configuration) {
    Optional<UaNode> publishSubscribeNode =
        getServer().getAddressSpaceManager().getManagedNode(NodeIds.PublishSubscribe);

    if (publishSubscribeNode.isEmpty()) {
      LOGGER.warn("ns0 PublishSubscribe node not found: {}", NodeIds.PublishSubscribe);
      return;
    }

    UaNode node = publishSubscribeNode.get();

    setExistingPropertyValue(
        node,
        PublishSubscribeType.SUPPORTED_TRANSPORT_PROFILES.getBrowseName(),
        new Variant(new String[] {UdpTransportProvider.TRANSPORT_PROFILE_URI}));

    setExistingPropertyValue(
        node,
        PublishSubscribeType.CONFIGURATION_VERSION.getBrowseName(),
        new Variant(versionTimeNow()));

    setExistingPropertyValue(
        node,
        PublishSubscribeType.CONFIGURATION_PROPERTIES.getBrowseName(),
        new Variant(orEmpty(configuration.getConfigurationProperties(), KeyValuePair[]::new)));

    setRootState(config.isEnabled() ? PubSubState.Operational : PubSubState.Disabled);
  }

  /** Set the value of an existing ns0 property node, by browse name; never creates. */
  private void setExistingPropertyValue(UaNode node, String browseName, Variant value) {
    Optional<VariableNode> propertyNode = node.getPropertyNode(new QualifiedName(0, browseName));

    propertyNode.ifPresentOrElse(
        property -> property.setValue(new DataValue(value)),
        () -> LOGGER.warn("ns0 property node not found: {}", browseName));
  }

  /**
   * Set the ns0 PublishSubscribe Status/State value ({@code i=17406}). The root state reflects the
   * service-level enabled flag: Operational while this exposure is active and the configuration is
   * enabled, Disabled otherwise (the engine has no service-root component handle).
   */
  private void setRootState(PubSubState state) {
    getServer()
        .getAddressSpaceManager()
        .getManagedNode(NodeIds.PublishSubscribe_Status_State)
        .ifPresent(
            node -> {
              if (node instanceof UaVariableNode variableNode) {
                variableNode.setValue(new DataValue(new Variant(state)));
              }
            });
  }

  /**
   * Register the live-update listeners. {@link PubSubService} has no listener removal, so the
   * callbacks are guarded by {@link #active} and become no-ops after shutdown.
   */
  private void registerListeners() {
    service.addStateListener(
        event -> {
          if (!active || !isTrackedComponentType(event.component().componentType())) {
            return;
          }

          UaVariableNode stateNode = stateVariables.get(event.component().path());
          if (stateNode != null) {
            stateNode.setValue(new DataValue(new Variant(event.newState())));
          }
        });

    service.addMetaDataListener(
        event -> {
          if (!active) {
            return;
          }

          UaVariableNode metaDataNode = metaDataVariables.get(event.reader().path());
          if (metaDataNode != null) {
            metaDataNode.setValue(new DataValue(new Variant(event.metaData())));
          }
        });

    service.addDataSetListener(
        event -> {
          if (!active) {
            return;
          }

          UInteger seq = event.dataSetMessageSequenceNumber();
          if (seq != null) {
            // computeIfPresent only tracks readers whose diagnostics node is currently built
            // (seeded in buildDataSetReaderNodes, purged with the subtree on rebuild)
            lastReaderMessageSeq.computeIfPresent(
                event.reader().path(), (path, previous) -> ushort(seq.intValue() & 0xFFFF));
          }
        });
  }

  // endregion

  // region config-derived rebuild

  /**
   * Reconcile the config-derived subtrees against {@code appliedConfig}, the configuration a
   * reconfigure just applied to the engine. Connections and PublishedDataSets whose normalized
   * {@code DataType} differs from the last-built configuration — and connections whose
   * DataSetWriters reference a changed PublishedDataSet — are torn down and rebuilt from {@code
   * appliedConfig}; unaffected subtrees are left in place. The root Status/State and
   * ConfigurationProperties are refreshed to match. No-op if the fragment is not active.
   *
   * <p>Called on the thread that applied the reconfigure (a server method-call thread for {@code
   * CloseAndUpdate}, or the caller of {@link ServerPubSub#reconfigure}); serialized against itself
   * by {@link #rebuildLock}.
   *
   * @param appliedConfig the configuration now in effect on the engine.
   */
  void onConfigurationApplied(PubSubConfig appliedConfig) {
    synchronized (rebuildLock) {
      PubSubConfiguration2DataType previous = builtConfiguration;
      if (!active || previous == null) {
        return;
      }

      PubSubConfiguration2DataType applied =
          appliedConfig.toDataType(getServer().getNamespaceTable());

      dataSetVersionsByName = dataSetVersions(applied);

      Set<String> changedDataSets = reconcilePublishedDataSets(previous, applied);

      var dataSetNodeIds = new HashMap<String, NodeId>();
      for (PublishedDataSetDataType dataSet :
          orEmpty(applied.getPublishedDataSets(), PublishedDataSetDataType[]::new)) {
        if (dataSet != null && dataSet.getName() != null) {
          dataSetNodeIds.put(
              dataSet.getName(),
              new NodeId(
                  namespaceIndex, NODE_ID_PREFIX + "/PublishedDataSets/" + dataSet.getName()));
        }
      }

      reconcileConnections(previous, applied, dataSetNodeIds, changedDataSets);

      refreshRootFromConfig(applied, appliedConfig.isEnabled());

      builtConfiguration = applied;
    }
  }

  /**
   * Reconcile the PublishedDataSet subtrees; returns the set of dataset names whose configuration
   * was added, removed, or changed (so connections referencing them can be rebuilt to re-establish
   * their DataSetToWriter references).
   */
  private Set<String> reconcilePublishedDataSets(
      PubSubConfiguration2DataType previous, PubSubConfiguration2DataType applied) {

    Map<String, PublishedDataSetDataType> oldByName =
        byName(previous.getPublishedDataSets(), PublishedDataSetDataType::getName);
    Map<String, PublishedDataSetDataType> newByName =
        byName(applied.getPublishedDataSets(), PublishedDataSetDataType::getName);

    var changed = new LinkedHashSet<String>();
    for (String name : union(oldByName.keySet(), newByName.keySet())) {
      PublishedDataSetDataType oldDataSet = oldByName.get(name);
      PublishedDataSetDataType newDataSet = newByName.get(name);

      if (Objects.equals(oldDataSet, newDataSet)) {
        continue;
      }
      changed.add(name);

      if (oldDataSet != null) {
        deleteSubtree(new NodeId(namespaceIndex, NODE_ID_PREFIX + "/PublishedDataSets/" + name));
      }
      if (newDataSet != null) {
        buildPublishedDataSetNodes(newDataSet);
      }
    }
    return changed;
  }

  /** Reconcile the connection subtrees (connection-shell granularity: rebuild the whole tree). */
  private void reconcileConnections(
      PubSubConfiguration2DataType previous,
      PubSubConfiguration2DataType applied,
      Map<String, NodeId> dataSetNodeIds,
      Set<String> changedDataSets) {

    Map<String, PubSubConnectionDataType> oldByName =
        byName(previous.getConnections(), PubSubConnectionDataType::getName);
    Map<String, PubSubConnectionDataType> newByName =
        byName(applied.getConnections(), PubSubConnectionDataType::getName);

    for (String name : union(oldByName.keySet(), newByName.keySet())) {
      PubSubConnectionDataType oldConnection = oldByName.get(name);
      PubSubConnectionDataType newConnection = newByName.get(name);

      boolean unchanged =
          Objects.equals(oldConnection, newConnection)
              && (newConnection == null
                  || !referencesChangedDataSet(newConnection, changedDataSets));
      if (unchanged) {
        continue;
      }

      if (oldConnection != null) {
        deleteSubtree(new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + name));
        purgeTracking(name);
      }
      if (newConnection != null) {
        buildConnectionNodes(newConnection, dataSetNodeIds);
      }
    }
  }

  /**
   * True if any DataSetWriter in {@code connection} references a dataset in {@code changedNames}.
   */
  private static boolean referencesChangedDataSet(
      PubSubConnectionDataType connection, Set<String> changedNames) {

    if (changedNames.isEmpty()) {
      return false;
    }
    for (WriterGroupDataType group :
        orEmpty(connection.getWriterGroups(), WriterGroupDataType[]::new)) {
      if (group == null) {
        continue;
      }
      for (DataSetWriterDataType writer :
          orEmpty(group.getDataSetWriters(), DataSetWriterDataType[]::new)) {
        if (writer != null && changedNames.contains(writer.getDataSetName())) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Delete the node with {@code nodeId} and its entire child subtree from this fragment's node
   * manager (a no-op if absent). {@link UaNode#delete()} recurses through the hierarchical
   * (HasComponent-subtype) references — HasWriterGroup, HasDataSetReader, HasProperty, ... — and
   * removes each reference and its inverse, including the forward reference the ns0 parent browses;
   * the non-hierarchical DataSetToWriter reference is removed (both directions) but not recursed,
   * so a referenced PublishedDataSet is not deleted with a writer.
   */
  private void deleteSubtree(NodeId nodeId) {
    getNodeManager().getNode(nodeId).ifPresent(UaNode::delete);
  }

  /** Drop live-update tracking entries for {@code path} and every descendant path. */
  private void purgeTracking(String path) {
    stateVariables.keySet().removeIf(key -> key.equals(path) || key.startsWith(path + "/"));
    metaDataVariables.keySet().removeIf(key -> key.equals(path) || key.startsWith(path + "/"));
    lastReaderMessageSeq.keySet().removeIf(key -> key.equals(path) || key.startsWith(path + "/"));
  }

  /** Refresh the ns0 root ConfigurationProperties and Status/State after a reconfigure. */
  private void refreshRootFromConfig(PubSubConfiguration2DataType configuration, boolean enabled) {
    getServer()
        .getAddressSpaceManager()
        .getManagedNode(NodeIds.PublishSubscribe)
        .ifPresent(
            node ->
                setExistingPropertyValue(
                    node,
                    PublishSubscribeType.CONFIGURATION_PROPERTIES.getBrowseName(),
                    new Variant(
                        orEmpty(configuration.getConfigurationProperties(), KeyValuePair[]::new))));

    setRootState(enabled ? PubSubState.Operational : PubSubState.Disabled);
  }

  /** Index {@code values} by name (skipping nulls), keyed by the empty-normalized name. */
  private static <T> Map<String, T> byName(
      T @Nullable [] values, Function<T, @Nullable String> nameOf) {

    var map = new LinkedHashMap<String, T>();
    if (values != null) {
      for (T value : values) {
        if (value != null) {
          map.put(nullToEmpty(nameOf.apply(value)), value);
        }
      }
    }
    return map;
  }

  private static Set<String> union(Set<String> a, Set<String> b) {
    var union = new LinkedHashSet<String>(a);
    union.addAll(b);
    return union;
  }

  // endregion

  // region live state

  /**
   * Only components with Status nodes in this exposure are tracked; other component types (e.g.
   * PublishedDataSets, whose bare-name paths could collide with connection names) are ignored.
   */
  private static boolean isTrackedComponentType(ComponentType componentType) {
    return switch (componentType) {
      case CONNECTION, WRITER_GROUP, DATA_SET_WRITER, READER_GROUP, DATA_SET_READER -> true;
      default -> false;
    };
  }

  /** Seed a Status/State value from the runtime, falling back to the Part 14 default Disabled. */
  private PubSubState initialState(Optional<PubSubHandle> handle) {
    try {
      return handle.map(service::state).orElse(PubSubState.Disabled);
    } catch (IllegalArgumentException e) {
      return PubSubState.Disabled;
    }
  }

  /** The current time as an OPC UA VersionTime: seconds since 2000-01-01T00:00:00 UTC. */
  private static UInteger versionTimeNow() {
    long seconds = Instant.now().getEpochSecond() - VERSION_TIME_EPOCH.getEpochSecond();
    return uint(seconds & 0xFFFFFFFFL);
  }

  // endregion

  // region diagnostics exposure

  private static final PubSubDiagnosticsCounterClassification INFO =
      PubSubDiagnosticsCounterClassification.Information;
  private static final PubSubDiagnosticsCounterClassification ERR =
      PubSubDiagnosticsCounterClassification.Error;

  /** The Part 14 §9.1.11 diagnostics object kind minted for a component, with its type node id. */
  private enum DiagnosticsKind {
    CONNECTION(NodeIds.PubSubDiagnosticsConnectionType),
    WRITER_GROUP(NodeIds.PubSubDiagnosticsWriterGroupType),
    READER_GROUP(NodeIds.PubSubDiagnosticsReaderGroupType),
    DATA_SET_WRITER(NodeIds.PubSubDiagnosticsDataSetWriterType),
    DATA_SET_READER(NodeIds.PubSubDiagnosticsDataSetReaderType);

    private final NodeId typeDefinition;

    DiagnosticsKind(NodeId typeDefinition) {
      this.typeDefinition = typeDefinition;
    }
  }

  /** One diagnostics counter exposed under a Counters folder: BrowseName, engine counter, class. */
  private record CounterSpec(
      String browseName, Counter counter, PubSubDiagnosticsCounterClassification classification) {}

  /** The six Part 14 Table 311 State* counters present on every diagnostics object. */
  private static final List<CounterSpec> STATE_COUNTERS =
      List.of(
          new CounterSpec("StateError", Counter.STATE_ERROR, ERR),
          new CounterSpec("StateOperationalByMethod", Counter.STATE_OPERATIONAL_BY_METHOD, INFO),
          new CounterSpec("StateOperationalByParent", Counter.STATE_OPERATIONAL_BY_PARENT, INFO),
          new CounterSpec("StateOperationalFromError", Counter.STATE_OPERATIONAL_FROM_ERROR, INFO),
          new CounterSpec("StatePausedByParent", Counter.STATE_PAUSED_BY_PARENT, INFO),
          new CounterSpec("StateDisabledByMethod", Counter.STATE_DISABLED_BY_METHOD, INFO));

  /** Engine counters classified Error; used for the {@code SubError} descendant roll-up. */
  private static final Set<Counter> ERROR_COUNTERS =
      Set.of(
          Counter.STATE_ERROR,
          Counter.FAILED_TRANSMISSIONS,
          Counter.ENCRYPTION_ERRORS,
          Counter.DECRYPTION_ERRORS,
          Counter.FAILED_DATA_SET_MESSAGES,
          Counter.DECODE_ERRORS);

  /** The ns0 PubSubCapabilities {@code Max*} property nodes (all advertised as 0). */
  private static final List<NodeId> CAPABILITY_MAX_NODES =
      List.of(
          NodeIds.PublishSubscribe_PubSubCapablities_MaxPubSubConnections,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxWriterGroups,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxReaderGroups,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxDataSetWriters,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxDataSetReaders,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxFieldsPerDataSet,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxDataSetWritersPerGroup,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxSecurityGroups,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxPushTargets,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxPublishedDataSets,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxStandaloneSubscribedDataSets,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxNetworkMessageSizeDatagram,
          NodeIds.PublishSubscribe_PubSubCapablities_MaxNetworkMessageSizeBroker);

  /** The counters exposed on a diagnostics object of {@code kind}. */
  private static List<CounterSpec> countersFor(DiagnosticsKind kind) {
    var specs = new ArrayList<>(STATE_COUNTERS);
    switch (kind) {
      case WRITER_GROUP -> {
        specs.add(new CounterSpec("SentNetworkMessages", Counter.NETWORK_MESSAGES_SENT, INFO));
        specs.add(new CounterSpec("FailedTransmissions", Counter.FAILED_TRANSMISSIONS, ERR));
        specs.add(new CounterSpec("EncryptionErrors", Counter.ENCRYPTION_ERRORS, ERR));
      }
      case READER_GROUP -> {
        specs.add(
            new CounterSpec("ReceivedNetworkMessages", Counter.NETWORK_MESSAGES_RECEIVED, INFO));
        specs.add(new CounterSpec("DecryptionErrors", Counter.DECRYPTION_ERRORS, ERR));
      }
      case DATA_SET_WRITER ->
          specs.add(
              new CounterSpec("FailedDataSetMessages", Counter.FAILED_DATA_SET_MESSAGES, ERR));
      case DATA_SET_READER ->
          // reader-side FailedDataSetMessages is fed by the engine's decodeErrors (§9.1.11.12);
          // DecryptionErrors is charged to the ReaderGroup/connection, not the reader, so omit it
          specs.add(new CounterSpec("FailedDataSetMessages", Counter.DECODE_ERRORS, ERR));
      case CONNECTION -> {
        // §9.1.11.8 adds no counters beyond the inherited six
      }
    }
    return specs;
  }

  /**
   * Mint the per-component {@code Diagnostics} object under {@code componentNode}: its read-only
   * Basic {@code DiagnosticsLevel}, the {@code TotalInformation}/{@code TotalError} sums of this
   * object's own counters, the {@code SubError} descendant roll-up, the {@code Reset} method, and
   * the {@code Counters} folder for {@code kind}. Counter values, Total*, and SubError are computed
   * at read time from the live {@link PubSubDiagnostics} snapshot with a fresh SourceTimestamp, and
   * UInt32-clamped (§9.1.11.5). Returns the (empty) {@code LiveValues} folder so the caller can add
   * the kind-specific live values.
   */
  private BaseObjectTypeNode buildComponentDiagnostics(
      UaNode componentNode, String path, DiagnosticsKind kind) {

    NodeId diagnosticsId = childNodeId(componentNode, "Diagnostics");
    QualifiedName browseName = new QualifiedName(0, "Diagnostics");
    NodeId parentId = componentNode.getNodeId();

    UaObjectNode diagnostics =
        switch (kind) {
          case CONNECTION ->
              addObjectNode(
                  PubSubDiagnosticsConnectionTypeNode::new,
                  diagnosticsId,
                  browseName,
                  kind.typeDefinition,
                  NodeIds.HasComponent,
                  parentId);
          case WRITER_GROUP ->
              addObjectNode(
                  PubSubDiagnosticsWriterGroupTypeNode::new,
                  diagnosticsId,
                  browseName,
                  kind.typeDefinition,
                  NodeIds.HasComponent,
                  parentId);
          case READER_GROUP ->
              addObjectNode(
                  PubSubDiagnosticsReaderGroupTypeNode::new,
                  diagnosticsId,
                  browseName,
                  kind.typeDefinition,
                  NodeIds.HasComponent,
                  parentId);
          case DATA_SET_WRITER ->
              addObjectNode(
                  PubSubDiagnosticsDataSetWriterTypeNode::new,
                  diagnosticsId,
                  browseName,
                  kind.typeDefinition,
                  NodeIds.HasComponent,
                  parentId);
          case DATA_SET_READER ->
              addObjectNode(
                  PubSubDiagnosticsDataSetReaderTypeNode::new,
                  diagnosticsId,
                  browseName,
                  kind.typeDefinition,
                  NodeIds.HasComponent,
                  parentId);
        };

    // read-only Basic level; no level switching/activation machinery
    addVariableNode(
        diagnostics,
        "DiagnosticsLevel",
        NodeIds.DiagnosticsLevel,
        new Variant(DiagnosticsLevel.Basic));

    List<CounterSpec> specs = countersFor(kind);

    // Total* = sum of this object's own Information/Error counters (§9.1.11.2)
    addComputedCounter(diagnostics, "TotalInformation", INFO, () -> totalValue(path, specs, INFO));
    addComputedCounter(diagnostics, "TotalError", ERR, () -> totalValue(path, specs, ERR));

    BaseDataVariableTypeNode subError =
        addVariableNode(diagnostics, "SubError", NodeIds.Boolean, new Variant(false));
    subError.getFilterChain().addLast(AttributeFilters.getValue(ctx -> subErrorValue(path)));

    // Reset (§9.1.11.3): zeroes this component's engine counters, guarded by checkConfigure
    UaMethodNode reset = addMethodNode(diagnostics, "Reset");
    reset.setInvocationHandler(new ComponentResetMethod(reset, path));

    BaseObjectTypeNode counters =
        addObjectNode(
            BaseObjectTypeNode::new,
            childNodeId(diagnostics, "Counters"),
            new QualifiedName(0, "Counters"),
            NodeIds.BaseObjectType,
            NodeIds.HasComponent,
            diagnostics.getNodeId());
    for (CounterSpec spec : specs) {
      addCounter(counters, spec.browseName(), path, spec.counter(), spec.classification());
    }

    return addObjectNode(
        BaseObjectTypeNode::new,
        childNodeId(diagnostics, "LiveValues"),
        new QualifiedName(0, "LiveValues"),
        NodeIds.BaseObjectType,
        NodeIds.HasComponent,
        diagnostics.getNodeId());
  }

  /** Add an engine-backed PubSubDiagnosticsCounterType counter under a Counters folder. */
  private void addCounter(
      UaNode counters,
      String name,
      String path,
      Counter counter,
      PubSubDiagnosticsCounterClassification classification) {

    addCounterVariable(
        counters,
        name,
        classification,
        () -> counterDataValue(path, counter),
        () -> timeFirstChangeDataValue(path, counter));
  }

  /** Add a computed (Total*) PubSubDiagnosticsCounterType counter with no TimeFirstChange. */
  private void addComputedCounter(
      UaNode parent,
      String name,
      PubSubDiagnosticsCounterClassification classification,
      Supplier<DataValue> valueSupplier) {

    addCounterVariable(parent, name, classification, valueSupplier, null);
  }

  /**
   * Create a PubSubDiagnosticsCounterType variable under {@code parent} whose UInt32 Value is
   * computed at read time by {@code valueSupplier}, with its Mandatory {@code Active} (always true,
   * a Basic counter), {@code Classification}, and {@code DiagnosticsLevel} (Basic) properties. When
   * {@code timeFirstChangeSupplier} is non-null the Optional {@code TimeFirstChange} is added too.
   */
  private void addCounterVariable(
      UaNode parent,
      String name,
      PubSubDiagnosticsCounterClassification classification,
      Supplier<DataValue> valueSupplier,
      @Nullable Supplier<DataValue> timeFirstChangeSupplier) {

    NodeId nodeId = childNodeId(parent, name);

    var node =
        new PubSubDiagnosticsCounterTypeNode(
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
            new DataValue(new Variant(uint(0))),
            NodeIds.UInt32,
            ValueRanks.Scalar,
            null);

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasTypeDefinition,
            NodeIds.PubSubDiagnosticsCounterType.expanded(),
            Reference.Direction.FORWARD));

    getNodeManager().addNode(node);

    node.addReference(
        new Reference(
            nodeId,
            NodeIds.HasComponent,
            parent.getNodeId().expanded(),
            Reference.Direction.INVERSE));

    node.getFilterChain().addLast(AttributeFilters.getValue(ctx -> valueSupplier.get()));

    addPropertyNode(node, "Active", NodeIds.Boolean, ValueRanks.Scalar, new Variant(true));
    addPropertyNode(
        node,
        "Classification",
        NodeIds.PubSubDiagnosticsCounterClassification,
        ValueRanks.Scalar,
        new Variant(classification));
    addPropertyNode(
        node,
        "DiagnosticsLevel",
        NodeIds.DiagnosticsLevel,
        ValueRanks.Scalar,
        new Variant(DiagnosticsLevel.Basic));

    if (timeFirstChangeSupplier != null) {
      PropertyTypeNode timeFirstChange =
          addPropertyNode(
              node, "TimeFirstChange", NodeIds.DateTime, ValueRanks.Scalar, Variant.NULL_VALUE);
      timeFirstChange
          .getFilterChain()
          .addLast(AttributeFilters.getValue(ctx -> timeFirstChangeSupplier.get()));
    }
  }

  /** Add a UInt16 count LiveValue whose value is computed at read time (Configured/Operational). */
  private void addCountLiveValue(UaNode liveValues, String name, IntSupplier count) {
    BaseDataVariableTypeNode node =
        addVariableNode(liveValues, name, NodeIds.UInt16, new Variant(ushort(0)));
    node.getFilterChain()
        .addLast(AttributeFilters.getValue(ctx -> countDataValue(count.getAsInt())));
  }

  /**
   * Add the Optional {@code MajorVersion}/{@code MinorVersion} LiveValues from a DataSet's
   * ConfigurationVersion; omitted (conformant) when no configured version is available.
   */
  private void addDataSetVersionLiveValues(
      UaNode liveValues, @Nullable ConfigurationVersionDataType version) {

    if (version == null) {
      return;
    }
    addVariableNode(
        liveValues, "MajorVersion", NodeIds.UInt32, new Variant(version.getMajorVersion()));
    addVariableNode(
        liveValues, "MinorVersion", NodeIds.UInt32, new Variant(version.getMinorVersion()));
  }

  /**
   * Add the Optional §9.1.11.12 {@code MessageSequenceNumber} LiveValue for a DataSetReader,
   * computed at read time from the last DataSet delivered to {@code readerPath} (see {@link
   * #registerListeners}). UInt16 per Table 331; reads {@code 0} until the first DataSet is
   * received.
   */
  private void addMessageSequenceNumberLiveValue(UaNode liveValues, String readerPath) {
    BaseDataVariableTypeNode node =
        addVariableNode(
            liveValues, "MessageSequenceNumber", NodeIds.UInt16, new Variant(ushort(0)));
    node.getFilterChain()
        .addLast(AttributeFilters.getValue(ctx -> messageSequenceNumberDataValue(readerPath)));
  }

  /** The last DataSetMessage sequence number received by the reader at {@code readerPath}. */
  private DataValue messageSequenceNumberDataValue(String readerPath) {
    UShort seq = active ? lastReaderMessageSeq.getOrDefault(readerPath, ushort(0)) : ushort(0);
    return new DataValue(new Variant(seq), StatusCode.GOOD);
  }

  // region ns0 root diagnostics + capabilities

  /** Back the loader-built ns0 Diagnostics root ({@code i=17409}) and PubSubCapabilities. */
  private void exposeNs0Diagnostics() {
    exposeRootDiagnostics();
    exposeCapabilities();
  }

  /**
   * Back the ns0 root Diagnostics ({@code i=17409}) subtree: values are set on the existing
   * loader-built nodes and the Reset handler is attached; no ns0 node is minted. The root object's
   * own counters (the six State*) are not engine-backed at the service level, so they and their
   * Total* sums are 0; the useful root signals are {@code SubError} (any component in error) and
   * the LiveValues counts, computed at read time.
   */
  private void exposeRootDiagnostics() {
    setNs0Value(
        NodeIds.PublishSubscribe_Diagnostics_DiagnosticsLevel, new Variant(DiagnosticsLevel.Basic));

    initNs0Counter(
        NodeIds.PublishSubscribe_Diagnostics_TotalInformation,
        NodeIds.PublishSubscribe_Diagnostics_TotalInformation_Active,
        NodeIds.PublishSubscribe_Diagnostics_TotalInformation_Classification,
        NodeIds.PublishSubscribe_Diagnostics_TotalInformation_DiagnosticsLevel,
        INFO);
    initNs0Counter(
        NodeIds.PublishSubscribe_Diagnostics_TotalError,
        NodeIds.PublishSubscribe_Diagnostics_TotalError_Active,
        NodeIds.PublishSubscribe_Diagnostics_TotalError_Classification,
        NodeIds.PublishSubscribe_Diagnostics_TotalError_DiagnosticsLevel,
        ERR);
    initNs0Counter(
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateError,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateError_Active,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateError_Classification,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateError_DiagnosticsLevel,
        ERR);
    initNs0Counter(
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalByMethod,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalByMethod_Active,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalByMethod_Classification,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalByMethod_DiagnosticsLevel,
        INFO);
    initNs0Counter(
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalByParent,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalByParent_Active,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalByParent_Classification,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalByParent_DiagnosticsLevel,
        INFO);
    initNs0Counter(
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalFromError,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalFromError_Active,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalFromError_Classification,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateOperationalFromError_DiagnosticsLevel,
        INFO);
    initNs0Counter(
        NodeIds.PublishSubscribe_Diagnostics_Counters_StatePausedByParent,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StatePausedByParent_Active,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StatePausedByParent_Classification,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StatePausedByParent_DiagnosticsLevel,
        INFO);
    initNs0Counter(
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateDisabledByMethod,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateDisabledByMethod_Active,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateDisabledByMethod_Classification,
        NodeIds.PublishSubscribe_Diagnostics_Counters_StateDisabledByMethod_DiagnosticsLevel,
        INFO);

    bindNs0GetValue(NodeIds.PublishSubscribe_Diagnostics_SubError, () -> subErrorValue(""));
    bindNs0GetValue(
        NodeIds.PublishSubscribe_Diagnostics_LiveValues_ConfiguredDataSetWriters,
        () -> countDataValue(writerCounts(null, null)[0]));
    bindNs0GetValue(
        NodeIds.PublishSubscribe_Diagnostics_LiveValues_ConfiguredDataSetReaders,
        () -> countDataValue(readerCounts(null, null)[0]));
    bindNs0GetValue(
        NodeIds.PublishSubscribe_Diagnostics_LiveValues_OperationalDataSetWriters,
        () -> countDataValue(writerCounts(null, null)[1]));
    bindNs0GetValue(
        NodeIds.PublishSubscribe_Diagnostics_LiveValues_OperationalDataSetReaders,
        () -> countDataValue(readerCounts(null, null)[1]));

    bindNs0ResetMethod();
  }

  /**
   * Populate the ns0 PubSubCapabilities object ({@code i=23678}). {@code Max*} are 0 ("no limit"):
   * Milo enforces no fixed component-count cap, and the {@code ReserveIds} allocator only bounds
   * AUTO-assigned ids ({@code 0x8000-0xFFFF}); clients may still supply their own ids across the
   * full range, so the advertised "no limit" agrees with actual behavior. {@code
   * SupportSecurityKeyPull} is true (the SKS pull provider exists), {@code SupportSecurityKeyPush}
   * is false (not supported in this version), and {@code SupportSecurityKeyServer} reflects the
   * SKS-server option.
   */
  private void exposeCapabilities() {
    for (NodeId maxNode : CAPABILITY_MAX_NODES) {
      setNs0Value(maxNode, new Variant(uint(0)));
    }
    setNs0Value(
        NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyPull, new Variant(true));
    setNs0Value(
        NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyPush, new Variant(false));
    setNs0Value(
        NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyServer,
        new Variant(sksServerEnabled));
  }

  /** Set a static counter Value (0) and its Mandatory Active/Classification/DiagnosticsLevel. */
  private void initNs0Counter(
      NodeId valueNode,
      NodeId activeNode,
      NodeId classificationNode,
      NodeId levelNode,
      PubSubDiagnosticsCounterClassification classification) {

    setNs0Value(valueNode, new Variant(uint(0)));
    setNs0Value(activeNode, new Variant(true));
    setNs0Value(classificationNode, new Variant(classification));
    setNs0Value(levelNode, new Variant(DiagnosticsLevel.Basic));
  }

  /** Set the value of an existing ns0 variable node by NodeId; never mints. */
  private void setNs0Value(NodeId nodeId, Variant value) {
    getServer()
        .getAddressSpaceManager()
        .getManagedNode(nodeId)
        .filter(UaVariableNode.class::isInstance)
        .map(UaVariableNode.class::cast)
        .ifPresentOrElse(
            node -> node.setValue(new DataValue(value)),
            () -> LOGGER.warn("ns0 diagnostics node not found: {}", nodeId));
  }

  /**
   * Attach a read-time computed value to an existing ns0 variable node and register its removal for
   * shutdown, so the ns0 skeleton is left inert when the exposure stops.
   */
  private void bindNs0GetValue(NodeId nodeId, Supplier<DataValue> supplier) {
    getServer()
        .getAddressSpaceManager()
        .getManagedNode(nodeId)
        .filter(UaVariableNode.class::isInstance)
        .map(UaVariableNode.class::cast)
        .ifPresentOrElse(
            node -> {
              AttributeFilter filter = AttributeFilters.getValue(ctx -> supplier.get());
              node.getFilterChain().addFirst(filter);
              ns0DiagnosticsCleanup.add(() -> node.getFilterChain().remove(filter));
            },
            () -> LOGGER.warn("ns0 diagnostics node not found: {}", nodeId));
  }

  /** Bind the ns0 root Reset method handler and register its restore for shutdown. */
  private void bindNs0ResetMethod() {
    getServer()
        .getAddressSpaceManager()
        .getManagedNode(NodeIds.PublishSubscribe_Diagnostics_Reset)
        .filter(UaMethodNode.class::isInstance)
        .map(UaMethodNode.class::cast)
        .ifPresentOrElse(
            method -> {
              method.setInvocationHandler(new RootResetMethod(method));
              ns0DiagnosticsCleanup.add(
                  () -> method.setInvocationHandler(MethodInvocationHandler.NOT_IMPLEMENTED));
            },
            () ->
                LOGGER.warn(
                    "ns0 Diagnostics Reset method node not found: {}",
                    NodeIds.PublishSubscribe_Diagnostics_Reset));
  }

  /** Undo the ns0 diagnostics exposure: remove getValue filters and restore the Reset handler. */
  private void teardownNs0Diagnostics() {
    ns0DiagnosticsCleanup.forEach(Runnable::run);
    ns0DiagnosticsCleanup.clear();
  }

  // endregion

  // region diagnostics value computation

  /** The UInt32-clamped value of {@code counter} at {@code path}, with a fresh SourceTimestamp. */
  private DataValue counterDataValue(String path, Counter counter) {
    long raw =
        active ? service.diagnostics().component(path).map(d -> d.counter(counter)).orElse(0L) : 0L;
    return uintDataValue(ComponentDiagnostics.toUInt32Saturating(raw));
  }

  /** The §9.1.11.5 TimeFirstChange of {@code counter} at {@code path} (null while it is 0). */
  private DataValue timeFirstChangeDataValue(String path, Counter counter) {
    DateTime firstChange =
        active
            ? service
                .diagnostics()
                .component(path)
                .flatMap(d -> d.timeFirstChange(counter))
                .orElse(null)
            : null;
    return new DataValue(new Variant(firstChange), StatusCode.GOOD);
  }

  /** Sum this object's own counters of {@code classification} at {@code path}, UInt32-clamped. */
  private DataValue totalValue(
      String path, List<CounterSpec> specs, PubSubDiagnosticsCounterClassification classification) {

    long sum = 0;
    if (active) {
      Optional<ComponentDiagnostics> diagnostics = service.diagnostics().component(path);
      if (diagnostics.isPresent()) {
        for (CounterSpec spec : specs) {
          if (spec.classification() == classification) {
            sum += diagnostics.get().counter(spec.counter());
          }
        }
      }
    }
    return uintDataValue(ComponentDiagnostics.toUInt32Saturating(sum));
  }

  /** True if any descendant component of {@code path} ({@code ""} = root) carries an error. */
  private DataValue subErrorValue(String path) {
    return new DataValue(new Variant(active && hasErrorDescendant(path)), StatusCode.GOOD);
  }

  private boolean hasErrorDescendant(String path) {
    String prefix = path.isEmpty() ? "" : path + "/";
    for (Map.Entry<String, ComponentDiagnostics> entry :
        service.diagnostics().snapshot().entrySet()) {
      String candidate = entry.getKey();
      boolean descendant = prefix.isEmpty() ? !candidate.isEmpty() : candidate.startsWith(prefix);
      if (descendant && hasError(entry.getValue())) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasError(ComponentDiagnostics diagnostics) {
    for (Counter counter : ERROR_COUNTERS) {
      if (diagnostics.counter(counter) > 0) {
        return true;
      }
    }
    return false;
  }

  private static DataValue uintDataValue(long value) {
    return new DataValue(new Variant(uint(value)), StatusCode.GOOD);
  }

  private static DataValue countDataValue(int count) {
    return new DataValue(new Variant(ushort(Math.min(count, 65535))), StatusCode.GOOD);
  }

  /**
   * {@code {configured, operational}} DataSetWriter counts over the current configuration, scoped
   * to {@code connectionFilter}/{@code groupFilter} (null = no filter, e.g. the service root).
   */
  private int[] writerCounts(@Nullable String connectionFilter, @Nullable String groupFilter) {
    PubSubConfiguration2DataType configuration = builtConfiguration;
    int configured = 0;
    int operational = 0;
    if (active && configuration != null) {
      for (PubSubConnectionDataType connection :
          orEmpty(configuration.getConnections(), PubSubConnectionDataType[]::new)) {
        if (connection == null) {
          continue;
        }
        String connectionName = nullToEmpty(connection.getName());
        if (connectionFilter != null && !connectionFilter.equals(connectionName)) {
          continue;
        }
        for (WriterGroupDataType group :
            orEmpty(connection.getWriterGroups(), WriterGroupDataType[]::new)) {
          if (group == null) {
            continue;
          }
          String groupName = nullToEmpty(group.getName());
          if (groupFilter != null && !groupFilter.equals(groupName)) {
            continue;
          }
          for (DataSetWriterDataType writer :
              orEmpty(group.getDataSetWriters(), DataSetWriterDataType[]::new)) {
            if (writer == null) {
              continue;
            }
            configured++;
            if (isOperational(
                service
                    .components()
                    .dataSetWriter(connectionName, groupName, nullToEmpty(writer.getName())))) {
              operational++;
            }
          }
        }
      }
    }
    return new int[] {configured, operational};
  }

  /** {@code {configured, operational}} DataSetReader counts; see {@link #writerCounts}. */
  private int[] readerCounts(@Nullable String connectionFilter, @Nullable String groupFilter) {
    PubSubConfiguration2DataType configuration = builtConfiguration;
    int configured = 0;
    int operational = 0;
    if (active && configuration != null) {
      for (PubSubConnectionDataType connection :
          orEmpty(configuration.getConnections(), PubSubConnectionDataType[]::new)) {
        if (connection == null) {
          continue;
        }
        String connectionName = nullToEmpty(connection.getName());
        if (connectionFilter != null && !connectionFilter.equals(connectionName)) {
          continue;
        }
        for (ReaderGroupDataType group :
            orEmpty(connection.getReaderGroups(), ReaderGroupDataType[]::new)) {
          if (group == null) {
            continue;
          }
          String groupName = nullToEmpty(group.getName());
          if (groupFilter != null && !groupFilter.equals(groupName)) {
            continue;
          }
          for (DataSetReaderDataType reader :
              orEmpty(group.getDataSetReaders(), DataSetReaderDataType[]::new)) {
            if (reader == null) {
              continue;
            }
            configured++;
            if (isOperational(
                service
                    .components()
                    .dataSetReader(connectionName, groupName, nullToEmpty(reader.getName())))) {
              operational++;
            }
          }
        }
      }
    }
    return new int[] {configured, operational};
  }

  private boolean isOperational(Optional<PubSubHandle> handle) {
    return handle
        .map(
            h -> {
              try {
                return service.state(h) == PubSubState.Operational;
              } catch (IllegalArgumentException e) {
                return false;
              }
            })
        .orElse(false);
  }

  /**
   * The connection's ResolvedAddress: for UDP, a best-effort hostname resolution of the configured
   * URL at exposure time; for MQTT (and unresolvable UDP), the configured broker URL verbatim. A
   * documented approximation — there is no transport-SPI accessor for the actually resolved remote
   * address in this version.
   */
  private String resolveAddress(PubSubConnectionDataType connection) {
    String url =
        connection.getAddress() instanceof NetworkAddressUrlDataType urlAddress
            ? urlAddress.getUrl()
            : null;
    if (url == null || url.isBlank()) {
      return "";
    }
    if (UdpTransportProvider.TRANSPORT_PROFILE_URI.equals(connection.getTransportProfileUri())) {
      try {
        String host = URI.create(url).getHost();
        if (host != null) {
          return InetAddress.getByName(host).getHostAddress();
        }
      } catch (Exception e) {
        LOGGER.debug("could not resolve UDP address '{}': {}", url, e.getMessage());
      }
    }
    return url;
  }

  /** Index DataSet ConfigurationVersion by PublishedDataSet name for the writer LiveValues. */
  private static Map<String, ConfigurationVersionDataType> dataSetVersions(
      PubSubConfiguration2DataType configuration) {

    var versions = new HashMap<String, ConfigurationVersionDataType>();
    for (PublishedDataSetDataType dataSet :
        orEmpty(configuration.getPublishedDataSets(), PublishedDataSetDataType[]::new)) {
      if (dataSet == null || dataSet.getName() == null) {
        continue;
      }
      DataSetMetaDataType metaData = dataSet.getDataSetMetaData();
      if (metaData != null && metaData.getConfigurationVersion() != null) {
        versions.put(dataSet.getName(), metaData.getConfigurationVersion());
      }
    }
    return versions;
  }

  // endregion

  // region diagnostics Reset method handlers

  /** Reset a per-component diagnostics object's counters, guarded by checkConfigure. */
  private final class ComponentResetMethod extends PubSubDiagnosticsType.ResetMethod {

    private final String path;

    ComponentResetMethod(UaMethodNode node, String path) {
      super(node);
      this.path = path;
    }

    @Override
    protected void invoke(InvocationContext context) throws UaException {
      requireConfigureSession(context);
      service.diagnostics().reset(path);
    }
  }

  /**
   * Reset for the ns0 root diagnostics object. Its own counters (the six State*) are not
   * engine-backed at the service level, so there is nothing to zero; §9.1.11.3 Reset acts only on
   * this object's counters, never on the child diagnostics objects. Authorized calls return Good.
   */
  private final class RootResetMethod extends PubSubDiagnosticsType.ResetMethod {

    RootResetMethod(UaMethodNode node) {
      super(node);
    }

    @Override
    protected void invoke(InvocationContext context) throws UaException {
      requireConfigureSession(context);
    }
  }

  // endregion

  private static <T> T[] orEmpty(T @Nullable [] array, IntFunction<T[]> arrayFactory) {
    return array != null ? array : arrayFactory.apply(0);
  }

  private static String nullToEmpty(@Nullable String value) {
    return value != null ? value : "";
  }
}
