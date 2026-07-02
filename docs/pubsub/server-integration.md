# Server Integration

This page covers `milo-sdk-pubsub-server`, the module that connects a PubSub runtime to an
`OpcUaServer` address space. Read it if you want to publish live node values without writing a
data source, or have received DataSets written into variable nodes. It assumes the basics from
[getting started](getting-started.md); the [configuration model](configuration.md) page is useful
as a reference alongside it.

```xml
<dependency>
    <groupId>org.eclipse.milo</groupId>
    <artifactId>milo-sdk-pubsub-server</artifactId>
</dependency>
```

The artifact is managed by `milo-bom` and depends on `milo-sdk-pubsub` and `milo-sdk-server`.

A standalone `PubSubService` knows nothing about servers: you bind a `PublishedDataSetSource` to
feed each dataset and a `DataSetListener` to consume what arrives. `ServerPubSub` wires both ends
to the address space for you:

- a published dataset whose fields all point at nodes is fed automatically from live node values
  (the auto-source) — no source code to write;
- a reader configured with TargetVariables writes received field values into variable nodes;
- optionally, the PubSub configuration and live component states are exposed as an information
  model under the server's ns0 `PublishSubscribe` object — read-only by default, but with opt-in
  remote configuration (the Part 14 file model), a diagnostics tree, and status events.

One honest limit before you design around this module: `ServerPubSub` builds its runtime
configuration internally and has no hook to register transport providers, so it is UDP/UADP only
in this version. See [what the server integration does not do](#what-the-server-integration-does-not-do).

## Attach and lifecycle

`ServerPubSub.attach(OpcUaServer, PubSubConfig)` (or the three-argument overload taking
`ServerPubSubOptions`) returns a `ServerPubSub` that is not yet started. Start it with
`startup()`; stop it with `close()` (or the async `shutdown()`). From
`ServerSourcePublisherExample`:

```java
// Because every field of "demo-nodes" is a NodeFieldAddress, attach() auto-binds an
// address-space source for it: each publish cycle pulls a fresh snapshot of the live
// node values. attach() also eagerly resolves every NodeFieldAddress against the
// server's NamespaceTable, failing fast on an unresolvable namespace.
ServerPubSub serverPubSub = ServerPubSub.attach(server, config);

serverPubSub.startup().get();
```

Attach validates eagerly: every `NodeFieldAddress` in the configuration — dataset field sources
and TargetVariables targets alike — is resolved against the server's `NamespaceTable`, and
TargetVariables index ranges are parsed. A failure throws `PubSubConfigValidationException`
naming the offending element. Node *existence* is deliberately not checked at attach time: a
field whose namespace resolves but whose node does not exist publishes `Bad_NodeIdUnknown` for
that field at runtime instead.

### PubSub does not need a started server

`ServerPubSub` is decoupled from the server's client-facing lifecycle. Attach is legal any time
after the `OpcUaServer` constructor returns, and the PubSub runtime operates independently of the
server's endpoints and transports. Both server examples exploit this and never start their
server at all:

```java
// An endpoint-less OpcUaServer that is never started: the address space (including ns0)
// loads in the constructor, which is all ServerPubSub needs. Attaching to a real, started
// server works exactly the same way.
OpcUaServerConfig serverConfig =
    OpcUaServerConfig.builder()
        .setApplicationUri("urn:eclipse:milo:examples:pubsub:server-source")
        .setApplicationName(LocalizedText.english("PubSub server-source example"))
        .setProductUri("urn:eclipse:milo:examples:pubsub")
        .build();

var server =
    new OpcUaServer(
        serverConfig,
        transportProfile -> {
          throw new IllegalStateException(
              "this example server has no transports: " + transportProfile);
        });
```

On a real, started server everything behaves identically. Two lifecycle details are worth
knowing either way:

- The ns0 address space loads in the `OpcUaServer` constructor and takes a few seconds. When you
  run the examples, the gap between launching and the first log line is mostly this, not PubSub.
- Do not call `server.shutdown()` on a server that was never started — it throws. The example's
  teardown reflects this:

```java
updater.shutdownNow();
serverPubSub.close();
namespace.shutdown();
// the OpcUaServer was never started, so there is no server.shutdown() to call
```

The caller owns shutdown ordering. The runtime borrows the server's executors, so close the
`ServerPubSub` before shutting down a started server.

## Publishing node values: the auto-source

`ServerSourcePublisherExample` publishes three variable nodes (Temperature, Pressure, Counter)
over UADP/UDP while a background task updates them every 500 ms. The interesting part is what it
does *not* contain: there is no `PublishedDataSetSource` anywhere in the file.

The trigger is the shape of the dataset. At attach time, a published dataset is auto-bound to an
address-space source if and only if its field list is non-empty and **every** field's source is a
`NodeFieldAddress`:

```java
// Field order is wire order, and ALL fields use NodeFieldAddress: a dataset with mixed or
// key-only field addresses would not be auto-bound and would need an explicit source.
PublishedDataSetConfig dataSet =
    PublishedDataSetConfig.builder("demo-nodes")
        .field(
            FieldDefinition.builder("Temperature")
                .source(nodeAddress(server, temperatureNodeId))
                .dataType(NodeIds.Double)
                .build())
        .field(
            FieldDefinition.builder("Pressure")
                .source(nodeAddress(server, pressureNodeId))
                .dataType(NodeIds.Double)
                .build())
        .field(
            FieldDefinition.builder("Counter")
                .source(nodeAddress(server, counterNodeId))
                .dataType(NodeIds.Int32)
                .build())
        .build();
```

```java
private static NodeFieldAddress nodeAddress(OpcUaServer server, NodeId nodeId) {
  return NodeFieldAddress.of(nodeId, AttributeId.Value, server.getNamespaceTable());
}
```

The auto-bound source pulls a fresh snapshot of the node values once per publish cycle (one
batched internal read), so writing to the nodes — `node.setValue(...)` — is all it takes to
change what goes on the wire. The example does this from a background task; nothing about the
publish cycle needs to know.

The rule's edges, precisely:

- A dataset that mixes `NodeFieldAddress` fields with key-only fields, or has only key fields, is
  **not** auto-bound. If no source is bound for it, `startup()` fails with
  `Bad_ConfigurationError` naming the unbound dataset.
- A source you supply yourself via `ServerPubSubOptions.builder().bindings(...)` always wins over
  the automatic binding, even for an all-`NodeFieldAddress` dataset.

The subscribing side of this pair, `ServerSourceSubscriberExample`, is a plain standalone
`PubSubService` — no server involved — whose `DataSetMetaDataConfig` mirrors the publisher's
dataset. Field names, order, and types must match; nothing else needs pinning, because
`PublishedDataSetConfig` and `DataSetMetaDataConfig` both default the configuration version to
(1, 1), so the reader's version check passes without you setting versions or field UUIDs on
either side.

### Run it

Build the examples module once, then run each program from the repository root in its own
terminal:

```sh
mvn -q -pl milo-examples/pubsub-examples -am install -DskipTests
```

```sh
mvn -pl milo-examples/pubsub-examples exec:java \
    -Dexec.mainClass=org.eclipse.milo.examples.pubsub.server.ServerSourcePublisherExample
```

```sh
mvn -pl milo-examples/pubsub-examples exec:java \
    -Dexec.mainClass=org.eclipse.milo.examples.pubsub.server.ServerSourceSubscriberExample
```

Do not add `-q` to the `exec:java` commands. The example runs inside Maven's JVM, where SLF4J
binds to Maven's own logger, and `-q` caps that logger at errors — the example runs fine but
prints nothing, which looks exactly like a hang. Keep `-q` on the build step only.

The publisher logs a startup line and then an update every ~5 seconds:

```
publishing "demo-nodes" (publisherId=4001, writerGroupId=1, dataSetWriterId=1) to 127.0.0.1:15120 every 500 ms
update #10: Temperature=24.33, Pressure=1015.42, Counter=10
```

The subscriber logs one line per delivered DataSet, roughly every 500 ms:

```
[received] dataSet=demo-nodes publisherId=4001 writerGroupId=1 dataSetWriterId=1 Temperature=22.94, Pressure=1014.02, Counter=24
[received] dataSet=demo-nodes publisherId=4001 writerGroupId=1 dataSetWriterId=1 Temperature=22.5, Pressure=1013.9, Counter=25
```

The continuously changing values are the point: the auto-source reads the live nodes each cycle,
not a captured snapshot. Both connections pin `discoveryAddress` to distinct loopback ports
(15121 and 15122) — without an explicit discovery address the engine binds UDP 4840 and joins
multicast group 224.0.2.14, and two processes on one host cannot share a discovery port.

## Writing received values into nodes: TargetVariables

The reverse direction: `ServerTargetSubscriberExample` is an `OpcUaServer` whose Temperature and
Counter nodes are written by a PubSub reader, fed by the standalone
`ServerTargetPublisherExample`.

The mapping is Part 14 TargetVariables, configured on the reader with
`DataSetReaderConfig.subscribedDataSet(TargetVariablesConfig)`. Select received fields with a
`FieldSelector` (`byName`, `byId`, or `byIndex`) and point each at a node:

```java
// Part 14 §6.2.11.1 TargetVariables: select received fields by name and write them to the
// Value attribute of server nodes. StatusCodes and source timestamps received on the wire
// pass through to the target nodes (Table 80).
TargetVariablesConfig targetVariables =
    TargetVariablesConfig.builder()
        .map(
            FieldSelector.byName("temperature"),
            TargetVariableConfig.builder()
                .target(
                    NodeFieldAddress.of(
                        temperatureNodeId, AttributeId.Value, server.getNamespaceTable()))
                .build())
        .map(
            FieldSelector.byName("counter"),
            TargetVariableConfig.builder()
                .target(
                    NodeFieldAddress.of(
                        counterNodeId, AttributeId.Value, server.getNamespaceTable()))
                .build())
        .build();
```

```java
.readerGroup(
    ReaderGroupConfig.builder("readers")
        .dataSetReader(
            DataSetReaderConfig.builder("reader")
                .publisherId(PUBLISHER_ID)
                .writerGroupId(WRITER_GROUP_ID)
                .dataSetWriterId(DATA_SET_WRITER_ID)
                .dataSetMetaData(metaData)
                .metadataPolicy(MetadataPolicy.REQUIRE_CONFIGURED)
                .subscribedDataSet(targetVariables)
                .build())
        .build())
```

Note the connection has no `.publisherId(...)` — a PublisherId is only required on connections
that have writer groups, and this side only reads.

### Target nodes should allow nulls

The Part 14 state-change rows (reader Disabled, Error, and so on) write status-only updates whose
value is a null Variant. A Milo variable node rejects null writes with `Bad_TypeMismatch` unless
you allow them, so create target nodes accordingly (from the example's `DemoNamespace`):

```java
// The Part 14 Table 80 Disabled-handling and state-change rows write null Variants;
// without allowNulls the server's AttributeWriter rejects them with Bad_TypeMismatch.
node.setAllowNulls(true);
```

Target writes also respect access level: a target node without `CurrentWrite` fails every write
with `Bad_NotWritable` (counted, see below) and is never written.

### Status and timestamp pass through

If the publisher's writer encodes fields as full DataValues, the received StatusCode and source
timestamp are written into the target node along with the value. `ServerTargetPublisherExample`
opts in with its field content mask:

```java
private static final DataSetFieldContentMask FIELD_MASK =
    DataSetFieldContentMask.of(
        DataSetFieldContentMask.Field.StatusCode, DataSetFieldContentMask.Field.SourceTimestamp);
```

With this mask the source timestamps you read off the target nodes are the publisher's — the time
the value was sampled, not the time it was written into the subscriber's address space.

### Monitoring target writes

Failed target writes never stop the flow; they are counted per target.
`ServerPubSub.targetWriteErrors()` returns a map keyed `"<reader-path>/<targetNodeId>"` to error
counts. The example polls it once a second:

```java
Map<String, Long> targetWriteErrors = serverPubSub.targetWriteErrors();
if (!targetWriteErrors.isEmpty()) {
  logger.warn("targetWriteErrors: {}", targetWriteErrors);
}
```

### Watching both layers at once

`ServerPubSub.runtime()` exposes the full `PubSubService`, so everything from the standalone API —
listeners, diagnostics, reconfiguration — is available alongside the server integration. The
example uses it to observe the same data at two layers, which is a useful pattern when bringing
up any TargetVariables configuration:

```java
// ServerPubSub.runtime() exposes the full PubSubService; a DataSetListener shows DataSets
// arriving on the wire, independent of the TargetVariables writes into the address space.
serverPubSub.runtime().addDataSetListener(this::onDataSetReceived);
```

The listener logs a `[received]` line for each DataSet arriving on the wire; a scheduled task
reads the target nodes once a second and logs a `[node]` line. If `[received]` lines appear but
`[node]` values never change, the problem is in your TargetVariables mapping (selector names,
target addresses, writability), not the network.

### Run it

Start the subscriber **first**. The subscribing side binds the UDP data port, and anything
published before that bind exists is silently lost — no error is reported anywhere. (For a
continuously publishing pair this only costs the earliest samples, but make it a habit; it
matters whenever the first messages carry meaning.)

```sh
mvn -q -pl milo-examples/pubsub-examples -am install -DskipTests
```

```sh
mvn -pl milo-examples/pubsub-examples exec:java \
    -Dexec.mainClass=org.eclipse.milo.examples.pubsub.server.ServerTargetSubscriberExample
```

Wait for `ServerPubSub started, reader listening on opc.udp://127.0.0.1:15130` (about ten
seconds — Maven and JVM startup plus the ns0 load), then in a second terminal:

```sh
mvn -pl milo-examples/pubsub-examples exec:java \
    -Dexec.mainClass=org.eclipse.milo.examples.pubsub.server.ServerTargetPublisherExample
```

Again, no `-q` on the `exec:java` steps. The subscriber terminal then shows both views
interleaved — about two `[received]` lines per second and one `[node]` line per second:

```
[received] publisherId=UInt16Id[value=5001] writerGroupId=1 dataSetWriterId=1 fields: temperature=24.817790927085966, counter=13
[node] Temperature=24.316046833244368 (status=StatusCode[name=Good, ...], sourceTime=...) Counter=21 (status=Good, ...)
```

The `[node]` lines show Good status and the publisher's source timestamps landing on the nodes —
the pass-through described above, observable end to end.

## The information model

Opt in with `ServerPubSubOptions.builder().exposeInformationModel(true)` (default `false`). At
`startup()`, `ServerPubSub` populates the ns0 `PublishSubscribe` object and grafts a node tree
describing the configuration onto it: connections, writer and reader groups, writers, readers,
and published datasets, with their addresses, message settings, and properties.

What you get, and the edges:

- The config-derived nodes are read-only by default. The tree is rebuilt incrementally when you
  reconfigure through `ServerPubSub.reconfigure(...)` (the info-model-aware reconfigure path added
  in this version) or when an authorized client applies a remote CloseAndUpdate — affected
  connections and datasets are torn down and rebuilt, untouched subtrees are left alone. A bare
  `runtime().reconfigure(...)` still bypasses the model, so use `ServerPubSub.reconfigure(...)`
  when you want the browse tree to keep up.
- Per-component `Status/State` variables are live — they track the runtime state machine, so a
  browsing client sees readers go `Operational` and components go `Disabled` as it happens.
- `SupportedTransportProfiles` advertises the UDP-UADP profile only, matching what the server
  integration actually runs.
- The ns0 method nodes are backed only when you opt in. `Enable`/`Disable` on the per-component
  Status objects come alive when both `exposeInformationModel(true)` and
  `allowRemoteConfiguration(true)` are set; the `PubSubConfiguration` file methods come alive with
  `allowRemoteConfiguration(true)` (below); the per-component diagnostics tree and `Reset` come
  alive with `diagnosticsEnabled(true)`; and `GetSecurityKeys` comes alive with
  `sksServerEnabled(true)`. The deprecated imperative methods (`AddConnection`, `RemoveConnection`,
  the SKS management methods) are never backed and return `Bad_NotImplemented`.

## Remote configuration

By default everything above is read-only. Set
`ServerPubSubOptions.builder().allowRemoteConfiguration(true)` and `ServerPubSub` backs the
standard Part 14 §9.1.3.7 configuration file — the ns0 `PubSubConfiguration` FileType object
(`i=25451`) under `PublishSubscribe` — so an authorized client can read the running configuration,
edit it, and apply the result atomically. This is the modern, file-based configuration interface;
Milo does not implement the older imperative methods (`AddConnection` and friends), which stay
unbacked and return `Bad_NotImplemented`.

The file behaves like any OPC UA FileType. A client `Open`s it (read, or read-write), `Read`s or
`Write`s bytes, moves the cursor with `GetPosition`/`SetPosition`, and `Close`s it. The bytes are a
`.uabinary` document — a `UABinaryFileDataType` wrapping a `PubSubConfiguration2DataType` — for
which `milo-sdk-pubsub` ships a codec, `PubSubConfigFiles.read`/`write`, that you can also use to
persist a config to disk. A read snapshot is materialized at `Open` and carries a
`ConfigurationVersion` (a VersionTime) that a client is expected to compare before writing back,
per the spec's read-modify-write flow.

Applying a change is `CloseAndUpdate`, and it is element-oriented rather than whole-file. The client
passes a list of ConfigurationReferences — each naming one element (a connection, group, writer,
reader, dataset, or SecurityGroup) and one operation: Add, Match, Add+Match, Modify, or Remove —
with the element bodies supplied in the written file. The applier works them against the live
configuration: Removes first, parents before children; an Add auto-assigns a name, PublisherId,
WriterGroupId, or DataSetWriterId when the client leaves them blank. The `requireCompleteUpdate`
argument picks the failure mode — `true` is atomic (apply only if every reference succeeded),
`false` applies the survivors. Either way the change lands as one `reconfigure(DISABLE_AFFECTED)` of
the running engine (affected components bounce through the state machine visibly, untouched ones
keep running), and the method returns a per-reference status array plus the NodeIds of the objects
it created or matched. The whole-config validity checks — id uniqueness, PublisherId presence, the
delta-frame/RawData/security rules — run at that reconfigure step: a config that fails them surfaces
as the method status with the live configuration left unchanged, even in partial mode.

`ReserveIds` supports a client that wants ids assigned before it writes the file. It reserves a
block of WriterGroupIds and DataSetWriterIds (and hands back a DefaultPublisherId typed for the
transport profile) that stay reserved for the life of the session and are consumed when they reach
the applied config. Auto-assignment and `ReserveIds` both draw from the `0x8000`-`0xFFFF` range and
honor every session's outstanding reservations, so two clients configuring concurrently never
collide.

Authorization runs on every handler. Each requires a session — a session-less internal call is
`Bad_UserAccessDenied` — and consults `PubSubMethodAuthorizer.checkConfigure`; references that touch
a SecurityGroup additionally consult `checkSksAdmin`. The default authorizer allows when no
`RoleMapper` is configured (the surface is opt-in to begin with) and enforces the well-known
`ConfigureAdmin` / `SecurityKeyServerAdmin` roles when one is; supply your own with
`ServerPubSubOptions.builder().methodAuthorizer(...)`. A successful `CloseAndUpdate` persists the new
configuration through the configured `PubSubConfigurationStore` (below); a save failure is logged
and retried on the next mutation, and never undoes the applied change. Editing a SecurityGroup's
`SecurityPolicyUri` or `KeyLifetime` this way also invalidates that group's live keys, forcing a
fresh SKS fetch (§6.2.12.2).

Enable and Disable are the other writable surface, and they live on the information model rather than
the file. When both `allowRemoteConfiguration(true)` and `exposeInformationModel(true)` are set, the
`Enable`/`Disable` methods on each component's Status object are backed: they enforce the §9.1.10
current-state rules (`Enable` requires the component `Disabled`, `Disable` requires it not
`Disabled`, else `Bad_InvalidState`), consult `checkConfigure`, and — unlike a `CloseAndUpdate` — do
not persist, because enabling or disabling a component is not a configuration mutation.

What is not implemented, all returning `Bad_NotImplemented`: the deprecated imperative methods
(`AddConnection`, `RemoveConnection`, and the rest), the dataset-binding methods (they mutate
owner-supplied source and target bindings), key push (`SetSecurityKeys`), and the SecurityGroup
management methods (`AddSecurityGroup` and friends).

## Diagnostics and status events

Two further opt-ins expose the runtime's health, both off by default.

`diagnosticsEnabled(true)` — which also needs `exposeInformationModel(true)`, since the nodes hang
off the component tree — backs the Part 14 diagnostics model. The ns0 `PublishSubscribe/Diagnostics`
root (`i=17409`) gets its `DiagnosticsLevel` (Basic, read-only) and service-level counts, and each
component in the exposed tree gains a `Diagnostics` object: a `Counters` folder holding that
component's counters (messages sent and received, failed transmissions, decode and decryption
errors, the six state-transition counters), a `TotalInformation`/`TotalError` roll-up, and a `Reset`
method that zeroes the engine counters for that path (guarded by `checkConfigure`). Values are read
live off `runtime().diagnostics()` and clamped to UInt32 at the wire, with the SourceTimestamp
advancing at the cap so a saturated counter still looks alive. `ResolvedAddress` on a connection is a
documented approximation — the configured URL, with UDP hostnames resolved at read time — not the
transport's actual peer address. Alongside the diagnostics tree, `PubSubCapabilities` (`i=23678`) is
filled in: every `Max*` limit reads 0 (no fixed cap — Milo imposes none), `SupportSecurityKeyPull`
is true, `SupportSecurityKeyPush` is false, and `SupportSecurityKeyServer` follows `sksServerEnabled`.

`statusEventsEnabled(true)` is independent of the information model — the events fire on the Server
Object's event notifier, so a client subscribed to Events there receives them whether or not the
PubSub nodes exist. State changes become `PubSubStatusEventType` events (`i=15535`) and send failures
become `PubSubCommunicationFailureEventType` events (`i=15563`, carrying the real un-flattened status
code). Severities follow the Part 14 bands: informational (100) for ordinary transitions, Error (500)
for an entry into `Error` and for every communication failure. A communication failure is reported at
most once per failure episode per component and re-armed when the component next recovers to
`Operational`, so a broker that stays down does not flood the event stream; teardown transitions
during shutdown produce nothing.

## Persisting configuration

`ServerPubSubOptions.builder().configurationStore(...)` accepts a `PubSubConfigurationStore`, a
two-method interface you implement — no implementation ships with the SDK:

```java
public interface PubSubConfigurationStore {

  @Nullable PubSubConfiguration2DataType load();

  void save(PubSubConfiguration2DataType value);
}
```

The semantics at attach are load-wins, save-once: if `load()` returns a non-null configuration,
it wins and the config passed to `attach` is ignored; if `load()` returns null, the attach config
is used and saved exactly once via `save()`. A `save` failure is logged and non-fatal; a `load`
failure propagates out of `attach`. Once running, a successful remote `CloseAndUpdate` (above)
saves the new configuration automatically. Changes you make yourself through `runtime()` are
**not** saved — if you reconfigure a running service in code and want it persisted, call your store
yourself.

## What the server integration does not do

These are hard limits of this version, listed with the exact failure mode so you can recognize
them:

- **MQTT and custom transports.** `ServerPubSub` cannot register transport providers, so only the
  built-in UDP transport (UADP mapping) is available. An enabled MQTT connection in the attached
  config fails `startup()` with `Bad_ConfigurationError` ("no TransportProvider supports
  connection ..."); a disabled MQTT connection passes startup but is rejected with the same
  status if you later enable it. For PubSub over MQTT, use the standalone `PubSubService` with
  `MqttTransportProvider` registered — and bridge to the address space yourself if needed.
- **Deprecated imperative configuration methods.** The file model in
  [Remote configuration](#remote-configuration) is the supported way to reconfigure over OPC UA.
  The older imperative ns0 methods — `AddConnection`, `RemoveConnection`, the dataset-binding
  methods, the SecurityGroup management methods, and key push (`SetSecurityKeys`) — are not
  implemented and return `Bad_NotImplemented`, whether or not remote configuration is enabled.
- **Standalone SubscribedDataSet references.** A reader whose SubscribedDataSet is a
  `StandaloneSubscribedDataSetRef` carrying TargetVariables gets no automatic writes: attach
  succeeds, the targets are still validated, a WARN is logged, and nothing is written at runtime.
  Configure the `TargetVariablesConfig` directly on the reader instead, as shown above.
