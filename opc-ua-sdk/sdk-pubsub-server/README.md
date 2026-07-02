# milo-sdk-pubsub-server

Server integration for OPC UA Part 14 PubSub: `ServerPubSub` attaches the standalone
PubSub runtime from [`milo-sdk-pubsub`](../sdk-pubsub) to an `OpcUaServer` and wires it
into the server's address space. Use it when the data you publish lives in server nodes,
when received data should land in server nodes, or when the server should expose the
Part 14 information model — for a publisher or subscriber with no OPC UA server, the core
module alone is the better fit.

The entry point is one call:

```java
ServerPubSub serverPubSub = ServerPubSub.attach(server, config);
serverPubSub.

startup().

get();
```

Attach connects configuration to the address space in both directions. PublishedDataSets
whose fields are all addressed by `NodeFieldAddress` are automatically bound to a source
that snapshots the live node values each publish cycle — publishing node values requires
no source code at all. In the other direction, DataSetReaders whose SubscribedDataSet is a
`TargetVariablesConfig` automatically write received fields into the mapped address-space
variables. Every node address in the configuration is resolved against the server's
namespace table eagerly, so a bad namespace URI fails at attach rather than at publish
time.

Everything beyond that is opt-in through `ServerPubSubOptions`:

- `exposeInformationModel` publishes the read-only ns0 PublishSubscribe information model
  mirroring the running configuration;
- a `PubSubConfigurationStore` persists the configuration across restarts (a stored
  configuration wins over the one passed to attach);
- `diagnosticsEnabled` backs the ns0 PubSub diagnostics tree and capabilities objects;
- `statusEventsEnabled` bridges component state changes and communication failures to
  OPC UA events (Part 14 §9.1.13);
- `allowRemoteConfiguration` lets OPC UA clients reconfigure PubSub through the ns0
  PubSubConfiguration file model (Open/Read/Write/CloseAndUpdate and ReserveIds) plus the
  Enable/Disable methods — the deprecated imperative methods (`AddConnection`, …) remain
  `Bad_NotImplemented`;
- `sksServerEnabled` makes the server act as a minimal Security Key Service, implementing
  the well-known `GetSecurityKeys` method for the SecurityGroups in the attach-time
  configuration, with access gated by a `PubSubMethodAuthorizer`.

The main limitation in this version: `ServerPubSub` supports UDP/UADP connections only.
An MQTT connection is rejected with `Bad_ConfigurationError`; MQTT works with the
standalone `PubSubService` and [`milo-sdk-pubsub-mqtt`](../sdk-pubsub-mqtt). Details and
the full behavior reference — attach semantics, TargetVariables rules, remote
configuration, diagnostics — are in
[docs/pubsub/server-integration.md](../../docs/pubsub/server-integration.md), and runnable
examples covering both directions (the `ServerSource*` and `ServerTarget*` pairs) are in
[milo-examples/pubsub-examples](../../milo-examples/pubsub-examples).
