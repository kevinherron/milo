# milo-sdk-pubsub

The core OPC UA Part 14 PubSub module: the configuration model, the runtime engine, the
UADP and JSON message mappings, PubSub message security, and the built-in UDP transport.

Everything else in Milo is client/server — a session between two parties, with the server
tracking state per client. PubSub is the other shape: a publisher pushes NetworkMessages
onto the network on a fixed cycle, addressed to no one in particular, and any number of
subscribers decode the ones they care about. This module implements that model standalone.
`PubSubService`, created from a `PubSubConfig` and optional `PubSubBindings` (data sources,
listeners, key providers), publishes and subscribes with no OPC UA client or server
involved. Accordingly, the module depends only on `milo-stack-core` and
`milo-encoding-json`: a standalone publisher or subscriber pulls in no client/server
machinery at all.

## What's inside

| Package (`org.eclipse.milo.opcua.sdk.pubsub…`) | Contents                                                                                                                                                                                                                                                                    |
|------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| (root)                                         | The public runtime API: `PubSubService`, `PubSubBindings`, `PubSubServiceConfig`, data-flow types for publishing (`PublishedDataSetSource`, `DataSetSnapshot`) and subscribing (`DataSetListener`, `DataSetReceivedEvent`), plus state, metadata, and diagnostics listeners |
| `.config`                                      | The immutable, builder-built configuration model — connections, groups, writers, readers, published and subscribed datasets, security groups — with validation and round-trip mapping to the Part 14 `PubSubConfiguration2DataType`                                         |
| `.uadp`                                        | UADP binary message mapping (Part 14 §7.2.2): encoder, decoder, chunk reassembly, and the UADP discovery model (metadata probes and announcements)                                                                                                                          |
| `.json`                                        | JSON message mapping (Part 14 §7.2.5): `ua-data` and `ua-metadata` NetworkMessages with the 1.05 VerboseEncoding field collapse rules                                                                                                                                       |
| `.security`                                    | Message security (Part 14 §7.2.4.4.3, §8.3.2): both PubSub AES-CTR SecurityPolicies, the `SecurityKeyProvider` SPI, and `StaticSecurityKeyProvider` for pre-shared keys                                                                                                     |
| `.transport`                                   | The `TransportProvider` SPI that external transports plug into                                                                                                                                                                                                              |
| `.transport.udp`                               | The built-in Netty-based UDP transport: unicast and multicast datagrams for the `pubsub-udp-uadp` profile                                                                                                                                                                   |
| `.internal`                                    | The engine — not public API, may change without notice                                                                                                                                                                                                                      |

## When to use it

This module is the one every PubSub application needs, and it is sufficient by itself for
brokerless UDP: UADP publishers and subscribers (unicast or multicast), delta frames, UDP
metadata discovery, live reconfiguration, sequence-number tracking, and signed/encrypted
messages with statically configured keys.

Three companion modules extend it, each kept separate so its dependencies stay out of the
core artifact:

- [`milo-sdk-pubsub-mqtt`](../sdk-pubsub-mqtt) — MQTT broker transport (UADP or JSON),
  built on the HiveMQ MQTT client.
- [`milo-sdk-pubsub-server`](../sdk-pubsub-server) — `ServerPubSub`, which attaches the
  runtime to an `OpcUaServer` so datasets publish live node values and received values are
  written back into nodes.
- [`milo-sdk-pubsub-sks`](../sdk-pubsub-sks) — a Security Key Service pull client that
  fetches message security keys over an OPC UA client session instead of static
  configuration.

All four artifacts are managed by `milo-bom`.

Not everything in Part 14 is implemented: event publishing, outbound NetworkMessage
chunking, `RawData` field encoding, PromotedFields, and the Ethernet/AMQP/WebSocket
transports are not supported, and unsupported configuration is either rejected with a
named error or documented as ignored. The per-feature matrix is in
[Limitations and interop](../../docs/pubsub/limitations-and-interop.md) — read it before
depending on a Part 14 feature.

## Where to start

The full documentation set lives in [docs/pubsub](../../docs/pubsub/README.md).
[Getting started](../../docs/pubsub/getting-started.md) walks a complete UDP/UADP
publisher and subscriber pair built on this module alone, and
[milo-examples/pubsub-examples](../../milo-examples/pubsub-examples) has runnable examples
for every scenario, all working with zero arguments on one machine.
