# milo-sdk-pubsub-mqtt

MQTT broker transport for OPC UA PubSub (OPC UA Part 14 §7.3.4), built on the HiveMQ MQTT
client. It lives in its own module so the core [`milo-sdk-pubsub`](../sdk-pubsub) artifact
carries no MQTT or HiveMQ dependency; use it when your publishers and subscribers talk
through an MQTT broker rather than directly over UDP.

The module contributes one implementation of the core module's transport SPI:
`MqttTransportProvider`. A single provider instance serves both MQTT transport profiles —
`pubsub-mqtt-uadp` (binary) and `pubsub-mqtt-json` — because the message mapping is
orthogonal to the transport; the provider is selected for any connection configured with
`MqttConnectionConfig`. MQTT is not auto-discovered, so registration is explicit:

```java
PubSubService service =
    PubSubService.create(
        config,
        bindings,
        PubSubServiceConfig.builder()
            .transportProvider(MqttTransportProvider.create())
            .build());
```

One MQTT client is opened per connection and shared by that connection's publisher and
subscriber channels. By default the provider connects with MQTT 5.0 and falls back to
3.1.1 when the broker rejects it; a version can be pinned with the `0:MqttVersion`
connection property. TLS (`mqtts://` URIs) and username/password authentication come from
the connection's `BrokerSecurityConfig`. Topic names follow the Part 14 topic tree unless
a queue name is configured explicitly, JSON metadata can be published retained so
late-joining subscribers decode immediately, and broker outages are handled automatically:
the connection drops to `Error` (pausing its writers and readers), and the built-in
reconnect recovers it, re-issuing subscriptions and re-publishing retained metadata.

Current limits, all detailed in the [MQTT documentation](../../docs/pubsub/mqtt.md):
MQTT-over-WebSocket (`wss://`) is not supported, client TLS keys must be unencrypted
PKCS#8, and credentials are per-connection — the Part 14 per-queue credential lookups are
not consulted. Note also that [`ServerPubSub`](../sdk-pubsub-server) does not support MQTT
connections yet; this transport is for the standalone `PubSubService`.

[docs/pubsub/mqtt.md](../../docs/pubsub/mqtt.md) covers broker URIs, the topic tree, QoS,
client identity, outage behavior, and TLS in depth. Runnable MQTT examples — including
scenarios with an embedded broker, so no external infrastructure is needed — are in
[milo-examples/pubsub-examples](../../milo-examples/pubsub-examples).
