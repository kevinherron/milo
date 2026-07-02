# milo-sdk-pubsub-sks

Security Key Service (SKS) pull client for OPC UA PubSub message security (OPC UA Part 14
§5.4.5.3, §6.2.5.4, §8.3.2). `SksSecurityKeyProvider` implements the `SecurityKeyProvider`
SPI from [`milo-sdk-pubsub`](../sdk-pubsub) by calling the `GetSecurityKeys` method on an
SKS over a SignAndEncrypt OPC UA client session — so a publisher or subscriber can
participate in signed and encrypted PubSub with keys distributed centrally, instead of
statically configured pre-shared keys.

This lives in its own module because of how Part 14 models SKS references. A configured
`SecurityKeyServices` entry is an SKS identity record — an ApplicationUri plus
DiscoveryUrls, with the endpoint URL explicitly required to be empty (§6.2.5.4 Table 40) —
not a connectable endpoint. Turning that record into keys requires the discovery service,
an `OpcUaClient` session with certificate trust validation, and identity providers, none
of which the core PubSub module may depend on. This module carries the `milo-sdk-client`
dependency so the core stays client-free.

The provider handles the full resolution chain: it tries entries in array order, runs
GetEndpoints against each discovery URL, keeps SignAndEncrypt endpoints whose
ApplicationUri matches, honors a configured SecurityPolicyUri (otherwise ranking by
security level), and authenticates per the entry's UserIdentityTokens — Anonymous, or
UserName with credentials looked up in the core module's `KeyCredentialStore`. The
resolved session is cached across fetches and re-resolved with failover after any failure.
A tolerance fallback accepts the shape common in the open62541 ecosystem (a filled
endpoint URL and no discovery URLs) by using the endpoint URL as a discovery target, with
a warning.

Construct one provider per SecurityGroup — the entries, the credential identity, and the
cached session are per-group state — and bind it via `PubSubBindings`:

```java
EffectiveMessageSecurity security = EffectiveMessageSecurity.of(config, readerGroup);
SecurityGroupConfig group = requireNonNull(security.securityGroup());

SksSecurityKeyProvider provider =
    SksSecurityKeyProvider.builder()
        .securityKeyServices(security.securityKeyServices())
        .securityGroupId(group.getSecurityGroupId())
        .keyCredentialStore(credentialStore)
        .certificateValidator(certificateValidator)
        .clientCustomizer(b -> /* client certificate, chain, and key pair */)
        .build();

PubSubBindings bindings =
    PubSubBindings.builder().securityKeys(group.ref(), provider).build();
```

Scope is the pull direction only. The push model (`SetSecurityKeys`) is not implemented,
and hosting the SKS itself — serving `GetSecurityKeys` to other applications — is the
`sksServerEnabled` option of [`milo-sdk-pubsub-server`](../sdk-pubsub-server), not this
module. If your keys are static pre-shared material, you don't need this module at all:
use `StaticSecurityKeyProvider` from the core module.

Message security and SKS behavior, including what is and isn't covered, is documented in
[docs/pubsub/limitations-and-interop.md](../../docs/pubsub/limitations-and-interop.md#message-security-and-sks).
