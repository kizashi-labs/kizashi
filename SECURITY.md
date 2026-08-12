# Security Policy

Kizashi is a security product. A vulnerability here can expose the telemetry of every
endpoint an operator monitors, so reports are taken seriously and handled privately
until a fix is available.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/kizashi-labs/kizashi/security)
2. Click **Report a vulnerability**
3. Describe the issue

Only you and the maintainer can see the report. GitHub notifies the maintainer
directly, so no e-mail address needs to be published — and you are not asked to send
details over an unencrypted channel.

If private reporting is unavailable to you for any reason, open a **blank issue**
saying only that you have a security report and would like a private channel. Do not
include details in it.

### What to include

- What the problem is, and which component (agent / server / console / rules)
- Version or commit hash
- Steps to reproduce, ideally minimal
- What an attacker gains — and, if you know, what it takes to reach the vulnerable code
- Your assessment of severity, if you have one

Proof-of-concept code is welcome but not required. A clear description of the flaw is
worth more than a weaponised exploit.

## What to expect

This project is maintained by one person, so please read the following as an honest
commitment rather than a service-level agreement:

| Stage | Target |
|---|---|
| Acknowledgement | within 5 days |
| Initial assessment | within 14 days |
| Fix or mitigation for a confirmed high-severity issue | as fast as reasonably possible; you will get progress updates |

If you have not heard back within 14 days, follow up on the same report — it means
the notification was missed, not that the report was dismissed.

## Disclosure

Coordinated disclosure is preferred. Once a fix is released, the advisory is published
through GitHub Security Advisories, and reporters are credited by whatever name or
handle they choose — including anonymously.

There is no bug bounty. This is an open source project with no revenue attached to the
public edition, so no monetary reward can be offered.

## Scope

**In scope** — anything in this repository: the agent, the server services, the web
console, the SDKs, the detection rules, and the deployment manifests.

**Out of scope**

- The unverified kernel-level prevention proof of concept (the Windows WDK driver under
  `agent/driver/windows/prevention/` and the eBPF LSM hooks). These are published as
  research artifacts, are not wired into production builds, and are known to be
  unhardened. Reports that they can be bypassed or crashed are expected, not
  vulnerabilities.
- Missing hardening in an operator's own deployment (weak `JWT_SECRET`, database
  exposed to the internet, running the console over plain HTTP)
- Detection evasion. A rule failing to catch a technique is a detection gap — please
  file that as a normal issue, it is useful and welcome.
- Denial of service that requires an already-authenticated administrator
- Vulnerabilities in third-party dependencies with no exploitable path in this code.
  Report those upstream; if there *is* an exploitable path here, that is in scope.

## Supported versions

Only the latest release receives security fixes. There are no long-term support
branches for the open source edition.

## Hardening

Operators should read `docs/セキュリティ強化ガイド.md` before exposing an instance
beyond a lab. The defaults are chosen for a working first-run experience, not for an
internet-facing deployment.
