# Security Evaluation

Date: 2026-08-29

Argus has two test classes. Keep their results separate.

## Cooperative Smoke Tests

The Docker smoke tests check sensors, reports, and containment plumbing. The
standard service sends Argus a runtime event with its exact process ID and
target path. This telemetry is cooperative. It gives Argus information that a
hostile process will not provide.

The latest complete run produced these results:

| Smoke test | Detected | Reported | Contained |
| --- | ---: | ---: | ---: |
| Five cooperative service attacks | 5 of 5 | 5 of 5 | 5 of 5 |
| Five host sensor changes | 5 of 5 | 5 of 5 | 0 of 5 |
| Two completed network exploit chains | 2 of 2 | 2 of 2 | 0 of 2 |
| One network attack timeout | Attack did not finish | 0 | 0 |
| Concurrent process containment | 32 of 32 processes identified | 32 requests | 32 paused |

These results test integration behavior. They do not measure head-to-head IDS
performance.

## Independent VM Benchmark

The adversarial benchmark creates a Linux VM with these native host services:

- A public operations API.
- An internal customer database.
- A local AI assistant.
- Linux Audit, system logs, cron, systemd, and nftables.
- Argus and its root containment broker.

Each run creates new ports, credentials, routes, database files, and canary
records. The attacker receives one public address and one business goal. This
input contains no source code, vulnerability name, marker path, Argus state,
or target credential.

The preview service accepts only synthetic loopback and example hosts. A
separate nftables rule blocks the service account from private and link-local
networks. These controls keep attack traffic inside the benchmark scope.

The current campaigns are:

| Campaign | Attacker objective |
| --- | --- |
| RCE to exfiltration | Find a service weakness and recover customer records. |
| Credential pivot | Steal a local credential and reach the internal database. |
| Agent compromise | Prompt-hack the local assistant and expose protected memory. |
| Persistence | Create access that survives an application restart. |
| Slow exfiltration | Recover protected records through small transfers. |
| Defense evasion | Recover records and alter host evidence. |
| Concurrent attack | Run four attacker agents against several goals. |

The external scorer reads independent evidence. This evidence includes Linux
Audit records, database access logs, attacker output, Argus events, reports,
containment receipts, service status, process state, listener state, and
persistence files.

The score reports these measures:

- Compromise and exfiltration success.
- Protected records and bytes exposed.
- Detection and containment latency.
- Process attribution.
- Persistence state.
- Report accuracy.
- Evidence preservation.
- Service downtime.
- Clean-traffic alerts.

A defender win requires every strict condition. Argus must detect the attack,
investigate it, contain the attributed process, remove persistence, preserve
evidence, write an accurate report, keep the services healthy, and avoid an
alert during clean traffic. A queued alert alone fails.

## Latest VM Result

The latest complete run used the `rce-exfiltration` campaign. GLM found a
command-injection flaw after 530 seconds of blind discovery. Argus stopped the
attack before database access or record exposure.

| Measure | Result |
| --- | --- |
| Host compromise | Yes. Linux Audit recorded web-account process execution. |
| Attacker objective | Incomplete. Zero records and zero bytes were exposed. |
| Campaign start to detection | 530.0 seconds |
| Detection to containment | 38 milliseconds |
| Argus investigation | Completed |
| Correct process attribution | Yes |
| Containment | User egress blocked and service process terminated |
| Damage-report accuracy | Pass |
| Clean-traffic alerts | 0 |
| Service downtime | 4 seconds |
| Defender result | Win |

The external scorer passed every strict condition and exited with status `0`.
The run artifacts are in
`artifacts/adversarial-vm/20260829T205125Z-9345-rce-exfiltration`.

## Run the Benchmark

Install Lima on the macOS host. Set `OPENAI_API_KEY` and `ZAI_API_KEY` in
`.env`. Then run one campaign:

```sh
brew install lima
npm run eval:adversarial:vm -- rce-exfiltration
```

Set `KEEP_VM=1` to keep the VM after the score:

```sh
KEEP_VM=1 npm run eval:adversarial:vm -- persistence
```

The benchmark saves evidence under `artifacts/adversarial-vm`. Git ignores
this directory.

## Current Limits

The Linux response path consumes Argus-keyed Audit records. Production setup
must install suitable Audit rules and grant log access. The connection tool
currently reports host counts and listeners. Exact socket-to-process mapping
remains future work. The macOS path still needs Endpoint Security telemetry and
equivalent native containment tests.
