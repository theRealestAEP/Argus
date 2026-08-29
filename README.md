# Argus On-Device IDS Agent

![Argus and Hermes by Diego Velázquez](assets/argus.jpg)

*Image source: [Ancient Origins](https://www.ancient-origins.net/myths-legends-europe/argos-panoptes-001044).*

Argus is an on device agent that dynamically maps the host, records intended use,
builds mechanical sensors, investigates alerts, and applies policy-approved
containment.

## Setup

Install Node.js 24 or later. Then run:

```sh
cp .env.example .env
npm install
./scripts/setup.sh
```

The setup wizard inspects the host and asks about its purpose, critical paths,
services, local agents, alert contacts, response mode, retention, and review
schedule. Agent Mail and S3 are optional.

Response modes:

- `report-only`: record and report.
- `approval-required`: ask before containment.
- `autonomous-action`: apply policy-approved containment.

Setup asks whether Argus may terminate a confirmed malicious process
automatically. The default requires approval during the incident.

### Linux release

```sh
npm run dist
npm install -g ./release/on-device-ids-agent-0.1.0.tgz
sudo ids-agent-install-linux "$PWD/.env"
```

The installer creates the `argus-ids` account and starts two systemd services.
One service runs Argus. A root broker validates and applies containment. Both
services start after a reboot.

### Mac Studio

Install from source before the first GitHub release:

```sh
git clone https://github.com/theRealestAEP/Argus.git
cd Argus
cp .env.example .env
nano .env
./scripts/setup.sh
```

After release `v0.1.0`, install its verified archive:

```sh
curl -fLo .env https://raw.githubusercontent.com/theRealestAEP/Argus/v0.1.0/.env.example
nano .env
curl -fLO https://github.com/theRealestAEP/Argus/releases/download/v0.1.0/on-device-ids-agent-0.1.0.tgz
curl -fLO https://github.com/theRealestAEP/Argus/releases/download/v0.1.0/SHA256SUMS
shasum -a 256 -c SHA256SUMS
sudo npm install --global ./on-device-ids-agent-0.1.0.tgz
sudo ids-agent-install-macos "$PWD/.env"
```

The installer creates two LaunchDaemons. One runs Argus as your macOS account.
The other runs the containment broker as root.

## Updates

Check GitHub Releases:

```sh
ids-agent update-check
```

Install a checksum-verified update and restart both services:

```sh
sudo ids-agent update \
  --state-dir="/Library/Application Support/Argus/state" \
  --env-file="/Library/Application Support/Argus/config/env"
```

Source installations use `git pull`, `npm ci`, and `npm run build`.

## Operations

```sh
ids-agent status
ids-agent access
ids-agent doctor
ids-agent re-onboard
ids-agent memory-pack
```

`re-onboard` updates policy and recommissions sensors. `memory-pack` builds
signed, grep-friendly long-term memory.

Argus can block an IPv4 destination or pause an identified process. Each
action records its target and rollback command.

**Warning:** The next command can stop a process or block network traffic.

```sh
sudo ids-agent contain \
  --state-dir=/var/lib/argus-ids \
  --env-file=/etc/argus-ids/env \
  --plan-file=/secure/path/containment-plan.json
```

## Docker and tests

Run all local checks:

```sh
npm run check
```

Run Linux setup, sensors, and a 32-process containment load test:

```sh
npm run test:e2e:linux
```

Run the interactive Linux onboarding demo:

```sh
npm run demo:onboarding:linux
```

Run the cooperative telemetry smoke test:

```sh
export ZAI_API_KEY=...
npm run eval:smoke:cooperative
```

This Docker test checks the runtime event integration. The service tells Argus
the exact process that performed an action. Use it as an integration test.

Run the independent adversarial benchmark on macOS:

```sh
brew install lima
npm run eval:adversarial:vm -- rce-exfiltration
```

The benchmark creates a Linux VM. It runs the target services and Argus as
native host services. GLM receives only the public address and a business
goal. The scorer uses Linux Audit logs, database access logs, Argus evidence,
containment receipts, attacker output, and final host state.

See the [security evaluation report](SECURITY-EVALUATION.md) for the campaigns,
score rules, and current limits. Git ignores all saved evaluation artifacts.

## Removal

List installed resources:

```sh
ids-agent uninstall-plan
```

**Warning:** The next command stops Argus and removes its boot services. It
keeps local state and reports.

```sh
sudo ids-agent uninstall-service \
  --state-dir=/var/lib/argus-ids \
  --env-file=/etc/argus-ids/env \
  --service-user=argus-ids \
  --service-group=argus-ids
```

## License

Argus uses the MIT License.
