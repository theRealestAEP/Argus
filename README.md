# On-Device IDS Agent

This project builds an intrusion detection agent for Linux and macOS. Argus
protects the host where it runs. It records approved use, collects local
evidence, creates mechanical monitors, investigates alerts, and prepares
security reports.

## Requirements

Install Node.js 24 or a later compatible release. Run the following command:

```sh
npm install
```

Copy the environment template. Then add your API key to `.env`:

```sh
cp .env.example .env
```

The setup script sets `.env` to mode `0600`. The boot service loads this file
so the daemon can use the configured model and Agent Mail account.

Git and Docker exclude `.env` and all other environment variants. They include
`.env.example`. The template includes optional Agent Mail API key and inbox
settings. Setup tests the selected inbox. It stores only the inbox address.
Report delivery remains local until the delivery adapter is complete.

## First-time setup

**Warning:** Setup requests administrator authorization. It installs and starts
a system boot service.

Run the setup script:

```sh
./scripts/setup.sh
```

The wizard asks for the device purpose, alert recipient, Agent Mail inbox,
allowed email senders, report recipients, change window, critical paths,
expected services, approved agents, response mode, review schedule, evidence
retention, and local log size limit. It can also record an S3 bucket for a
future archive adapter.

The operator can defer external alert delivery. Enter `local-only` or accept
that default. The agent will keep alerts and reports in local state. The local
CLI remains available for status, review, re-onboarding, and lifecycle work.
An operator can add Agent Mail, email, or another adapter later.

Enter `skip` at the Agent Mail prompt to use local reports. When an inbox is
selected, setup reads `AGENTMAIL_API_KEY` from `.env` and tests the inbox. A
failed test does not stop setup. The API key stays in `.env`.

An allowed sender can send evidence or an operator message to the inbox. A
report recipient can receive agent mail. These roles do not authorize a host
change. Setup applies both lists to Agent Mail. If that step fails, setup keeps
local reports active and prints the failure.

The wizard then probes the access needed for collection, detection,
investigation, and mitigation. It prints one action for each missing
permission. Complete each action and run this command:

```sh
node dist/cli.js access
node dist/cli.js doctor
```

The script returns status 1 while a required capability needs action. This
status keeps an installer from treating partial commissioning as operational.

The command creates `.ids-agent` with mode `0700`. It creates the private
signing key with mode `0600`. Argus signs the install manifest and operating
policy. The signatures detect accidental or unauthorized file changes.

Argus writes evidence to `.ids-agent/logs/events.jsonl`. It removes records
after the retention period. It also removes the oldest records when the file
reaches the configured size limit.

Setup installs `argus-ids.service` on Linux. It installs
`com.argus.ids-agent` as a system LaunchDaemon on macOS. The service starts at
boot, runs as the commissioning user, restarts after failure, and writes a
heartbeat to `.ids-agent/runtime/heartbeat.json`.

The signed install manifest records the service file. Show the removal order
with `node dist/cli.js uninstall-plan`.

**Warning:** The next command stops the daemon and removes its boot service.
It keeps local state and reports.

```sh
sudo node dist/cli.js uninstall-service \
  --state-dir="$PWD/.ids-agent" \
  --service-user="$(id -un)" \
  --service-group="$(id -gn)"
```

An installer can supply all three answers as options:

```sh
node --env-file-if-exists=.env dist/cli.js setup \
  --device-purpose="developer laptop" \
  --admin-contact="security@example.com" \
  --agent-mail-inbox="argus-01@agentmail.to" \
  --email-allowed-senders="admin@example.com,operator@example.com" \
  --email-report-recipients="security@example.com" \
  --maintenance-window="Sunday 02:00 local time"
```

The remaining policy options use conservative defaults. Pass the following
options when an automated installer needs explicit values:

```text
--critical-paths=/etc,/srv/app
--expected-services=sshd,postgresql
--approved-agent-runtimes=codex,local-review-agent
--response-mode=approval-required
--review-schedule="every 2 days"
--retention-days=30
--log-cache-mb=1024
--s3-archive-bucket=none
```

Set `IDS_AGENT_STATE_DIR` to use another development state directory:

```sh
IDS_AGENT_STATE_DIR=/secure/path node dist/cli.js setup
```

## Daily commands

Check the agent state:

```sh
node dist/cli.js status
node dist/cli.js access
node dist/cli.js doctor
```

Update the approved-use answers:

```sh
node dist/cli.js re-onboard
```

Use re-onboarding when an administrator, inbox, sender, or recipient changes.
The command writes and signs a new policy. It applies the new Agent Mail lists.
Native host access is the recovery authority. If the local signing key is lost,
stop the service, preserve required reports, remove the Argus state directory,
and run setup again as an administrator. This design has no recovery backdoor.

## Containment policy

Argus can propose a process termination or a destination block. Process
termination always requires native administrator approval. A reversible
destination block can run automatically only in `autonomous-reversible` mode.
Each plan must cite evidence and identify its exact target. Each completed
action must record a receipt and a removal command.

Every generated sensor must define a heartbeat, resource limit, safe test
fixture, expected event flow, stale-alert rule, and removal step. Argus must
record a successful canary test before it enables the sensor.

Build and verify the current memory pack:

```sh
node dist/cli.js memory-pack
grep -R "search text" .ids-agent/memory-packs/current
```

Show the future removal order:

```sh
node dist/cli.js uninstall-plan
```

The removal command will use Linux `polkit` or Apple Authorization Services.
The operating system will authenticate an administrator before a lifecycle
change. Routine monitoring will continue without an agent passphrase.

## Development checks

Run all checks:

```sh
npm run check
```

Run the checks and the Linux Docker evaluation:

```sh
npm run check:all
```

## Live model evaluation

Run the live evaluation from the host:

```sh
npm run test:e2e:model
```

Run the same evaluation in Docker:

```sh
docker build -f tests/e2e/Dockerfile -t ids-agent-e2e .
docker run --rm --env-file .env ids-agent-e2e npm run test:e2e:model
```

## Live Linux workload demo

Run this command to start the complete Docker demo:

```sh
npm run demo:e2e:linux
```
