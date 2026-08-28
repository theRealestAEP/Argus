# Repository Instructions

This repository contains an on-device intrusion detection agent for Linux and
macOS. One installed agent protects the host where it runs. Keep fleet control,
remote administration, cloud-account control, and active network scanning out
of this repository.

Write the smallest clear change that solves the current task. Use model
reasoning for investigation and adaptation. Use deterministic code for access
control, evidence capture, signatures, policy limits, and system changes.

Run `npm run check` before you finish a code change. Keep classic cyclomatic
complexity at 10 or less. Treat all anti-slop findings as errors.

Write README and documentation files in Simplified Technical English. Use
short sentences, active voice, one instruction per step, and one meaning for
each technical term. Put warnings before the action that can cause harm.

System changes must be reversible and recorded in the install manifest. Keep
teardown commands behind native administrator authentication. Never add a
custom shared passphrase as a substitute for operating-system authorization.
