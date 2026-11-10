---
name: steam-input-lease
description:
  Implement or review Steam Input Lease protocol, gate, client bindings and controller recovery. Use
  for native leasing mechanisms; host input policy remains in the consumer.
---

# Steam Input Lease contributions

Resolve aliases to this owning repository. Read AGENTS.md and README.md, especially Proxy delivery,
Lease lifecycle, Controller recovery, Compatibility and Security. Preserve evidence-backed loader
and recovery constraints. Public ABI changes update the header and every binding together.

Keep lease policy in consumers and mechanism in the existing client/gate/recovery owners. Follow the
repository's Rust/C/C# formatter and ABI conventions. Preserve fixed-width wire layouts and native
signatures. C# bindings use expanded braces, var locals with clear construction types and named
literals; retain complete public lifetime/error documentation.

Trace acquire, renew/drop, disconnect, process exit and recovery through the real owner. A client
request, server acceptance and recovered controller are different outcomes. Do not report clean
release while a failed recovery remains hidden; cancellation after dispatch is not a refusal.
Preserve idempotency and ownership when reconnecting rather than blindly replaying uncertain work.
Use existing isolated lifecycle/native validation under the maintainer's timing. Injection, live
Steam recovery, installation and deployment need explicit scope; build/export checks prove neither
live recovery nor controller usability. Publish library artifacts/pins before consumer integration.
