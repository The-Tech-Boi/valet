# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Developers and IT admins on Windows who let coding assistants and their own scripts sign in to servers,
APIs, websites and databases, and do not want those tools to ever see the passwords.

## Product Purpose

valet uses credentials from a Vaultwarden or Bitwarden vault on the caller's behalf: it performs the
sign-in itself and hands back only the result, with secrets redacted, approvals for sensitive uses and an
audit trail. Success means automation gets its job done while the secret never enters its context, logs or
transcripts.

## Positioning

An SSH-agent-style broker for every kind of login (HTTP APIs, browser forms, SSH, WinRM, SQL Server, Remote
Desktop), not a password manager and not a secrets injector: the caller names the credential, valet does
the sign-in, and the credential only goes to hosts its vault item lists.

## Operating Context

A single Windows executable: an MCP server on stdio for coding assistants, a command line (`valet install`,
`valet run`, `valet check`, `valet rdp`), a background agent, and small native windows for setup, unlock
and approval. Distributed as an open-source GitHub project with downloadable releases.

## Capabilities and Constraints

Windows 10/11 only. Same-user isolation: valet keeps honest automation from seeing secrets but is not a
sandbox against malicious code running as the same user; never claim otherwise.

## Brand Commitments

Name: valet (lowercase). Open-source project under the The-Tech-Boi GitHub account, MIT licence. Its own
identity, not Async Solution's branding. No logo existed before 2026-11.

## Evidence on Hand

README with real usage examples. No users, testimonials, metrics or press; do not invent any.

## Product Principles

- The secret never reaches the caller; every design choice protects that.
- Plain and honest about limits: say what it does not protect.
- Small and quiet: one exe, no config files, windows only when a person must decide.
