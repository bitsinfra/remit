# How an exchange works

Remit has two roles. A **sender** asks for work; a **holder** controls the data and executes admitted work. An agent can use either role, or both. The holder is a runtime with a catalog and policy, rather than a language model interpreting another agent’s message.

## Catalog

A signed catalog describes the resources the sender may discover: tables, visible columns, enums, allowed purposes, policy hints, limits and example programs. SDKs fetch it from `/.well-known/remit` and verify its signature. TypeScript can request a principal-scoped catalog with `holder(url, { scoped: true })`.

The catalog helps an agent write a valid program. Discovering a resource is not permission to execute any program against it; admission checks the actual request.

## Remit

A remit contains a program and a manifest. The manifest names the holder, sender, purpose, declared reads, parameters, execution limits and result type. The sender signs the envelope.

In **query mode**, the program is a restricted SQL query. In **kernel mode**, a sandboxed program calls named read templates and computes a result. A kernel cannot open arbitrary network connections or read the holder’s filesystem.

## Admission and execution

The holder authenticates the sender and checks the program’s facts against authority, access policy and budgets. It can admit, deny, propose a narrower request, or require approval. An admission check alone does not run the program or guarantee a later request will still fit the policy and budget.

When admitted, reads pass through the holder’s policy views. The runtime enforces execution limits. The output must fit the declared result type before the holder releases it.

## Result and receipt

The response contains a typed value, labels, terms and a signed receipt. The receipt binds the result to the request, parties, policy and source versions. SDKs verify it before returning a successful result.

Strings from a peer remain untrusted data. A signature proves their origin and integrity, not that instructions embedded in them should be followed.

## Boundaries across agents

An agent can ask several holders and combine their answers. The coordinating agent owns that orchestration. Remit supplies checked exchanges and provenance; it does not schedule a swarm, decide what question to ask, or write a final brief by itself.

Continue with [agent-to-agent workflows](agent-to-agent.md), or read the exact [manifest](../spec/manifest.md) and [admission](../spec/admission.md) contracts.
