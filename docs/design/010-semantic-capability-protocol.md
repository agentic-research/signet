# 010: Semantic Capability Protocol

**Status**: Draft
**Date**: 2025-10-10
**Authors**: The Signet Collective

---

## 1. Abstract

This document specifies the Signet Semantic Capability Protocol, a new authorization model designed to replace traditional, identity-centric IAM systems. The protocol is founded on the principle of **verifiable, carried authority**, where permissions are not granted by a central authority but are carried with a request as a cryptographically verifiable proof, or "capability."

This design moves beyond the limitations of static, opaque policies by treating authorization as a real-time, contextual act of validation. It introduces a four-dimensional capability model of **[Action, Resource, Constraint, Context]** that is human-legible, machine-verifiable, and built for the demands of modern, decentralized, offline-first systems.

## 2. Context: The Problem Statement

The current landscape of authorization, dominated by IAM and RBAC systems, is fundamentally broken. It was designed for a centralized, static, and always-online world, and its core assumptions have collapsed under the weight of modern infrastructure. The result is a class of systems that are hostile to developers, operators, and security teams alike.

The key problems with these existing systems are:

*   **Un-debuggable Complexity (The "Why-Not Labyrinth"):** Authorization logic is spread across a web of sprawling, inherited, and often conflicting policy documents. Debugging a single "Access Denied" error is a forensic exercise with no clear starting point, leading to massive operational overhead.

*   **Insecure by Default (The "Ambient Authority Trap"):** The difficulty of applying least privilege and the availability of overly broad defaults (`*:*`) mean that systems are often wildly over-provisioned. This creates a massive, latent blast radius for any compromised credential.

*   **Contextual Blindness:** Policies are bound to abstract identities (users, roles) and are blind to the critical runtime context of a request. They cannot answer questions like, "Is this request coming from an attested, secure workload?" or "Did this request traverse an untrusted network boundary?"

*   **Operational Fragility:** The reliance on a central policy decision point creates a single point of failure that is incompatible with the demands of resilient, distributed systems. "Eventual consistency" in a security system is a bug, not a feature.

## 3. Core Principles

To solve these problems, this protocol is built on five non-negotiable principles. All technical decisions must be measured against them.

1.  **Causal Clarity is a Security Feature:** Authorization policy must be expressed in a human-legible format. Every decision, especially a denial, must be explainable in seconds, providing a complete, auditable chain of evidence for why it was made.

2.  **Authority is Carried, Not Conferred:** All authority is a cryptographic capability ("currency") that travels with a request. Every request is guilty until its proof is validated locally, without network calls to a central authority.

3.  **Credentials are Radioactive & Decay by Default:** All capabilities are ephemeral. Every credential must have a "half-life" (TTL). There is no concept of a permanent or standing permission.

4.  **Provenance & Context are Intrinsic:** The path a request takes and the context of its origin are as critical as who sent it. This must be a verifiable, first-class part of every authorization decision.

5.  **Policy is Declarative Data, Locally Verified:** Policy intent is expressed as declarative data (e.g., YAML), which is then compiled into a machine-verifiable format. The resource endpoint is the sovereign authority for making the final, local decision.

## 4. Proposed Capability Model: The Four-Pillar Lattice

To satisfy these principles, we define a capability as a composite of four orthogonal pillars. A request is only authorized if it satisfies all four dimensions.

*   **Pillar 1: Action**
    *   *Answers:* What is the actor trying to do?
    *   *Examples:* `read`, `write`, `delete`, `impersonate`

*   **Pillar 2: Resource**
    *   *Answers:* What are they trying to do it to?
    *   *Examples:* `transactions-table`, `billing-service`, `user-profile:123`

*   **Pillar 3: Constraint**
    *   *Answers:* Under what external, static conditions?
    *   *Examples:* `time < 2025-12-31`, `ip_in_range(...)`, `mfa_present == true`

*   **Pillar 4: Context**
    *   *Answers:* How did this request's authority get here, and from where?
    *   *Concept:* A verifiable, cryptographic record of the request's journey and environment.
    *   *Sub-dimensions:*
        *   **Provenance:** The origin issuer, the chain of custody, and any attenuations (`[Issuer] → [Sidecar] → [Target]`)
        *   **Environment:** The attested, immutable facts about the runtime (`image_digest`, `enclave_measurement`).
        *   **Boundary:** The logical, network, or geographic perimeter the capability is valid within (`vpc-123`, `eu-sovereign-cloud`).

## 5. Next Steps

This document establishes the foundational principles and model. The next steps in the design process are to detail:

*   The precise wire format for a capability token incorporating the four pillars.
*   The cryptographic operations for signing, attenuating, and verifying capabilities.
*   The formal verification logic that a sovereign endpoint must execute.
*   The high-level language for expressing policies in a human-readable format.

## 6. Core Principle: A Pluggable Framework

For this protocol to succeed and avoid the rigidity of the systems it replaces, it must be designed as a pluggable framework, not a monolithic product. The core protocol should be small, verifiable, and concerned only with the structure and validation of capabilities. The richness and domain-specific logic will come from a vibrant, extensible ecosystem.

The architecture must provide clear interfaces and extension points for the following components:

*   **Policy Language Engines:** While a default, human-readable format (e.g., YAML) will be defined, the system must be agnostic to the policy language itself. It should be possible to compile different languages (e.g., OPA's Rego, HCL) into the standard, machine-verifiable capability format.

*   **Context Providers:** The `Context` pillar is the primary extension point. The protocol will define a standard interface for "Context Providers" to supply signed, verifiable claims about the runtime world. This allows third parties to build plugins for various environments:
    *   **Cloud Providers:** Attesting to workload identity, instance metadata, etc.
    *   **Service Meshes:** Attesting to request paths and traffic properties.
    *   **CI/CD Systems:** Attesting to build pipelines and artifact origins.
    *   **Hardware Security Modules:** Attesting to operations backed by TPMs or secure enclaves.

*   **Domain-Specific Dictionaries:** The specific meanings of `Action` and `Resource` are domain-dependent. The protocol will not enforce a global dictionary. Instead, it will allow for domain-specific schemas or dictionaries to be plugged in, enabling the framework to be adapted for diverse use cases like database authorization, financial transactions, or infrastructure management.
