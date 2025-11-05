# 010: The Signet Capability Protocol

**Status**: Draft
**Date**: 2025-10-10

---

## 1. Abstract

This document specifies the Signet Capability Protocol, a **canonical representation for authorization**. Its purpose is to serve as a universal language or "lingua franca" for expressing and verifying permissions in modern, distributed systems.

By defining a single, verifiable format based on the four pillars of **[Action, Resource, Constraint, Context]**, this protocol allows complex, domain-specific authorization systems (like AWS IAM, Kubernetes RBAC, or new human-readable policies) to be translated into a common representation. This decouples policy definition from enforcement, enabling a small, universal, offline-first verifier to handle authorization for any system that can target the canonical format.

## 2. Context: The Problem Statement

The current landscape of authorization is a "Tower of Babel"—a collection of bespoke, incompatible, and overwhelmingly complex policy engines. This lack of a common, interoperable standard for authorization is the root cause of many critical issues in modern infrastructure:

*   **Un-debuggable Complexity (The "Why-Not Labyrinth"):** Authorization logic is spread across a web of sprawling, inherited, and often conflicting policy documents. Debugging a single "Access Denied" error is a forensic exercise with no clear starting point.

*   **Insecure by Default (The "Ambient Authority Trap"):** The difficulty of applying least privilege leads to overly permissive, static roles that create a massive, latent blast radius for any compromised credential.

*   **Contextual Blindness:** Existing policies are bound to abstract identities and are blind to the critical runtime context of a request. They cannot answer questions like, "Is this request coming from an attested, secure workload?" or "Did this request traverse an untrusted network boundary?"

*   **Operational Fragility:** The reliance on centralized, online policy decision points is antithetical to the demands of resilient, offline-first, and distributed systems.

## 3. Core Concept: A Canonical Authorization Representation

The Signet Capability Protocol does not aim to be yet another authorization system. Instead, it provides a **Canonical Authorization Representation**—a single, universal format that other systems can be translated into. This is the core architectural principle.

This "lingua franca" model allows us to decouple the **definition** of a policy from its **enforcement**:

1.  **The Policy Sources (The "Many"):** A policy can be defined in any number of human-friendly or legacy formats:
    *   A simple, prose-like YAML file.
    *   An existing AWS IAM Policy document.
    *   A Kubernetes RBAC RoleBinding.
    *   A high-level language like OPA's Rego.

2.  **The Translators (The "Bridge"):** For each source format, a dedicated "Policy Compiler" or "Bridge" is responsible for translating the *intent* of that policy into a standard, signed Signet Capability Token.

3.  **The Universal Runtime (The "One"):** The Signet verifier (e.g., the middleware in a service) is now incredibly simple. It does not need to understand IAM, Kubernetes, or any other complex system. It only needs to know how to do one thing: **validate a canonical Signet Capability Token.**

This architecture is mechanistically simple yet fundamentally powerful. It allows us to create compatibility and clarity across the entire chaotic landscape of authorization, providing a single, verifiable format for the runtime while offering flexibility and a world-class developer experience at the policy definition layer.

## 4. Guiding Principles

To solve these problems, the protocol itself is built on five non-negotiable principles. These are the commandments for the canonical representation.

1.  **Causal Clarity is a Security Feature:** The canonical format must contain enough information to allow a human-readable explanation for any decision to be reconstructed. Every denial must be explainable.

2.  **Authority is Carried, Not Conferred:** The canonical token is a self-contained, cryptographic capability ("currency") that travels with a request. It must be verifiable locally without network calls.

3.  **Credentials are Radioactive & Decay by Default:** All capabilities are ephemeral. The canonical format must have a built-in, non-negotiable lifetime (TTL).

4.  **Provenance & Context are Intrinsic:** The path a request takes and the context of its origin are as critical as who sent it. This must be a verifiable, first-class part of every authorization decision.

5.  **Policy is Declarative Data, Locally Verified:** The canonical token is a declarative data structure. The resource endpoint is the sovereign authority for making the final, local decision based on this data.

## 5. The Capability Model: The Four-Pillar Lattice

The canonical representation is a composite of four orthogonal pillars. A request is only authorized if its presented capability token satisfies all four dimensions.

*   **Pillar 1: Action**
    *   *Answers:* What is the actor trying to do?
    *   *Examples:* `read`, `write`, `impersonate`

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

## 7. Next Steps

This document establishes the foundational principles and model. The next steps in the design process are to detail:

*   The precise wire format for the canonical capability token.
*   The cryptographic operations for signing, attenuating, and verifying tokens.
*   The formal verification logic that a sovereign endpoint must execute.
