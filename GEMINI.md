# Signet Project Overview

This document provides a comprehensive overview of the Signet project, intended for developers and contributors.

## Project Purpose and Technologies

Signet is a Go-based toolchain for cryptographic proof-of-possession, designed to replace traditional bearer tokens. It uses ephemeral Ed25519 certificates to sign commits, files, and HTTP requests, offering a more secure alternative to static API keys or tokens.

**Core Technologies:**

*   **Programming Language:** Go
*   **Cryptography:** Ed25519 for digital signatures, X.509 for certificates, and COSE (CBOR Object Signing and Encryption) for a compact signature format.
*   **Data Format:** CBOR (Concise Binary Object Representation) for lightweight token structures.

## Architecture

Signet employs a layered, offline-first architecture:

*   **`libsignet`:** A core library containing all the cryptographic primitives, including key management, ephemeral proof generation, and certificate handling.
*   **`signet-commit`:** A reference implementation for Git commit signing, designed to work completely offline.
*   **`signet` binary:** The main entry point for the application, providing subcommands for various operations.

The system is designed around a local-first identity model, where each user's device acts as its own certificate authority. For more details, see `ARCHITECTURE.md`.

## Building, Running, and Testing

The project uses a `Makefile` to streamline common development tasks.

*   **Build the project:**
    ```bash
    make build
    ```
    This command compiles the `signet` and `signet-git` binaries.

*   **Run unit tests:**
    ```bash
    make test
    ```

*   **Run integration tests:**
    ```bash
    make integration-test
    ```
    This runs the integration tests in a Docker container to ensure a consistent testing environment.

*   **Install the binaries:**
    ```bash
    make install
    ```
    This command installs the `signet` and `signet-git` binaries to `/usr/local/bin`.

## Development Conventions

*   **Code Formatting:** Use `make fmt` to format the code according to the project's standards.
*   **Linting:** Run `make lint` to check for code quality and style issues.
*   **Dependencies:** Project dependencies are managed using Go modules, as defined in the `go.mod` file.
*   **Contribution:** Guidelines for contributing to the project are outlined in `CONTRIBUTING.md`.
