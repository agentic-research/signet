package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultAuthorityURL = "https://auth.notme.bot"
	defaultOIDCAudience = "notme.bot"
)

type artifactOutputs struct {
	Bundle      string
	Certificate string
	CABundle    string
	PublicKey   string
}

type cosignRunner func(context.Context, []string, io.Writer, io.Writer, ...string) error

func artifactOutputPaths(artifact string) artifactOutputs {
	return artifactOutputs{
		Bundle:      artifact + ".sigstore.json",
		Certificate: artifact + ".signet.crt.pem",
		CABundle:    artifact + ".signet.ca.pem",
		PublicKey:   artifact + ".signet.pub",
	}
}

func validateArtifactPaths(artifacts []string) error {
	if len(artifacts) == 0 {
		return fmt.Errorf("at least one artifact path is required")
	}
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if strings.TrimSpace(artifact) == "" {
			return fmt.Errorf("artifact path must not be empty")
		}
		cleaned := filepath.Clean(artifact)
		if _, exists := seen[cleaned]; exists {
			return fmt.Errorf("artifact path is repeated: %s", artifact)
		}
		seen[cleaned] = struct{}{}
		info, err := os.Stat(artifact)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("artifact does not exist: %s", artifact)
			}
			return fmt.Errorf("stat artifact %s: %w", artifact, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("artifact is not a regular file: %s", artifact)
		}
	}
	return nil
}

func signArtifactsWithSession(
	ctx context.Context,
	enrolled *enrollment,
	artifacts []string,
	runner cosignRunner,
	stdout io.Writer,
	stderr io.Writer,
) (returnErr error) {
	if enrolled == nil || enrolled.Signer == nil {
		return fmt.Errorf("an active enrollment is required")
	}
	if runner == nil {
		return fmt.Errorf("cosign runner is required")
	}
	if err := validateArtifactPaths(artifacts); err != nil {
		return err
	}

	session, err := startKMSSession(enrolled.Signer)
	if err != nil {
		return err
	}
	defer func() {
		if err := session.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close Signet KMS session: %w", err)
		}
	}()

	environment := withEnvironment(os.Environ(), map[string]string{
		sessionSocketEnv: session.SocketPath(),
		sessionTokenEnv:  session.Token(),
	})
	trustedRootPath, removeTrustedRoot, err := createCosignTrustedRoot(ctx, enrolled, environment, runner, stdout, stderr)
	if err != nil {
		return err
	}
	defer removeTrustedRoot()

	for _, artifact := range artifacts {
		if time.Until(enrolled.ExpiresAt) < 30*time.Second {
			return fmt.Errorf("ephemeral signing certificate expires too soon to sign %s", artifact)
		}
		outputs := artifactOutputPaths(artifact)
		for path, contents := range map[string][]byte{
			outputs.Certificate: enrolled.SigningCertificatePEM,
			outputs.CABundle:    enrolled.CABundlePEM,
			outputs.PublicKey:   enrolled.PublicKeyPEM,
		} {
			if err := writePublicFile(path, contents); err != nil {
				return err
			}
		}

		if err := runner(ctx, environment, stdout, stderr, cosignSignBlobArgs(artifact, outputs, trustedRootPath)...); err != nil {
			return fmt.Errorf("cosign sign-blob %s: %w", artifact, err)
		}
		if err := runner(ctx, environment, stdout, stderr, cosignVerifyBlobArgs(artifact, outputs, trustedRootPath, enrolled.Identity)...); err != nil {
			return fmt.Errorf("cosign verify-blob %s: %w", artifact, err)
		}
		if _, err := fmt.Fprintf(stdout, "signed and verified %s as %s\n", artifact, enrolled.Identity); err != nil {
			return fmt.Errorf("write signing result: %w", err)
		}
	}
	return nil
}

func createCosignTrustedRoot(
	ctx context.Context,
	enrolled *enrollment,
	environment []string,
	runner cosignRunner,
	stdout io.Writer,
	stderr io.Writer,
) (string, func(), error) {
	if enrolled.AuthorityURL == "" {
		return "", nil, fmt.Errorf("enrollment authority URL is required")
	}
	if strings.Contains(enrolled.AuthorityURL, ",") {
		return "", nil, fmt.Errorf("enrollment authority URL must not contain a comma")
	}
	tempDir, err := os.MkdirTemp("", "signet-trusted-root-")
	if err != nil {
		return "", nil, fmt.Errorf("create temporary trusted-root directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }
	caPath := filepath.Join(tempDir, "authority-ca.pem")
	if err := os.WriteFile(caPath, enrolled.CABundlePEM, 0o600); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("write temporary authority CA bundle: %w", err)
	}
	trustedRootPath := filepath.Join(tempDir, "trusted-root.json")
	fulcioSpec := "--fulcio=url=" + enrolled.AuthorityURL + ",certificate-chain=" + caPath
	if err := runner(ctx, environment, stdout, stderr,
		"trusted-root", "create",
		"--with-default-services",
		// Notme/Cloister does not issue RFC 6962 SCTs. Keep public Rekor and
		// TSA verification material, but do not advertise CTFE for this CA.
		"--no-default-ctfe",
		fulcioSpec,
		"--out", trustedRootPath,
	); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("cosign trusted-root create: %w", err)
	}
	info, err := os.Stat(trustedRootPath)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("stat generated cosign trusted root: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		cleanup()
		return "", nil, fmt.Errorf("cosign generated an empty or non-regular trusted root")
	}
	return trustedRootPath, cleanup, nil
}

func cosignSignBlobArgs(artifact string, outputs artifactOutputs, trustedRootPath string) []string {
	return []string{
		"sign-blob", "--yes",
		"--key", "signet://session",
		"--certificate", outputs.Certificate,
		"--certificate-chain", outputs.CABundle,
		"--trusted-root", trustedRootPath,
		"--bundle", outputs.Bundle,
		artifact,
	}
}

func cosignVerifyBlobArgs(artifact string, outputs artifactOutputs, trustedRootPath, identity string) []string {
	return []string{
		"verify-blob",
		"--trusted-root", trustedRootPath,
		"--certificate-identity", identity,
		// Notme bridge certificates intentionally use Notme's extension arc,
		// not Fulcio's OIDC issuer extension. Assert that it is absent while
		// pinning the exact WIMSE SAN and authority CA above.
		"--certificate-oidc-issuer-regexp", "^$",
		// Notme/Cloister bridge certificates are not submitted to a CT log.
		// Rekor inclusion remains required by the generated trusted root.
		"--insecure-ignore-sct",
		"--bundle", outputs.Bundle,
		artifact,
	}
}

func writePublicFile(path string, contents []byte) error {
	if len(contents) == 0 {
		return fmt.Errorf("refusing to write empty public signing material to %s", path)
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		return fmt.Errorf("write public signing material %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("set public signing material permissions %s: %w", path, err)
	}
	return nil
}

func withEnvironment(base []string, replacements map[string]string) []string {
	result := make([]string, 0, len(base)+len(replacements))
	for _, entry := range base {
		name, _, found := strings.Cut(entry, "=")
		if found {
			if _, replace := replacements[name]; replace {
				continue
			}
		}
		result = append(result, entry)
	}
	for name, value := range replacements {
		result = append(result, name+"="+value)
	}
	return result
}

func runCosign(ctx context.Context, environment []string, stdout, stderr io.Writer, args ...string) error {
	command := exec.CommandContext(ctx, "cosign", args...)
	command.Env = environment
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("run cosign: %w", err)
	}
	return nil
}

func runSignArtifactCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("sign-artifact", flag.ContinueOnError)
	flags.SetOutput(stderr)
	authorityURL := flags.String("authority-url", defaultAuthorityURL, "Notme authority base URL (use https://<cloister>/identity for cluster-rooted trust)")
	audience := flags.String("audience", defaultOIDCAudience, "GitHub Actions OIDC audience")
	if err := flags.Parse(args); err != nil {
		return err
	}
	artifacts := flags.Args()
	if err := validateArtifactPaths(artifacts); err != nil {
		return err
	}

	enrolled, err := enrollGitHubSession(ctx, enrollConfig{
		AuthorityURL: *authorityURL,
		Audience:     *audience,
	})
	if err != nil {
		return err
	}
	defer enrolled.Destroy()
	return signArtifactsWithSession(ctx, enrolled, artifacts, runCosign, stdout, stderr)
}
