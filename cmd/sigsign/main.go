package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jamestexas/signet/pkg/cms"
	"github.com/jamestexas/signet/pkg/crypto/keys"
)

func main() {
	var (
		signCmd   = flag.NewFlagSet("sign", flag.ExitOnError)
		verifyCmd = flag.NewFlagSet("verify", flag.ExitOnError)

		// Sign flags
		formatFlag = signCmd.String("format", "cms", "Output format: cms, cose, signet")
		keyFlag    = signCmd.String("key", "", "Path to signing key")

		// Verify flags
		sigFlag = verifyCmd.String("sig", "", "Path to signature file")
	)

	if len(os.Args) < 2 {
		fmt.Println("Usage: sigsign <sign|verify> [options] <file>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "sign":
		signCmd.Parse(os.Args[2:])
		if signCmd.NArg() != 1 {
			fmt.Println("Usage: sigsign sign [options] <file>")
			os.Exit(1)
		}

		// TODO: Load key, generate ephemeral cert, sign data
		fmt.Printf("Signing %s with format %s\n", signCmd.Arg(0), *formatFlag)

	case "verify":
		verifyCmd.Parse(os.Args[2:])
		// TODO: Implement verification
		fmt.Println("Verification not yet implemented")

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}