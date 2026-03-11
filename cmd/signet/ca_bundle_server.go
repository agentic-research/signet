package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/agentic-research/signet/pkg/revocation/types"
	"github.com/spf13/cobra"
)

var caBundleServerCmd = &cobra.Command{
	Use:   "ca-bundle-server",
	Short: "Run a simple CA bundle server",
	RunE:  runCABundleServer,
}

func init() {
	rootCmd.AddCommand(caBundleServerCmd)
}

func runCABundleServer(cmd *cobra.Command, args []string) error {
	bundle := &types.CABundle{
		Epoch: 1,
		Seqno: 1,
		Keys:  make(map[string][]byte),
	}

	http.HandleFunc("/ca-bundle", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(bundle); err != nil {
			log.Printf("failed to encode bundle: %v", err)
		}
	})

	fmt.Println("CA bundle server listening on :8443")
	return http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil)
}
