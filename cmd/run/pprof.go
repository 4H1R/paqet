//go:build pprof

package run

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
)

// Builds with -tags pprof serve net/http/pprof on $PAQET_PPROF (for
// example 127.0.0.1:6060), for profiling and for collecting PGO profiles.
// The tag keeps net/http out of release binaries.
func init() {
	addr := os.Getenv("PAQET_PPROF")
	if addr == "" {
		return
	}
	go func() {
		log.Printf("pprof listening on %s", addr)
		log.Println(http.ListenAndServe(addr, nil))
	}()
}
