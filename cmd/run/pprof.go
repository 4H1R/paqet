//go:build pprof

package run

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
)

// With -tags pprof, paqet serves net/http/pprof on $PAQET_PPROF (e.g.
// 127.0.0.1:6060). The tag keeps net/http out of release builds.
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
