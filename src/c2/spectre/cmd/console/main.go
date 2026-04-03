package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"

	"github.com/sbu/spectre-c2/pkg/console"
	"github.com/sbu/spectre-c2/pkg/db"
)

var (
	flagServer   = flag.String("server", "127.0.0.1:7443", "SPECTRE server gRPC address")
	flagOperator = flag.String("operator", "", "Operator name (default: system username)")
	flagDB       = flag.String("db", "/var/lib/spectre/spectre.db", "Local SQLite path for db command")
)

func main() {
	flag.Parse()

	operatorID := *flagOperator
	if operatorID == "" {
		u, err := user.Current()
		if err == nil {
			operatorID = u.Username
		} else {
			operatorID = "operator"
		}
	}

	// Open local DB for db command passthrough.
	// Fall back to in-memory if the db file does not exist yet.
	dbPath := *flagDB
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		dbPath = ":memory:"
	}
	store, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("[!] Local DB: %v", err)
	}
	defer store.Close()

	fmt.Printf("SPECTRE-C2 Console | operator: %s | server: %s\n", operatorID, *flagServer)

	if err := console.Start(*flagServer, operatorID, store); err != nil {
		log.Fatalf("[!] Console: %v", err)
	}
}
