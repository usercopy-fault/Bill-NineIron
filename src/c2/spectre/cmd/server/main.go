package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"github.com/sbu/spectre-c2/pkg/db"
	pb "github.com/sbu/spectre-c2/pkg/proto"
	"github.com/sbu/spectre-c2/pkg/server"
)

var (
	flagAddr    = flag.String("addr", ":7443", "gRPC listen address")
	flagDB      = flag.String("db", "/var/lib/spectre/spectre.db", "SQLite database path")
	flagWebAddr = flag.String("web", ":8080", "Web dashboard address (reserved)")
)

func main() {
	flag.Parse()

	// Ensure DB directory exists (best-effort; will fail gracefully below).
	if err := os.MkdirAll("/var/lib/spectre", 0700); err != nil {
		log.Printf("[!] Cannot create /var/lib/spectre: %v (continuing)", err)
	}

	store, err := db.Open(*flagDB)
	if err != nil {
		log.Fatalf("[!] Database: %v", err)
	}
	defer store.Close()
	log.Printf("[*] Database: %s", *flagDB)

	srv := server.New(store)

	lis, err := net.Listen("tcp", *flagAddr)
	if err != nil {
		log.Fatalf("[!] Listen %s: %v", *flagAddr, err)
	}

	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(64*1024*1024),
		grpc.MaxSendMsgSize(64*1024*1024),
	)
	pb.RegisterAgentServiceServer(gs, srv)
	pb.RegisterOperatorServiceServer(gs, srv)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		fmt.Printf("[*] SPECTRE-C2 server listening on %s\n", *flagAddr)
		_ = *flagWebAddr // reserved for future web dashboard
		if err := gs.Serve(lis); err != nil {
			log.Printf("[!] gRPC serve: %v", err)
		}
	}()

	<-ctx.Done()
	fmt.Println("\n[*] Shutting down...")
	gs.GracefulStop()
	fmt.Println("[*] Server stopped.")
}
