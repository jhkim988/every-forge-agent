package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	portFlag := flag.String("port", "", "Server port (default: 9921)")
	tokenFlag := flag.String("token", "", "Custom security token (optional)")
	devFlag := flag.Bool("dev", false, "Enable development mode (allows preview subdomains)")
	flag.Parse()

	port := *portFlag
	if port == "" {
		port = os.Getenv("PORT")
		if port == "" {
			port = "9921"
		}
	}

	token := *tokenFlag
	if token == "" {
		token = os.Getenv("EF_TOKEN")
	}

	isDev := *devFlag || os.Getenv("EF_DEV") == "true" || os.Getenv("NODE_ENV") == "development"

	agent := NewAgentServer(token, isDev)

	fmt.Println("======================================================")
	fmt.Println("  ⚡ Every-Forge Ultra-Lightweight Local Bridge Agent")
	fmt.Println("======================================================")
	fmt.Printf("  • Environment: %s\n", map[bool]string{true: "Development", false: "Production"}[isDev])
	fmt.Printf("  • Listening On: http://127.0.0.1:%s\n", port)
	fmt.Printf("  • Allowed Origins: https://every-forge.com, https://www.every-forge.com, http://localhost:*\n")
	fmt.Printf("  • Security Token (X-EF-Token): %s\n", agent.Token)
	fmt.Println("  • Features: Native CORS Proxy | Process & Ports | Local Cron | Chrome PNA")
	fmt.Println("======================================================")
	fmt.Println("  Ready. Press Ctrl+C to terminate.")

	server := &http.Server{
		Addr:         "127.0.0.1:" + port,
		Handler:      agent.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 35 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Agent server error: %v", err)
		}
	}()

	<-ctx.Done()
	fmt.Println("\n  Shutting down gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
