package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// This file provides a tiny HTTP server using Fiber to experiment with
// command-injection defenses. Routes:
//  - GET /vuln?ip=<value> : vulnerable example that invokes the shell (unsafe)
//  - GET /safe?ip=<value> : safe example that validates input and runs command

func vulnHandler(c *fiber.Ctx) error {
	ip := c.Query("ip")
	if ip == "" {
		return c.Status(400).SendString("missing ip parameter")
	}
	// Vulnerable: constructs a shell command using user input
	cmdStr := "ping -c 1 " + ip
	out, err := exec.Command("/bin/sh", "-c", cmdStr).CombinedOutput()
	if err != nil {
		return c.Status(500).SendString(fmt.Sprintf("command error: %v, output: %s", err, out))
	}
	return c.Status(200).Send(out)
}

// var ipv4Regexp = regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`)

func safeHandler(c *fiber.Ctx) error {
	ip := c.Query("ip")
	if ip == "" {
		return c.Status(400).SendString("missing ip parameter")
	}
	// Input validation: simple IPv4 regex (note: not full validation of octet range)
	// if !ipv4Regexp.MatchString(ip) {
	//	return c.Status(400).SendString("invalid ip format")
	// }
	// Blacklist check: block obvious injection patterns
	if contains := regexp.MustCompile(`(?i)\bwhoami\b|\|`).MatchString(ip); contains {
		return c.Status(400).SendString("input blocked by blacklist: suspicious token detected")
	}
	// Safe: run ping without a shell by passing args directly
	out, err := exec.Command("ping", "-c", "1", ip).CombinedOutput()
	if err != nil {
		return c.Status(500).SendString(fmt.Sprintf("command error: %v, output: %s", err, out))
	}
	return c.Status(200).Send(out)
}

func startServer() *fiber.App {
	app := fiber.New()
	app.Get("/vuln", vulnHandler)
	app.Get("/safe", safeHandler)
	go func() {
		log.Printf("starting fiber server on :8080")
		if err := app.Listen(":8080"); err != nil {
			log.Fatalf("fiber server failed: %v", err)
		}
	}()
	return app
}

func TestServerEndpoints(t *testing.T) {
	_ = startServer()

	// Simple smoke test on /safe (should return 200 or command error if ping not permitted)
	resp, err := http.Get("http://localhost:8080/safe?ip=127.0.0.1")
	if err != nil {
		t.Fatalf("failed to GET /safe: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("/safe status=%d body=%s", resp.StatusCode, string(body))

	// Test /vuln endpoint as well
	resp2, err := http.Get("http://localhost:8080/vuln?ip=127.0.0.1")
	if err != nil {
		t.Fatalf("failed to GET /vuln: %v", err)
	}
	defer resp2.Body.Close()
	b2, _ := io.ReadAll(resp2.Body)
	t.Logf("/vuln status=%d body=%s", resp2.StatusCode, string(b2))
}

func main() {
	app := startServer()
	defer app.Shutdown()
	select {}
}
