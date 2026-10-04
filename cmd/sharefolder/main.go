package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sharefolder/internal/app"
	"sharefolder/internal/auth"
	"sharefolder/internal/config"
	"sharefolder/internal/db"
	"sharefolder/internal/loadtest"
	"sharefolder/internal/platform"
	"strings"
	"syscall"
	"time"
)

var version = "0.1.5"

type commandError struct {
	code int
	error
}

func exitError(code int, e error) error {
	if e == nil {
		return nil
	}
	return &commandError{code, e}
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		var ce *commandError
		if errors.As(e, &ce) {
			os.Exit(ce.code)
		}
		os.Exit(1)
	}
}
func output(v any) { json.NewEncoder(os.Stdout).Encode(v) }
func run() error {
	args := os.Args[1:]
	envFile := ""
	if len(args) >= 2 && args[0] == "--env-file" {
		envFile = args[1]
		args = args[2:]
	}
	if len(args) == 0 {
		return exitError(2, fmt.Errorf("command required: version, doctor, migrate, bootstrap-admin, seed, serve, stop, verify-storage"))
	}
	command := args[0]
	if command == "loadtest" {
		if os.Getenv("APP_ENV") != "test" {
			return fmt.Errorf("loadtest requires APP_ENV=test")
		}
		f := flag.NewFlagSet(command, flag.ContinueOnError)
		o := loadtest.Options{}
		f.StringVar(&o.BaseURL, "base-url", "", "")
		f.StringVar(&o.Scenario, "scenario", "mixed", "")
		f.StringVar(&o.FixtureRoot, "fixture-root", "", "")
		f.StringVar(&o.Report, "report", "test-results/load.json", "")
		f.IntVar(&o.Users, "users", 4, "")
		f.IntVar(&o.MetadataNodes, "metadata-nodes", 1000, "")
		f.DurationVar(&o.Duration, "duration", time.Minute, "")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		return loadtest.Run(o)
	}
	if command == "version" {
		output(map[string]any{"version": version, "go": runtime.Version(), "schema": 1, "build_id": version})
		return nil
	}
	c, e := config.Load(envFile)
	if e != nil {
		return exitError(2, e)
	}
	if command == "stop" {
		if c.Env == "production" {
			return fmt.Errorf("use systemctl stop sharefolder")
		}
		b, e := os.ReadFile(filepath.Join(c.Metadata, "control.json"))
		if e != nil {
			return e
		}
		var v map[string]string
		if e = json.Unmarshal(b, &v); e != nil {
			return e
		}
		req, e := http.NewRequest("POST", v["url"], nil)
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+v["token"])
		client := http.Client{Timeout: 5 * time.Second}
		res, e := client.Do(req)
		if e != nil {
			return e
		}
		defer res.Body.Close()
		if res.StatusCode != 204 {
			return fmt.Errorf("stop rejected")
		}
		return nil
	}
	if command == "doctor" {
		if e = db.Doctor(c); e != nil {
			return exitError(3, e)
		}
		for _, path := range []string{c.Metadata, c.Data} {
			if e = config.SafePath(path); e != nil {
				return e
			}
			if _, e = os.Stat(path); e != nil {
				return e
			}
			_, free, e := platform.Disk(path)
			if e != nil {
				return e
			}
			if free < 2*1024*1024*1024 {
				return fmt.Errorf("insufficient free storage")
			}
		}
		output(map[string]any{"status": "ok", "os": runtime.GOOS, "arch": runtime.GOARCH, "environment": c.Env})
		return nil
	}
	d, e := db.Open(c, command == "migrate")
	if e != nil {
		return exitError(3, e)
	}
	defer d.Close()
	a := app.New(c, d)
	a.Log = os.Stdout
	switch command {
	case "admin-status":
		var count int
		if e = d.Read.QueryRow("SELECT count(*) FROM users WHERE role='admin'").Scan(&count); e != nil {
			return e
		}
		output(map[string]any{"admin_exists": count > 0})
		return nil
	case "migrate":
		if e = d.Migrate(); e != nil {
			return exitError(3, e)
		}
		output(map[string]any{"status": "migrated", "schema": 1})
		return nil
	case "bootstrap-admin":
		f := flag.NewFlagSet(command, flag.ContinueOnError)
		username := f.String("username", "", "")
		display := f.String("display-name", "", "")
		stdin := f.Bool("password-stdin", false, "")
		if e = f.Parse(args[1:]); e != nil {
			return exitError(2, e)
		}
		if !*stdin {
			return exitError(2, fmt.Errorf("--password-stdin required"))
		}
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 65537))
		if e != nil {
			return e
		}
		if len(b) > 65536 {
			return exitError(2, fmt.Errorf("stdin request exceeds 64 KiB"))
		}
		e = a.Bootstrap(*username, *display, strings.TrimRight(string(b), "\r\n"))
		if e == nil {
			output(map[string]string{"status": "admin_created"})
		}
		if e != nil && e.Error() == "admin already exists" {
			return exitError(4, e)
		}
		var invalid *app.Problem
		if errors.As(e, &invalid) {
			return exitError(2, e)
		}
		return exitError(3, e)
	case "seed":
		f := flag.NewFlagSet(command, flag.ContinueOnError)
		fixture := f.String("fixture", "", "")
		if e = f.Parse(args[1:]); e != nil {
			return e
		}
		if *fixture != "office-demo" {
			return fmt.Errorf("unknown fixture")
		}
		if e = a.Seed(); e != nil {
			return exitError(4, e)
		}
		return d.Verify()
	case "verify-storage":
		if e = d.Verify(); e != nil {
			return e
		}
		if e = a.VerifyStorage(); e != nil {
			return e
		}
		output(map[string]string{"status": "consistent"})
		return nil
	case "serve":
		if e = a.Start(); e != nil {
			return e
		}
		defer a.Close()
		server := &http.Server{Addr: c.Listen, Handler: a, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if c.Env != "production" {
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				return e
			}
			defer listener.Close()
			token := auth.Token()
			control := http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || !auth.Equal(r.Header.Get("Authorization"), "Bearer "+token) {
					w.WriteHeader(403)
					return
				}
				w.WriteHeader(204)
				cancel()
			})}
			defer control.Close()
			b, _ := json.Marshal(map[string]string{"url": "http://" + listener.Addr().String(), "token": token})
			if e = os.WriteFile(filepath.Join(c.Metadata, "control.json"), b, 0600); e != nil {
				return e
			}
			defer os.Remove(filepath.Join(c.Metadata, "control.json"))
			go control.Serve(listener)
		}
		errs := make(chan error, 1)
		go func() {
			if c.Cert != "" && c.Key != "" {
				errs <- server.ListenAndServeTLS(c.Cert, c.Key)
			} else {
				errs <- server.ListenAndServe()
			}
		}()
		output(map[string]string{"event": "started"})
		select {
		case e = <-errs:
			if e != http.ErrServerClosed {
				return e
			}
		case <-ctx.Done():
			shutdown, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			if e = server.Shutdown(shutdown); e != nil {
				server.Close()
				return e
			}
		}
		return nil
	}
	return fmt.Errorf("unknown command")
}
