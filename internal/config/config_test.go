package config

import (
	"path/filepath"
	"testing"
)

func TestGuards(t *testing.T) {
	root := t.TempDir()
	c := Config{Env: "test", Listen: "127.0.0.1:18080", Origin: "http://127.0.0.1:18080", Metadata: filepath.Join(root, "state"), Data: filepath.Join(root, "data")}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	if c.OriginForHost("sf.cloudserver.my.id") != "https://sf.cloudserver.my.id" || c.OriginForHost("files.example.net") != "https://files.example.net" || c.OriginForHost("127.0.0.1:18080") != c.Origin {
		t.Fatal("origin host mapping is incorrect")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Listen = "0.0.0.0:18080" }, func(c *Config) { c.Origin = "http://user:password@localhost" }, func(c *Config) { c.Data = "relative" }, func(c *Config) { c.Env = "production" }, func(c *Config) { c.Env = "staging" }} {
		bad := c
		mutate(&bad)
		if e := bad.Validate(); e == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
	for _, host := range []string{"evil.example:8443", "localhost", "127.0.0.2", "192.168.1.1", "example..org", "-bad.example", "bad-.example", "example.123", "example.org/extra", "example.org@evil.net", "[::1]", "example.org."} {
		if got := c.OriginForHost(host); got != "" {
			t.Fatalf("unsafe host accepted: %s -> %s", host, got)
		}
	}
}
