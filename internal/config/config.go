package config

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sharefolder/internal/platform"
	"strings"
	"time"
)

type Config struct{ Env, Listen, Origin, Metadata, Data, Cert, Key, TestID string }

var allowed = map[string]bool{"RF_LISTEN": true, "RF_PUBLIC_ORIGIN": true, "RF_METADATA_DIR": true, "RF_DATA_DIR": true, "RF_TLS_CERT_FILE": true, "RF_TLS_KEY_FILE": true, "RF_TEST_INSTANCE_ID": true}

func Load(envFile string) (Config, error) {
	values := map[string]string{}
	for _, e := range os.Environ() {
		k, v, _ := strings.Cut(e, "=")
		if strings.HasPrefix(k, "RF_") && !allowed[k] {
			return Config{}, fmt.Errorf("unknown configuration: %s", k)
		}
		values[k] = v
	}
	if envFile != "" {
		f, e := os.Open(envFile)
		if e != nil {
			return Config{}, e
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || (!allowed[k] && k != "APP_ENV" && k != "GOMAXPROCS" && k != "GOMEMLIMIT") {
				return Config{}, fmt.Errorf("invalid env file entry")
			}
			values[k] = v
		}
		if e = s.Err(); e != nil {
			return Config{}, e
		}
	}
	cwd, e := os.Getwd()
	if e != nil {
		return Config{}, e
	}
	val := func(k, d string) string {
		if v := values[k]; v != "" {
			return v
		}
		return d
	}
	c := Config{Env: val("APP_ENV", "development"), Listen: val("RF_LISTEN", "127.0.0.1:8080"), Origin: val("RF_PUBLIC_ORIGIN", "http://127.0.0.1:8080"), Metadata: val("RF_METADATA_DIR", filepath.Join(cwd, ".local", "dev", "metadata")), Data: val("RF_DATA_DIR", filepath.Join(cwd, ".local", "dev", "data")), Cert: values["RF_TLS_CERT_FILE"], Key: values["RF_TLS_KEY_FILE"], TestID: values["RF_TEST_INSTANCE_ID"]}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.Env != "development" && c.Env != "test" && c.Env != "production" {
		return fmt.Errorf("invalid APP_ENV")
	}
	u, e := parseOrigin(c.Origin)
	if e != nil {
		return fmt.Errorf("invalid public origin")
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil {
		return fmt.Errorf("invalid listen address")
	}
	if c.Env != "production" && host != "127.0.0.1" {
		return fmt.Errorf("development/test must bind IPv4 loopback")
	}
	for _, p := range []string{c.Metadata, c.Data} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("storage paths must be absolute and clean")
		}
		if e := SafePath(p); e != nil {
			return e
		}
	}
	if c.Metadata == c.Data {
		return fmt.Errorf("metadata and data directories must differ")
	}
	if c.Env == "production" {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			return fmt.Errorf("production requires linux/amd64")
		}
		if u.Scheme != "https" || c.TestID != "" {
			return fmt.Errorf("unsafe production configuration")
		}
		if !filepath.IsAbs(c.Cert) || !filepath.IsAbs(c.Key) {
			return fmt.Errorf("absolute TLS paths required")
		}
		if e := SafePath(c.Key); e != nil {
			return e
		}
		if e := platform.Private(c.Key); e != nil {
			return e
		}
		pair, e := tls.LoadX509KeyPair(c.Cert, c.Key)
		if e != nil {
			return fmt.Errorf("TLS certificate/key invalid")
		}
		cert, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			return e
		}
		if e = cert.VerifyHostname(u.Hostname()); e != nil {
			return e
		}
		if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return fmt.Errorf("TLS certificate not currently valid")
		}
	}
	return nil
}
func parseOrigin(value string) (*url.URL, error) {
	u, e := url.Parse(value)
	if e != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" {
		return nil, fmt.Errorf("invalid origin")
	}
	return u, nil
}
func (c Config) OriginForHost(host string) string {
	u, e := parseOrigin(c.Origin)
	if e == nil && host == u.Host {
		return c.Origin
	}
	name := strings.ToLower(strings.TrimSuffix(host, ":443"))
	if !validPublicHostname(name) {
		return ""
	}
	return "https://" + name
}
func validPublicHostname(name string) bool {
	if len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	if strings.IndexFunc(labels[len(labels)-1], func(char rune) bool { return char >= 'a' && char <= 'z' }) < 0 {
		return false
	}
	return true
}
func SafePath(p string) error {
	for current := filepath.Clean(p); ; current = filepath.Dir(current) {
		i, e := os.Lstat(current)
		if e == nil && i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink/reparse path rejected")
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}
