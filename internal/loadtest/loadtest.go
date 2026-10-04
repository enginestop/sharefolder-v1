package loadtest

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sharefolder/internal/config"
	"sharefolder/internal/db"
	"sharefolder/internal/platform"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type M = map[string]any
type Options struct {
	BaseURL, Scenario, FixtureRoot, Report string
	Users, MetadataNodes                   int
	Duration                               time.Duration
}
type Client struct {
	HTTP       *http.Client
	Base, CSRF string
}

func New(base string) *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{HTTP: &http.Client{Jar: jar, Timeout: 150 * time.Second}, Base: base}
}
func (c *Client) call(method, path string, body any, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	switch v := body.(type) {
	case []byte:
		reader = bytes.NewReader(v)
	case nil:
	default:
		b, _ := json.Marshal(v)
		reader = bytes.NewReader(b)
	}
	r, e := http.NewRequest(method, c.Base+path, reader)
	if e != nil {
		return nil, e
	}
	r.Header.Set("Origin", c.Base)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", c.CSRF)
	if method != "GET" && method != "HEAD" {
		r.Header.Set("Idempotency-Key", db.ID())
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return c.HTTP.Do(r)
}
func (c *Client) json(method, path string, body any, headers map[string]string) (M, error) {
	r, e := c.call(method, path, body, headers)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	var v M
	if r.StatusCode != 204 {
		if e = json.NewDecoder(r.Body).Decode(&v); e != nil {
			return nil, e
		}
	}
	if r.StatusCode >= 400 {
		code := "HTTP_ERROR"
		if problem, ok := v["error"].(map[string]any); ok {
			code, _ = problem["code"].(string)
		}
		return nil, fmt.Errorf("HTTP %d %s", r.StatusCode, code)
	}
	return v, nil
}
func (c *Client) Login(username, password string) error {
	r, e := c.call("GET", "/login", nil, nil)
	if e != nil {
		return e
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, 65536))
	r.Body.Close()
	if e != nil {
		return e
	}
	nonce := regexp.MustCompile(`name="login-nonce" content="([^"]+)"`).FindStringSubmatch(string(body))
	if len(nonce) != 2 {
		return fmt.Errorf("nonce unavailable")
	}
	v, e := c.json("POST", "/api/v1/session", M{"username": username, "password": password}, map[string]string{"X-Login-Nonce": nonce[1]})
	if e != nil {
		return e
	}
	c.CSRF = v["csrf_token"].(string)
	return nil
}
func (c *Client) Upload(parent, workspace, name string, source io.Reader, size int64) (M, error) {
	u, e := c.json("POST", "/api/v1/uploads", M{"parent_id": parent, "workspace_id": workspace, "name": name, "size_bytes": strconv.FormatInt(size, 10), "last_modified_ms": 0}, nil)
	if e != nil {
		return nil, e
	}
	id := u["id"].(string)
	buffer := make([]byte, 8388608)
	for offset := int64(0); offset < size; {
		length := min(int64(len(buffer)), size-offset)
		n, e := io.ReadFull(source, buffer[:length])
		if e != nil {
			return nil, e
		}
		h := sha256.Sum256(buffer[:n])
		_, e = c.json("PATCH", "/api/v1/uploads/"+id, buffer[:n], map[string]string{"Content-Type": "application/offset+octet-stream", "Upload-Offset": strconv.FormatInt(offset, 10), "Upload-Checksum": "sha256 " + hex.EncodeToString(h[:])})
		if e != nil {
			return nil, e
		}
		offset += int64(n)
	}
	v, e := c.json("GET", "/api/v1/uploads/"+id, nil, nil)
	if e != nil {
		return nil, e
	}
	u = v["upload"].(map[string]any)
	_, e = c.json("POST", "/api/v1/uploads/"+id+"/complete", M{"manifest_sha256": u["manifest_sha256"]}, nil)
	if e != nil {
		return nil, e
	}
	for i := 0; i < 120; i++ {
		v, e = c.json("GET", "/api/v1/uploads/"+id, nil, nil)
		if e != nil {
			return nil, e
		}
		u = v["upload"].(map[string]any)
		if u["state"] == "COMPLETE" {
			return c.json("GET", "/api/v1/nodes/"+u["node_id"].(string), nil, nil)
		}
		if u["state"] == "FAILED" {
			return nil, fmt.Errorf("upload failed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("upload completion timeout")
}
func (c *Client) Delete(n M) error {
	id := n["id"].(string)
	headers := map[string]string{"If-Match": fmt.Sprintf(`"r%.0f"`, n["revision"].(float64))}
	v, e := c.json("POST", "/api/v1/nodes/"+id+"/trash", M{}, headers)
	if e != nil {
		return e
	}
	headers["If-Match"] = fmt.Sprintf(`"r%.0f"`, v["revision"].(float64))
	_, e = c.json("POST", "/api/v1/nodes/"+id+"/purge", M{"confirm_name": n["name"]}, headers)
	return e
}
func Run(options Options) error {
	u, e := url.Parse(options.BaseURL)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid test base URL")
	}
	admin := New(options.BaseURL)
	if e = admin.Login("admin", "LocalOnly-Admin!2026"); e != nil {
		return e
	}
	instance, e := admin.json("GET", "/api/v1/admin/test-instance", nil, nil)
	if e != nil || instance["fixture"] != "office-demo" || instance["instance_id"] != "00000000-0000-4000-8000-000000009999" {
		return fmt.Errorf("refusing unbound or production instance")
	}
	report := M{"scenario": options.Scenario, "started_at": time.Now().UTC().Format(time.RFC3339), "base_url": options.BaseURL, "instance_id": instance["instance_id"], "full_capacity_acceptance": false}
	var runErr error
	switch options.Scenario {
	case "large-file":
		runErr = large(options, report)
	case "mixed":
		runErr = mixed(options, report)
	case "transfer-stress":
		_, free, e := platform.Disk(options.FixtureRoot)
		if e != nil {
			return e
		}
		if free < 60*1024*1024*1024 {
			return fmt.Errorf("stress requires at least 60 GiB free")
		}
		return fmt.Errorf("full 50-user stress requires separately provisioned capacity and is deferred")
	default:
		return fmt.Errorf("invalid scenario")
	}
	report["passed"] = runErr == nil
	if runErr != nil {
		report["error"] = runErr.Error()
	}
	report["finished_at"] = time.Now().UTC().Format(time.RFC3339)
	if e = os.MkdirAll(filepath.Dir(options.Report), 0700); e != nil {
		return e
	}
	b, _ := json.MarshalIndent(report, "", "  ")
	if e = os.WriteFile(options.Report, b, 0600); e != nil {
		return e
	}
	fmt.Printf("scenario=%s passed=%t report=%s\n", options.Scenario, runErr == nil, options.Report)
	return runErr
}
func large(o Options, report M) error {
	const total int64 = 10 * 1024 * 1024 * 1024
	if !filepath.IsAbs(o.FixtureRoot) {
		return fmt.Errorf("fixture-root must be absolute")
	}
	if e := config.SafePath(o.FixtureRoot); e != nil {
		return e
	}
	if e := os.MkdirAll(o.FixtureRoot, 0700); e != nil {
		return e
	}
	marker := filepath.Join(o.FixtureRoot, "instance_id")
	expected := []byte("00000000-0000-4000-8000-000000009999\n")
	if b, e := os.ReadFile(marker); e == nil {
		if !bytes.Equal(b, expected) {
			return fmt.Errorf("foreign fixture marker")
		}
	} else if os.IsNotExist(e) {
		entries, e := os.ReadDir(o.FixtureRoot)
		if e != nil || len(entries) > 0 {
			return fmt.Errorf("fixture root must be empty before binding")
		}
		if e = os.WriteFile(marker, expected, 0600); e != nil {
			return e
		}
	} else {
		return e
	}
	_, free, e := platform.Disk(o.FixtureRoot)
	if e != nil {
		return e
	}
	if free < total+5*1024*1024*1024 {
		return fmt.Errorf("insufficient fixture capacity")
	}
	c := New(o.BaseURL)
	if e = c.Login("pegawai-a", "LocalOnly-Staff!2026"); e != nil {
		return e
	}
	admin := New(o.BaseURL)
	if e = admin.Login("admin", "LocalOnly-Admin!2026"); e != nil {
		return e
	}
	capacity, e := admin.json("GET", "/api/v1/admin/capacity", nil, nil)
	if e != nil {
		return e
	}
	available, e := strconv.ParseInt(capacity["usable_bytes"].(string), 10, 64)
	if e != nil || available < total {
		return fmt.Errorf("insufficient server capacity")
	}
	report["capacity_before"] = capacity
	path := filepath.Join(o.FixtureRoot, "source-"+db.ID()+".bin")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	buffer := make([]byte, 256*1024)
	if _, e = rand.Read(buffer); e != nil {
		f.Close()
		return e
	}
	sourceHash := sha256.New()
	for written := int64(0); written < total; written += int64(len(buffer)) {
		if _, e = f.Write(buffer); e != nil {
			f.Close()
			return e
		}
		sourceHash.Write(buffer)
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	f.Close()
	f, e = os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	begin := time.Now()
	node, e := c.Upload("00000000-0000-4000-8000-000000000201", "00000000-0000-4000-8000-000000000101", "large-file-"+db.ID()+".bin", f, total)
	if e != nil {
		return e
	}
	uploadTime := time.Since(begin)
	f.Close()
	begin = time.Now()
	res, e := c.call("GET", "/api/v1/nodes/"+node["id"].(string)+"/content", nil, nil)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("download status %d", res.StatusCode)
	}
	downloadHash := sha256.New()
	received, e := io.CopyBuffer(downloadHash, res.Body, make([]byte, 256*1024))
	if e != nil {
		return e
	}
	downloadTime := time.Since(begin)
	if received != total || !bytes.Equal(sourceHash.Sum(nil), downloadHash.Sum(nil)) {
		return fmt.Errorf("large file digest mismatch")
	}
	report["size_bytes"] = strconv.FormatInt(total, 10)
	report["sha256"] = hex.EncodeToString(sourceHash.Sum(nil))
	report["upload_seconds"] = uploadTime.Seconds()
	report["download_seconds"] = downloadTime.Seconds()
	report["upload_mib_s"] = float64(total) / uploadTime.Seconds() / 1048576
	report["download_mib_s"] = float64(total) / downloadTime.Seconds() / 1048576
	report["real_non_sparse_transfer"] = true
	if e = c.Delete(node); e != nil {
		return e
	}
	b, e := os.ReadFile(marker)
	if e != nil || !bytes.Equal(b, expected) || filepath.Dir(path) != filepath.Clean(o.FixtureRoot) {
		return fmt.Errorf("cleanup containment/marker failed")
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	report["source_fixture_removed"] = true
	return nil
}
func mixed(o Options, report M) error {
	if o.Users < 1 || o.Users > 4 || o.Duration < time.Second || o.MetadataNodes < 0 || o.MetadataNodes > 10000 {
		return fmt.Errorf("bounded mixed test supports 1-4 fixture users and up to 10000 nodes")
	}
	names := []string{"admin", "pegawai-a", "pegawai-b", "pegawai-c"}
	clients := []*Client{}
	for i := 0; i < o.Users; i++ {
		c := New(o.BaseURL)
		password := "LocalOnly-Staff!2026"
		if i == 0 {
			password = "LocalOnly-Admin!2026"
		}
		if e := c.Login(names[i], password); e != nil {
			return e
		}
		clients = append(clients, c)
	}
	owner := New(o.BaseURL)
	if e := owner.Login("pegawai-a", "LocalOnly-Staff!2026"); e != nil {
		return e
	}
	folder, e := owner.json("POST", "/api/v1/folders", M{"workspace_id": "00000000-0000-4000-8000-000000000101", "parent_id": "00000000-0000-4000-8000-000000000201", "name": "load-" + db.ID()}, nil)
	if e != nil {
		return e
	}
	for i := 0; i < o.MetadataNodes; i++ {
		if _, e = owner.json("POST", "/api/v1/folders", M{"workspace_id": folder["workspace_id"], "parent_id": folder["id"], "name": fmt.Sprintf("node-%06d", i)}, nil); e != nil {
			return e
		}
	}
	payload := bytes.Repeat([]byte("test-transfer-00"), 1024*1024)
	node, e := owner.Upload(folder["id"].(string), folder["workspace_id"].(string), "payload.bin", bytes.NewReader(payload), int64(len(payload)))
	if e != nil {
		return e
	}
	var mu sync.Mutex
	var timings []float64
	var failures, requests int
	var transferred int64
	end := time.Now().Add(o.Duration)
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func(index int, c *Client) {
			defer wg.Done()
			for time.Now().Before(end) {
				start := time.Now()
				_, e := c.json("GET", "/api/v1/search?q=node&limit=50", nil, nil)
				elapsed := time.Since(start).Seconds() * 1000
				mu.Lock()
				requests++
				timings = append(timings, elapsed)
				if e != nil {
					failures++
				}
				mu.Unlock()
				if index == 0 || index == 1 {
					res, e := c.call("GET", "/api/v1/nodes/"+node["id"].(string)+"/content", nil, nil)
					if e == nil {
						n, readErr := io.Copy(io.Discard, res.Body)
						res.Body.Close()
						mu.Lock()
						if res.StatusCode == 200 && readErr == nil {
							transferred += n
						} else {
							failures++
						}
						mu.Unlock()
					} else {
						mu.Lock()
						failures++
						mu.Unlock()
					}
				}
			}
		}(i, c)
	}
	wg.Wait()
	sort.Float64s(timings)
	report["users"] = o.Users
	report["metadata_nodes"] = o.MetadataNodes
	report["duration_seconds"] = o.Duration.Seconds()
	report["metadata_requests"] = requests
	report["unexpected_errors"] = failures
	report["metadata_p95_ms"] = timings[min(len(timings)-1, int(float64(len(timings))*.95))]
	report["metadata_p99_ms"] = timings[min(len(timings)-1, int(float64(len(timings))*.99))]
	report["download_mib_s"] = float64(transferred) / o.Duration.Seconds() / 1048576
	report["scope"] = "bounded metadata and download workload; full mixed/stress pending"
	if e = owner.Delete(folder); e != nil {
		return e
	}
	if failures > 0 {
		return fmt.Errorf("%d unexpected errors", failures)
	}
	return nil
}

var _ = strings.Compare
