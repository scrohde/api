// main.go
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the saved configuration values for a specific host.
type Config struct {
	BaseURL  string            `yaml:"base"`
	Method   string            `yaml:"method"`
	Username string            `yaml:"username"`
	Password string            `yaml:"password"`
	Token    string            `yaml:"token"`
	CACert   string            `yaml:"cacert"`
	Cert     string            `yaml:"cert"`
	Key      string            `yaml:"key"`
	Body     string            `yaml:"body"`
	Headers  map[string]string `yaml:"headers"`
}

// SavedConfigs holds the mapping from normalized host to its configuration and the last used host.
type SavedConfigs struct {
	LastUsed string            `yaml:"last_used"`
	Configs  map[string]Config `yaml:"configs"`
}

// Options holds the command-line options.
type Options struct {
	BaseURL   string
	Method    string
	Username  string
	Password  string
	Token     string
	CACert    string
	Cert      string
	Key       string
	Body      string
	Headers   map[string]string
	Save      bool
	URLPath   string
	ReadStdin bool
}

// headerFlag allows repeatable -H options.
type headerFlag struct {
	headers map[string]string
}

func (h *headerFlag) String() string {
	var parts []string
	for k, v := range h.headers {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(parts, ", ")
}

func (h *headerFlag) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid header format (expected key:value): %s", value)
	}
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])
	if h.headers == nil {
		h.headers = make(map[string]string)
	}
	h.headers[key] = val
	return nil
}

// fatal prints an error message and exits.
func fatal(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
	os.Exit(1)
}

// getConfigPath returns the file path for the configuration file.
func getConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".api_config.yaml"), nil
}

// loadConfigs loads the YAML configuration from the config file.
func loadConfigs() (SavedConfigs, error) {
	sc := SavedConfigs{}
	configPath, err := getConfigPath()
	if err != nil {
		return sc, err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		// It's acceptable if the config file doesn't exist.
		sc.Configs = make(map[string]Config)
		return sc, nil
	}
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return sc, fmt.Errorf("error parsing config file: %w", err)
	}
	if sc.Configs == nil {
		sc.Configs = make(map[string]Config)
	}
	return sc, nil
}

// saveConfigs saves the configurations to the YAML config file.
func saveConfigs(sc SavedConfigs) error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(sc)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0600)
}

// setupTLSConfig returns a TLS configuration if mTLS parameters are provided.
func setupTLSConfig(certFile, keyFile, caCertFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate/key: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if caCertFile != "" {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("appending CA certificate")
		}
		tlsConfig.RootCAs = caPool
	}
	return tlsConfig, nil
}

// buildHTTPClient creates an HTTP client, configuring mTLS if needed.
func buildHTTPClient(cert, key, cacert string) (*http.Client, error) {
	tlsConfig, err := setupTLSConfig(cert, key, cacert)
	if err != nil {
		return nil, err
	}
	client := &http.Client{}
	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	return client, nil
}

// buildURL constructs the URL from a base and relative path.
func buildURL(base, rel string) (*url.URL, error) {
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}
	finalURL, err := baseURL.Parse(rel)
	if err != nil {
		return nil, fmt.Errorf("invalid URL path arg: %w", err)
	}
	return finalURL, nil
}

// readRequestBody reads the request body from the flag value or stdin.
func readRequestBody(flagBody string, readStdin bool) ([]byte, error) {
	if readStdin {
		return io.ReadAll(os.Stdin)
	}
	return []byte(flagBody), nil
}

// addJSONContentType adds a JSON Content-Type header if the body appears to be JSON.
func addJSONContentType(headers map[string]string, body []byte) {
	trimmed := strings.TrimSpace(string(body))
	if (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) && !hasContentType(headers) {
		headers["Content-Type"] = "application/json"
	}
}

func hasContentType(headers map[string]string) bool {
	for k := range headers {
		if strings.ToLower(k) == "content-type" {
			return true
		}
	}
	return false
}

// processResponse outputs the HTTP response.
func processResponse(resp *http.Response) error {
	defer resp.Body.Close()

	fmt.Fprintln(os.Stderr, resp.Request.Method, resp.Request.URL)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(contentType), "application/json") {
		fmt.Fprintln(os.Stderr, resp.Status)
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, body, "", "  "); err != nil {
			_, _ = os.Stdout.Write(body)
		} else {
			_, _ = os.Stdout.Write(pretty.Bytes())
		}
	} else {
		fmt.Println(resp.Status)
		_, _ = os.Stdout.Write(body)
	}
	return nil
}

// parseFlags parses command-line flags and returns an Options struct.
func parseFlags() Options {
	var hdrs = headerFlag{headers: make(map[string]string)}

	host := flag.String("host", "", "Base URL or hostname")
	method := flag.String("x", "", "HTTP method to use")
	username := flag.String("username", "", "Basic auth username")
	password := flag.String("password", "", "Basic auth password")
	token := flag.String("token", "", "Bearer token for Authorization header")
	cacert := flag.String("cacert", "", "CA certificate file for mTLS")
	cert := flag.String("cert", "", "Client certificate file for mTLS")
	key := flag.String("key", "", "Client key file for mTLS")
	body := flag.String("d", "", "Request body data (if it starts with { or [, Content-Type is set to application/json)")
	save := flag.Bool("save", false, "Save all flag values to the config file for reuse")

	flag.Var(&hdrs, "H", "Custom header in the form \"Key: Value\" (can be repeated)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] <url-path> [--]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing URL path argument")
		flag.Usage()
		os.Exit(1)
	}
	urlPath := args[0]

	// Check for "--" argument to signal reading body from stdin.
	readStdin := false
	for _, arg := range args[1:] {
		if arg == "--" {
			readStdin = true
			break
		}
	}

	return Options{
		BaseURL:   *host,
		Method:    *method,
		Username:  *username,
		Password:  *password,
		Token:     *token,
		CACert:    *cacert,
		Cert:      *cert,
		Key:       *key,
		Body:      *body,
		Headers:   hdrs.headers,
		Save:      *save,
		URLPath:   urlPath,
		ReadStdin: readStdin,
	}
}

// extractHost determines the host from the provided options or last used host.
func extractHost(baseURL, urlPath, lastUsed string) string {
	// Try to extract from baseURL.
	if baseURL != "" {
		if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	// Try to extract from urlPath.
	if u, err := url.Parse(urlPath); err == nil && u.Host != "" {
		return u.Host
	}
	// Fall back to last used.
	return lastUsed
}

// mergeConfig applies non-empty fields from the saved config to opts.
func mergeConfig(opts *Options, cfg Config) {
	if opts.BaseURL == "" {
		opts.BaseURL = cfg.BaseURL
	}
	if opts.Method == "" {
		opts.Method = cfg.Method
	}
	if opts.Username == "" {
		opts.Username = cfg.Username
	}
	if opts.Password == "" {
		opts.Password = cfg.Password
	}
	if opts.Token == "" {
		opts.Token = cfg.Token
	}
	if opts.CACert == "" {
		opts.CACert = cfg.CACert
	}
	if opts.Cert == "" {
		opts.Cert = cfg.Cert
	}
	if opts.Key == "" {
		opts.Key = cfg.Key
	}
	if opts.Body == "" {
		opts.Body = cfg.Body
	}
	if len(opts.Headers) == 0 && cfg.Headers != nil {
		opts.Headers = cfg.Headers
	}
}

func createRequest(opts Options, finalURL string, reqBody []byte) *http.Request {
	req, err := http.NewRequest(strings.ToUpper(opts.Method), finalURL, bytes.NewReader(reqBody))
	if err != nil {
		fatal("Error creating HTTP request", err)
	}
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}
	if opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
	} else if opts.Username != "" && opts.Password != "" {
		req.SetBasicAuth(opts.Username, opts.Password)
	}
	return req
}

func main() {
	// 1. Parse command-line flags.
	opts := parseFlags()

	// 2. Load saved configurations.
	savedConfigs, err := loadConfigs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load config: %v\n", err)
		savedConfigs = SavedConfigs{Configs: make(map[string]Config)}
	}

	// 3. Determine the effective host and merge saved config if available.
	host := extractHost(opts.BaseURL, opts.URLPath, savedConfigs.LastUsed)
	if cfg, exists := savedConfigs.Configs[host]; exists {
		mergeConfig(&opts, cfg)
	}
	// Set default HTTP method if still not provided.
	if opts.Method == "" {
		opts.Method = "GET"
	}

	// 4. Build the final URL.
	finalURL, err := buildURL(opts.BaseURL, opts.URLPath)
	if err != nil {
		fatal("Error building final URL", err)
	}

	// 5. Read and prepare the request body.
	reqBody, err := readRequestBody(opts.Body, opts.ReadStdin)
	if err != nil {
		fatal("Error reading request body", err)
	}
	addJSONContentType(opts.Headers, reqBody)

	// 6. Create and send the HTTP request.
	req := createRequest(opts, finalURL.String(), reqBody)
	client, err := buildHTTPClient(opts.Cert, opts.Key, opts.CACert)
	if err != nil {
		fatal("Error setting up HTTP client", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		fatal("Error making HTTP request", err)
	}
	if err := processResponse(resp); err != nil {
		fatal("Error processing response", err)
	}

	// 7. Optionally, save the effective configuration.
	if opts.Save {
		savedConfigs.Configs[finalURL.Host] = Config{
			BaseURL:  opts.BaseURL,
			Method:   strings.ToUpper(opts.Method),
			Username: opts.Username,
			Password: opts.Password,
			Token:    opts.Token,
			CACert:   opts.CACert,
			Cert:     opts.Cert,
			Key:      opts.Key,
			Body:     opts.Body,
			Headers:  opts.Headers,
		}
		savedConfigs.LastUsed = finalURL.Host
		if err := saveConfigs(savedConfigs); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
		}
	}
}
