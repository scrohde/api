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

// Config holds the saved configuration values.
type Config struct {
	Host     string            `yaml:"host"`
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

// headerFlag is a custom flag type to allow repeatable -H options.
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

// getConfigPath returns the file path for the configuration file.
func getConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".api_config.yaml"), nil
}

// loadConfig loads the YAML configuration from the config file (if it exists).
func loadConfig() (*Config, error) {
	cfg := &Config{}
	configPath, err := getConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		// It's acceptable if the config file doesn't exist.
		return cfg, nil
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}
	return cfg, nil
}

// saveConfig saves the configuration to the YAML config file.
func saveConfig(cfg *Config) error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
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
	client := &http.Client{}
	tlsConfig, err := setupTLSConfig(cert, key, cacert)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	return client, nil
}

// buildFinalURL constructs the final URL from a host and URL path.
func buildFinalURL(host, urlPath string) (string, error) {
	if strings.HasPrefix(urlPath, "http://") || strings.HasPrefix(urlPath, "https://") {
		return urlPath, nil
	}
	if host == "" {
		return "", fmt.Errorf("no host specified and URL path is not a full URL")
	}
	// Assume HTTPS if no scheme is provided.
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}
	baseURL, err := url.Parse(host)
	if err != nil {
		return "", fmt.Errorf("parsing host URL: %w", err)
	}
	relURL, err := url.Parse(urlPath)
	if err != nil {
		return "", fmt.Errorf("parsing URL path: %w", err)
	}
	return baseURL.ResolveReference(relURL).String(), nil
}

// readRequestBody determines the request body based on flag input or stdin.
func readRequestBody(flagBody string, readStdin bool) ([]byte, error) {
	if readStdin {
		return io.ReadAll(os.Stdin)
	}
	return []byte(flagBody), nil
}

// addJSONContentType adds a JSON Content-Type header if the body appears to be JSON.
func addJSONContentType(headers map[string]string, body []byte) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		for k := range headers {
			if strings.ToLower(k) == "content-type" {
				return
			}
		}
		headers["Content-Type"] = "application/json"
	}
}

// processResponse handles outputting the HTTP response.
func processResponse(resp *http.Response) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	contentType := resp.Header.Get("Content-Type")
	isJSON := strings.Contains(strings.ToLower(contentType), "application/json")
	if isJSON {
		// Print the HTTP status code to stderr and pretty-print JSON to stdout.
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

func main() {
	// Load saved configuration.
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load config: %v\n", err)
		cfg = &Config{}
	}
	// Set default HTTP method if not provided.
	if cfg.Method == "" {
		cfg.Method = "GET"
	}

	// Prepare flags using configuration values as defaults.
	hostFlag := flag.String("host", cfg.Host, "Base URL or hostname (if scheme is omitted, https:// is assumed)")
	methodFlag := flag.String("x", cfg.Method, "HTTP method to use")
	flag.StringVar(methodFlag, "method", *methodFlag, "HTTP method to use")
	usernameFlag := flag.String("username", cfg.Username, "Basic auth username")
	passwordFlag := flag.String("password", cfg.Password, "Basic auth password")
	tokenFlag := flag.String("token", cfg.Token, "Bearer token for Authorization header")
	cacertFlag := flag.String("cacert", cfg.CACert, "CA certificate file for mTLS")
	certFlag := flag.String("cert", cfg.Cert, "Client certificate file for mTLS")
	keyFlag := flag.String("key", cfg.Key, "Client key file for mTLS")
	bodyFlag := flag.String("body", cfg.Body, "Request body (if it starts with { or [, Content-Type is set to application/json)")
	saveFlag := flag.Bool("save", false, "Save all flag values to the config file for reuse")

	// Set up header flags.
	var hdrs = headerFlag{headers: make(map[string]string)}
	if cfg.Headers != nil {
		for k, v := range cfg.Headers {
			hdrs.headers[k] = v
		}
	}
	flag.Var(&hdrs, "H", "Custom header in the form \"Key: Value\" (can be repeated)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] <url-path> [--]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Ensure the URL path argument is provided.
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing URL path argument")
		flag.Usage()
		os.Exit(1)
	}
	urlPath := args[0]

	// Check for the "--" argument to signal reading body from stdin.
	readStdin := false
	for _, arg := range args[1:] {
		if arg == "--" {
			readStdin = true
			break
		}
	}

	// Read and prepare the request body.
	reqBody, err := readRequestBody(*bodyFlag, readStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading request body: %v\n", err)
		os.Exit(1)
	}
	addJSONContentType(hdrs.headers, reqBody)

	// Build the final URL.
	finalURL, err := buildFinalURL(*hostFlag, urlPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building final URL: %v\n", err)
		os.Exit(1)
	}

	// Create the HTTP request.
	req, err := http.NewRequest(strings.ToUpper(*methodFlag), finalURL, bytes.NewReader(reqBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating HTTP request: %v\n", err)
		os.Exit(1)
	}
	// Set any custom headers.
	for k, v := range hdrs.headers {
		req.Header.Set(k, v)
	}
	// Set authentication headers.
	if *tokenFlag != "" {
		req.Header.Set("Authorization", "Bearer "+*tokenFlag)
	} else if *usernameFlag != "" && *passwordFlag != "" {
		req.SetBasicAuth(*usernameFlag, *passwordFlag)
	}

	// Build the HTTP client (with mTLS if parameters are provided).
	client, err := buildHTTPClient(*certFlag, *keyFlag, *cacertFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up HTTP client: %v\n", err)
		os.Exit(1)
	}

	// Execute the HTTP request.
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error making HTTP request: %v\n", err)
		os.Exit(1)
	}

	if err := processResponse(resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error processing response: %v\n", err)
		os.Exit(1)
	}

	// Optionally, save the effective configuration.
	if *saveFlag {
		newCfg := &Config{
			Host:     *hostFlag,
			Method:   strings.ToUpper(*methodFlag),
			Username: *usernameFlag,
			Password: *passwordFlag,
			Token:    *tokenFlag,
			CACert:   *cacertFlag,
			Cert:     *certFlag,
			Key:      *keyFlag,
			Body:     *bodyFlag, // Note: if the body came from stdin, this flag value is still saved.
			Headers:  hdrs.headers,
		}
		if err := saveConfig(newCfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			// Continue even if saving the config fails.
		}
	}
}
