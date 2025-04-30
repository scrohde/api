package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

func main() {
	cobra.OnInitialize(initConfig)
	rootCmd := &cobra.Command{
		Use:   "api [method] [path]",
		Short: "api - simple REST client with JSON formatting and config profiles",
		Args:  cobra.MinimumNArgs(1),
		RunE:  runRequest,
	}

	// Global flags
	rootCmd.PersistentFlags().StringP("profile", "p", "", "Profile name to use from config")
	rootCmd.PersistentFlags().StringP("data", "d", "", "Request body or '@file' to read from file or '-' for stdin")
	rootCmd.PersistentFlags().StringArray("header", []string{}, "Add request header (Key: Value)")
	rootCmd.PersistentFlags().String("cert", "", "Client certificate file for mTLS")
	rootCmd.PersistentFlags().String("key", "", "Client key file for mTLS")
	rootCmd.PersistentFlags().String("ca", "", "Custom CA cert file")
	rootCmd.PersistentFlags().Bool("save", false, "Save flags as default for this profile")
	// Auth shortcuts
	rootCmd.PersistentFlags().String("token", "", "Bearer token for Authorization header")
	rootCmd.PersistentFlags().String("user", "", "Username for basic auth")
	rootCmd.PersistentFlags().String("password", "", "Password for basic auth")

	// Config subcommands
	config := &cobra.Command{
		Use:   "config",
		Short: "Manage profiles",
	}
	add := &cobra.Command{
		Use:   "add [profile] [baseURL]",
		Short: "Add or update a profile",
		Args:  cobra.ExactArgs(2),
		RunE:  addProfile,
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List all profiles",
		Args:  cobra.NoArgs,
		Run:   listProfiles,
	}
	use := &cobra.Command{
		Use:   "use [profile]",
		Short: "Set default profile",
		Args:  cobra.ExactArgs(1),
		RunE:  useProfile,
	}

	config.AddCommand(add, list, use)
	rootCmd.AddCommand(config)

	rootCmd.Execute()
}

func initConfig() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error finding home directory:", err)
		os.Exit(1)
	}
	configDir := filepath.Join(home, ".config", "api")
	os.MkdirAll(configDir, 0700)
	cfgFile = filepath.Join(configDir, "config.yaml")

	viper.SetConfigFile(cfgFile)
	viper.SetConfigType("yaml")
	_ = viper.ReadInConfig()
}

// Profile structure

type Profile struct {
	BaseURL  string            `yaml:"base_url" mapstructure:"base_url"`
	Headers  map[string]string `mapstructure:"headers"`
	Cert     string            `mapstructure:"cert"`
	Key      string            `mapstructure:"key"`
	CA       string            `mapstructure:"ca"`
	Token    string            `mapstructure:"token"`
	Username string            `mapstructure:"username"`
	Password string            `mapstructure:"password"`
}

func addProfile(cmd *cobra.Command, args []string) error {
	name := args[0]
	base := args[1]

	// Validate baseURL
	parsedBaseURL, err := url.Parse(base)
	if err != nil || !parsedBaseURL.IsAbs() || parsedBaseURL.Hostname() == "" {
		return fmt.Errorf("invalid baseURL: must be a valid absolute URL with hostname")
	}

	p := Profile{BaseURL: base, Headers: map[string]string{}}
	// headers
	headers, _ := cmd.Flags().GetStringArray("header")
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			p.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	// mTLS
	p.Cert, _ = cmd.Flags().GetString("cert")
	p.Key, _ = cmd.Flags().GetString("key")
	p.CA, _ = cmd.Flags().GetString("ca")
	// auth shortcuts
	p.Token, _ = cmd.Flags().GetString("token")
	p.Username, _ = cmd.Flags().GetString("user")
	p.Password, _ = cmd.Flags().GetString("password")

	viper.Set("profiles."+name, p)
	return viper.WriteConfigAs(cfgFile)
}

func listProfiles(cmd *cobra.Command, args []string) {
	profiles := viper.GetStringMap("profiles")
	for name := range profiles {
		fmt.Println(name)
	}
}

func useProfile(cmd *cobra.Command, args []string) error {
	viper.Set("default", args[0])
	return viper.WriteConfigAs(cfgFile)
}

func runRequest(cmd *cobra.Command, args []string) error {
	method := strings.ToUpper(args[0])
	endpoint := ""
	if len(args) > 2 {
		endpoint = args[1]
	}

	// Load profile
	profile := viper.GetString("default")
	flagProfile, _ := cmd.Flags().GetString("profile")
	if flagProfile != "" {
		profile = flagProfile
	}

	var prof Profile
	if profile != "" {
		if err := viper.UnmarshalKey("profiles."+profile, &prof); err != nil {
			return fmt.Errorf("profile '%s' not found", profile)
		}
	}

	// Prepare URL
	if prof.BaseURL == "" {
		return fmt.Errorf("baseURL is required in the profile or as an argument")
	}

	parsedBaseURL, err := url.Parse(prof.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid baseURL: %v", err)
	}

	if endpoint != "" {
		parsedPath, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("invalid path: %v", err)
		}
		parsedBaseURL = parsedBaseURL.ResolveReference(parsedPath)
	}

	url := parsedBaseURL.String()

	// Build payload
	dataFlag, _ := cmd.Flags().GetString("data")
	var bodyBytes []byte
	switch {
	case dataFlag == "-":
		bodyBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("error reading from stdin: %w", err)
		}
	case strings.HasPrefix(dataFlag, "@"):
		bodyBytes, err = os.ReadFile(strings.TrimPrefix(dataFlag, "@"))
		if err != nil {
			return fmt.Errorf("error reading file %s: %w", strings.TrimPrefix(dataFlag, "@"), err)
		}
	case dataFlag != "":
		bodyBytes = []byte(dataFlag)
	}

	var body io.Reader
	if len(bodyBytes) > 0 {
		body = bytes.NewReader(bodyBytes)
	}

	// Setup client with mTLS
	transport := &http.Transport{}
	if prof.CA != "" {
		caCert, err := os.ReadFile(prof.CA)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	if prof.Cert != "" && prof.Key != "" {
		certPair, err := tls.LoadX509KeyPair(prof.Cert, prof.Key)
		if err != nil {
			return err
		}
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{certPair}
	}

	httpClient := &http.Client{Transport: transport}

	// Create request
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}

	// Auth shortcuts: flag overrides profile
	tokenFlag, _ := cmd.Flags().GetString("token")
	if tokenFlag != "" {
		req.Header.Set("Authorization", "Bearer "+tokenFlag)
	} else if prof.Token != "" {
		req.Header.Set("Authorization", "Bearer "+prof.Token)
	}
	userFlag, _ := cmd.Flags().GetString("user")
	passFlag, _ := cmd.Flags().GetString("password")
	if userFlag != "" && passFlag != "" {
		req.SetBasicAuth(userFlag, passFlag)
	} else if prof.Username != "" && prof.Password != "" {
		req.SetBasicAuth(prof.Username, prof.Password)
	}

	// Headers: from profile then flags
	for k, v := range prof.Headers {
		req.Header.Set(k, v)
	}
	headersFlag, _ := cmd.Flags().GetStringArray("header")
	for _, h := range headersFlag {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Auto-detect JSON content type if not set by user and body exists
	if len(bodyBytes) > 0 && req.Header.Get("Content-Type") == "" {
		var js json.RawMessage
		if json.Unmarshal(bodyBytes, &js) == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	// Execute
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Pretty-print JSON if applicable
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var out bytes.Buffer
		err = json.Indent(&out, respData, "", "  ")
		if err != nil {
			fmt.Println(string(respData))
		} else {
			fmt.Println(out.String())
		}
	} else {
		os.Stdout.Write(respData)
	}

	// Save profile defaults if requested
	if save, _ := cmd.Flags().GetBool("save"); save && profile != "" {
		prof.Cert, _ = cmd.Flags().GetString("cert")
		prof.Key, _ = cmd.Flags().GetString("key")
		prof.CA, _ = cmd.Flags().GetString("ca")
		prof.Token, _ = cmd.Flags().GetString("token")
		prof.Username, _ = cmd.Flags().GetString("user")
		prof.Password, _ = cmd.Flags().GetString("password")
		combined := map[string]string{}
		for k, v := range prof.Headers {
			combined[k] = v
		}
		for _, h := range headersFlag {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				combined[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	return nil
}
