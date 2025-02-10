# API CLI Tool

This tool is a simple command-line utility for sending HTTP requests to REST APIs. It supports common HTTP methods, custom headers, request bodies (from a flag or stdin), authentication (basic and bearer token), and even mTLS. You can also save your configuration to a YAML file for quick reuse.

## Features

- **HTTP Methods**: GET, POST, PUT, PATCH, DELETE
- **Custom Headers**: Specify multiple headers with `-H`
- **Request Body**: Provide JSON (or any text) via the `-body` flag or via stdin
- **Authentication**: Basic auth (`-username` and `-password`) or Bearer token (`-token`)
- **mTLS Support**: Use client certificates with `-cert`, `-key`, and `-cacert`
- **Config Saving**: Save your settings for reuse with the `-save` flag

## Installation

1. Clone the repository.
2. Build the tool:
   ```bash
   go build -o api main.go
   ```

## Usage

```
Usage: api [flags] <url-path> [--]
```

- `<url-path>`: The endpoint path relative to the host or a full URL.
- `--`: Optional separator to indicate that the request body should be read from stdin.

### Available Flags

- `-host`  
  The base URL or hostname (if scheme is omitted, `https://` is assumed).

- `-x` or `-method`  
  HTTP method to use (e.g. GET, POST, PUT, PATCH, DELETE).

- `-username` and `-password`  
  Basic authentication credentials.

- `-token`  
  Bearer token for the `Authorization` header.

- `-cacert`  
  CA certificate file for mTLS.

- `-cert`  
  Client certificate file for mTLS.

- `-key`  
  Client key file for mTLS.

- `-body`  
  Request body. If it starts with `{` or `[`, the tool automatically sets `Content-Type` to `application/json`.

- `-H`  
  Custom header in the form `"Key: Value"` (can be repeated).

- `-save`  
  Save all flag values to the config file (`~/.api_config.yaml`) for reuse.

## Examples

Below are examples using public REST APIs (all responses are in JSON).

### 1. Simple GET Request and Saving Configuration

Save your current settings to the configuration file for reuse:

```bash
./api -host https://httpbin.org -save /get
```

On subsequent runs, the saved values from `~/.api_config.yaml` will be used as defaults.

### 2. GET Request with Custom Headers

Send a GET request with a custom header:

```bash
./api -H "X-Custom-Header: MyValue" /get
```

### 3. POST Request with JSON Body

Send a POST request with a JSON body using the `-body` flag:

```bash
./api -x post -body '{"name": "John", "age": 30}' /post
```

Alternatively, read the request body from stdin:

```bash
echo '{"name": "John", "age": 30}' | ./api -method POST /post --
```

### 4. Basic Authentication

Access an endpoint that requires basic authentication:

```bash
./api -username user -password passwd /basic-auth/user/passwd
```

### 5. Bearer Token Authentication

Send a request using a Bearer token:

```bash
./api -token your_token_here /bearer
```

### 6. mTLS (Mutual TLS)

If your API requires mTLS, provide your client certificate, key, and CA certificate:

```bash
./api -host https://your-secure-api.com -cert client.crt -key client.key -cacert ca.crt /your-endpoint
```

*Note: Ensure you have valid certificate files for mTLS testing.*

## Conclusion

This API CLI Tool provides a flexible and lightweight way to test and interact with REST APIs directly from the command line. Customize your requests using a variety of options and streamline your workflow by saving your configuration. Feel free to contribute or open issues to help improve the tool!