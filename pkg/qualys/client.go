package qualys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	EnvQualysAPIURL   = "QUALYS_API_URL"
	EnvQualysUsername = "QUALYS_USERNAME"
	EnvQualysPassword = "QUALYS_PASSWORD"
	EnvQualysAPIToken = "QUALYS_API_TOKEN"
)

var (
	ErrNoCredentials     = errors.New("no Qualys credentials configured; set QUALYS_API_TOKEN or QUALYS_USERNAME/QUALYS_PASSWORD environment variables")
	ErrNoAPIURL          = errors.New("no Qualys API URL configured; set QUALYS_API_URL environment variable")
	ErrCredentialsInCode = errors.New("credentials must come from environment variables, not code or config files")
)

const (
	DefaultTimeout = 30 * time.Second
	APIVersion     = "v1.3"
	UserAgent      = "qualys-k8s-agentless/0.1.0"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	auth       AuthConfig
}

type AuthConfig struct {
	Username string `json:"-"`
	Password string `json:"-"`
	APIToken string `json:"-"`
}

func (a AuthConfig) String() string {
	if a.APIToken != "" {
		return "AuthConfig{APIToken: [REDACTED]}"
	}
	if a.Username != "" {
		return fmt.Sprintf("AuthConfig{Username: %s, Password: [REDACTED]}", a.Username)
	}
	return "AuthConfig{<no credentials>}"
}

func (a AuthConfig) MarshalJSON() ([]byte, error) {
	return []byte(`{"credentials":"[REDACTED]"}`), nil
}

func (a AuthConfig) HasCredentials() bool {
	return a.APIToken != "" || (a.Username != "" && a.Password != "")
}

func NewAuthConfigFromEnv() (AuthConfig, error) {
	auth := AuthConfig{
		APIToken: os.Getenv(EnvQualysAPIToken),
		Username: os.Getenv(EnvQualysUsername),
		Password: os.Getenv(EnvQualysPassword),
	}

	if !auth.HasCredentials() {
		return auth, ErrNoCredentials
	}

	return auth, nil
}

func GetAPIURLFromEnv() (string, error) {
	url := os.Getenv(EnvQualysAPIURL)
	if url == "" {
		return "", ErrNoAPIURL
	}
	return url, nil
}

type ClientOption func(*Client)

func NewClient(baseURL string, auth AuthConfig, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: baseURL,
		auth:    auth,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func NewClientFromEnv(opts ...ClientOption) (*Client, error) {
	baseURL, err := GetAPIURLFromEnv()
	if err != nil {
		return nil, err
	}

	auth, err := NewAuthConfigFromEnv()
	if err != nil {
		return nil, err
	}

	return NewClient(baseURL, auth, opts...), nil
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

func (c *Client) request(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	url := fmt.Sprintf("%s/csapi/%s%s", c.baseURL, APIVersion, path)

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)

	if c.auth.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.auth.APIToken)
	} else if c.auth.Username != "" && c.auth.Password != "" {
		req.SetBasicAuth(c.auth.Username, c.auth.Password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.Unmarshal(respBody, &apiErr); err != nil {
			return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
		}
		return &apiErr
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

type APIError struct {
	Code       int    `json:"code"`
	Message    string `json:"message"`
	Details    string `json:"details,omitempty"`
	StatusCode int    `json:"-"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Qualys API error %d: %s", e.Code, e.Message)
}

func (c *Client) Ping(ctx context.Context) error {
	var result interface{}
	return c.request(ctx, http.MethodGet, "/clusters", nil, &result)
}
