package config

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	ErrInvalidClusterName  = errors.New("invalid cluster name")
	ErrInvalidNamespace    = errors.New("invalid namespace name")
	ErrInvalidURL          = errors.New("invalid URL")
	ErrInvalidProvider     = errors.New("invalid provider")
	ErrInvalidFramework    = errors.New("invalid framework")
	ErrEmptyInput          = errors.New("input cannot be empty")
	ErrInputTooLong        = errors.New("input exceeds maximum length")
)

var (
	dnsLabelRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	validProviders = map[string]bool{
		"aws":        true,
		"azure":      true,
		"gcp":        true,
		"kubeconfig": true,
	}
	validFrameworks = map[string]bool{
		"cis-k8s-1.10":         true,
		"cis-k8s-1.11":         true,
		"cis-eks-1.6":          true,
		"cis-aks-1.6":          true,
		"cis-ocp-1.7":          true,
		"k8s-best-practices":   true,
		"eks-best-practices":   true,
		"aks-best-practices":   true,
		"ocp-best-practices":   true,
		"nsa-cisa":             true,
		"mitre-attack":         true,
	}
)

const (
	MaxClusterNameLength   = 253
	MaxNamespaceNameLength = 63
	MaxURLLength           = 2048
)

func ValidateClusterName(name string) error {
	if name == "" {
		return ErrEmptyInput
	}
	if len(name) > MaxClusterNameLength {
		return ErrInputTooLong
	}
	if !isValidDNSLabel(name) {
		return ErrInvalidClusterName
	}
	return nil
}

func ValidateNamespace(name string) error {
	if name == "" {
		return ErrEmptyInput
	}
	if len(name) > MaxNamespaceNameLength {
		return ErrInputTooLong
	}
	if !dnsLabelRegex.MatchString(name) {
		return ErrInvalidNamespace
	}
	return nil
}

func ValidateURL(rawURL string) error {
	if rawURL == "" {
		return ErrEmptyInput
	}
	if len(rawURL) > MaxURLLength {
		return ErrInputTooLong
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ErrInvalidURL
	}
	if parsed.Scheme != "https" {
		return ErrInvalidURL
	}
	if parsed.Host == "" {
		return ErrInvalidURL
	}
	return nil
}

func ValidateProvider(provider string) error {
	if provider == "" {
		return ErrEmptyInput
	}
	if !validProviders[strings.ToLower(provider)] {
		return ErrInvalidProvider
	}
	return nil
}

func ValidateFramework(framework string) error {
	if framework == "" {
		return ErrEmptyInput
	}
	if !validFrameworks[strings.ToLower(framework)] {
		return ErrInvalidFramework
	}
	return nil
}

func ValidateFrameworks(frameworks []string) error {
	for _, fw := range frameworks {
		if err := ValidateFramework(fw); err != nil {
			return err
		}
	}
	return nil
}

func ValidateNamespaces(namespaces []string) error {
	for _, ns := range namespaces {
		if err := ValidateNamespace(ns); err != nil {
			return err
		}
	}
	return nil
}

func isValidDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > MaxClusterNameLength {
		return false
	}
	parts := strings.Split(s, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		if !dnsLabelRegex.MatchString(part) {
			for _, r := range part {
				if r == '_' || r == '-' {
					continue
				}
				if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
					continue
				}
				return false
			}
		}
	}
	return true
}

func SanitizeLogMessage(msg string) string {
	sanitized := strings.ReplaceAll(msg, "\n", " ")
	sanitized = strings.ReplaceAll(sanitized, "\r", " ")
	if len(sanitized) > 1000 {
		sanitized = sanitized[:1000] + "..."
	}
	return sanitized
}
