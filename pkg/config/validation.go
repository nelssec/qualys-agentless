package config

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrInvalidNamespace = errors.New("invalid namespace name")
	ErrInvalidProvider  = errors.New("invalid provider")
	ErrInvalidFramework = errors.New("invalid framework")
	ErrEmptyInput       = errors.New("input cannot be empty")
	ErrInputTooLong     = errors.New("input exceeds maximum length")
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
		"cis-k8s-1.10":       true,
		"cis-k8s-1.11":       true,
		"cis-eks-1.6":        true,
		"cis-aks-1.6":        true,
		"cis-ocp-1.7":        true,
		"k8s-best-practices": true,
		"eks-best-practices": true,
		"aks-best-practices": true,
		"ocp-best-practices": true,
		"nsa-cisa":           true,
		"mitre-attack":       true,
	}
)

const MaxNamespaceNameLength = 63

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
