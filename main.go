package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net"
    "net/http"

    "github.com/containous/traefik/v2/pkg/config/dynamic"
    "github.com/containous/traefik/v2/pkg/middlewares"
    "github.com/containous/traefik/v2/pkg/middlewares/plugin"
    "github.com/containous/traefik/v2/pkg/middlewares/tracing"
    "github.com/containous/traefik/v2/pkg/safe"
    "github.com/containous/traefik/v2/pkg/types"
    "github.com/containous/traefik/v2/pkg/log"
)

// Config holds the plugin configuration.
type Config struct {
    APIEndpoint string `json:"apiEndpoint,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
    return &Config{}
}

// IPFilter is a middleware plugin.
type IPFilter struct {
    next       http.Handler
    apiEndpoint string
    name       string
}

// New creates a new IPFilter plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    if config.APIEndpoint == "" {
        return nil, fmt.Errorf("API endpoint cannot be empty")
    }

    return &IPFilter{
        next:       next,
        apiEndpoint: config.APIEndpoint,
        name:       name,
    }, nil
}

func (a *IPFilter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
    if err != nil {
        rw.WriteHeader(http.StatusInternalServerError)
        _, _ = rw.Write([]byte("Internal Server Error.\n"))
        return
    }

    allowed, err := a.isIPAllowed(clientIP)
    if err != nil {
        rw.WriteHeader(http.StatusInternalServerError)
        _, _ = rw.Write([]byte("Internal Server Error.\n"))
        return
    }

    if !allowed {
        rw.WriteHeader(http.StatusForbidden)
        _, _ = rw.Write([]byte("Forbidden.\n"))
        return
    }

    a.next.ServeHTTP(rw, req)
}

func (a *IPFilter) isIPAllowed(ip string) (bool, error) {
    resp, err := http.Get(a.apiEndpoint)
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return false, fmt.Errorf("failed to get allowed IPs: %s", resp.Status)
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return false, err
    }

    var allowedIPs []string
    if err := json.Unmarshal(body, &allowedIPs); err != nil {
        return false, err
    }

    for _, allowedIP := range allowedIPs {
        if allowedIP == ip {
            return true, nil
        }
    }

    return false, nil
}
