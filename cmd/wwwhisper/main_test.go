// Copyright (C) 2025 Jan Wrobel <jan@wwwhisper.io>
// This program is freely distributable under the terms of the
// Simplified BSD License. See COPYING.

package main

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

func clearEnv() {
	os.Unsetenv("WWWHISPER_URL")
	os.Unsetenv("WWWHISPER_LOG")
	os.Unsetenv("WWWHISPER_NO_OVERLAY")
	os.Unsetenv("WWWHISPER_ALLOW_HTTP")
}

func TestNewConfig(t *testing.T) {
	clearEnv()
	defer clearEnv()

	_, err := newProxyConfig("", 80, 8080)
	expected := "WWWHISPER_URL environment variable is not set"
	if err == nil || err.Error() != expected {
		t.Error("Unexpected error:", err)
	}

	os.Setenv("WWWHISPER_URL", "https://example.com:-1")
	_, err = newProxyConfig("", 80, 8080)
	expected = "WWWHISPER_URL has invalid format: "
	if err == nil || !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected error:", err)
	}

	os.Setenv("WWWHISPER_URL", "https://example.com")
	_, err = newProxyConfig("", 70000, 8080)
	expected = "port number out of range 70000"
	if err == nil || err.Error() != expected {
		t.Error("Unexpected error:", err)
	}

	_, err = newProxyConfig("", 80, 80000)
	expected = "port number out of range 80000"
	if err == nil || !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected error:", err)
	}

	cfg, _ := newProxyConfig("/tmp/foo", 80, 8080)
	if cfg.PidFilePath != "/tmp/foo" {
		t.Error("pidFilePath invalid", cfg.PidFilePath)
	}
	if cfg.NoOverlay != false {
		t.Error("NoOverlay invalid")
	}
	if cfg.WwwhisperURL.String() != "https://example.com" {
		t.Error("WwhisperURL invalid", cfg.WwwhisperURL)
	}
	if cfg.LogLevel != slog.LevelWarn {
		t.Error("LogLevel invalid", cfg.LogLevel)
	}
	if cfg.Listen != 80 {
		t.Error("ExternalPort invalid", cfg.Listen)
	}
	if cfg.ProxyTo != 8080 {
		t.Error("ProxyToPort port invalid", cfg.ProxyTo)
	}
	if cfg.AllowHttp != false {
		t.Error("AllowHttp invalid")
	}

	os.Setenv("WWWHISPER_LOG", "info")
	os.Setenv("WWWHISPER_NO_OVERLAY", "")
	os.Setenv("WWWHISPER_ALLOW_HTTP", "")
	cfg, _ = newProxyConfig("/tmp/foo", 80, 8080)
	if cfg.LogLevel != slog.LevelInfo {
		t.Error("LogLevel invalid", cfg.LogLevel)
	}
	if cfg.NoOverlay != true {
		t.Error("NoOverlay invalid")
	}
	if cfg.AllowHttp != true {
		t.Error("AllowHttp invalid")
	}
}

func TestIntToPort(t *testing.T) {
	_, err := intToPort(65536)
	expected := "port number out of range 65536"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected output", err)
	}

	_, err = intToPort(-1)
	expected = "port number out of range -1"
	if !strings.HasPrefix(err.Error(), expected) {
		t.Error("Unexpected output", err)
	}

	port, err := intToPort(0)
	if port != 0 || err != nil {
		t.Error("Unexpected output", port, err)
	}

	port, err = intToPort(65535)
	if port != 65535 || err != nil {
		t.Error("Unexpected output", port, err)
	}
}

func TestParseLogLevel(t *testing.T) {
	testCases := []struct {
		levelIn  string
		levelOut slog.Level
	}{
		// All levels are case insensitive.
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"deBuG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"", slog.LevelWarn},
		{"error", slog.LevelError},
		{"off", slog.LevelError + 1},
		// Any not recognized setting is mapped to info
		{"on", slog.LevelInfo},
		{"1", slog.LevelInfo},
	}

	for _, test := range testCases {
		t.Run(test.levelIn, func(t *testing.T) {
			out := parseLogLevel(test.levelIn)
			if test.levelOut != out {
				t.Errorf("expected: %s, got: %s", test.levelOut, out)
			}
		})
	}
}
