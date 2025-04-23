package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/wrr/wwwhisper/internal/proxy"
)

func parseLogLevel(logLevelStr string) slog.Level {
	switch strings.ToLower(logLevelStr) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "":
		// default if WWWHISPER_LOG is not set
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "off":
		return slog.LevelError + 1
	default:
		// Use Info if logLevelStr is set to any other string
		return slog.LevelInfo
	}
}

func intToPort(in int) (proxy.Port, error) {
	if in < 0 || in > 0xffff {
		return 0, fmt.Errorf("port number out of range %d", in)
	}
	return proxy.Port(in), nil
}

func newProxyConfig(pidFilePath string, listen int, proxyTo int) (proxy.Config, error) {
	_, noOverlay := os.LookupEnv("WWWHISPER_NO_OVERLAY")
	config := proxy.Config{
		PidFilePath: pidFilePath,
		NoOverlay:   noOverlay,
		LogLevel:    parseLogLevel(os.Getenv("WWWHISPER_LOG")),
	}
	wwwhisperURL := os.Getenv("WWWHISPER_URL")
	if wwwhisperURL == "" {
		return proxy.Config{}, errors.New("WWWHISPER_URL environment variable is not set")
	}

	var err error
	config.WwwhisperURL, err = url.Parse(wwwhisperURL)
	if err != nil {
		return proxy.Config{}, fmt.Errorf("WWWHISPER_URL has invalid format: %s; %v", wwwhisperURL, err)
	}

	config.Listen, err = intToPort(listen)
	if err != nil {
		return proxy.Config{}, err
	}
	config.ProxyTo, err = intToPort(proxyTo)
	if err != nil {
		return proxy.Config{}, err
	}
	return config, nil
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}

func main() {
	listenFlag := flag.Int("listen", -1,
		`Externally accessible local port on which wwwhisper will listen.
wwwhisper authenticates and authorizes requests incoming to this port.`)

	proxyToFlag := flag.Int("proxyto", -1,
		`A local port on which a web application listens.
This port should not be externally accessible, otherwise wwwhisper
authorization could be bypassed by connecting to this port directly.
wwwhisper forwards authorized requests to this port.`)

	pidFileFlag := flag.String("pidfile", "", `Path to file where process ID is written.
The file is removed when the program terminates.`)

	versionFlag := flag.Bool("version", false, "Print the program version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "wwwhisper authorization reverse proxy\nOptions:\n")
		flag.PrintDefaults()
	}
	err := flag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		die(err)
	}
	if flag.NArg() > 0 {
		die(fmt.Errorf("unrecognized arguments: %v", flag.Args()))
	}

	if *versionFlag {
		fmt.Println(proxy.Version)
		return
	}

	if *listenFlag == -1 {
		die(errors.New("missing -listen flag"))
	}
	if *proxyToFlag == -1 {
		die(errors.New("missing -proxyto flag"))
	}

	config, err := newProxyConfig(*pidFileFlag, *listenFlag, *proxyToFlag)
	if err == nil {
		err = proxy.Run(config)
	}
	if err != nil {
		die(err)
	}

}
