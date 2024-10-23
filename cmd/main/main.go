package main

import (
	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
	stdlog "log"
	"net/http"
	"os"
	"ssh-exporter/collector"
)

var (
	configFile = kingpin.Flag(
		"config.file",
		"Path to configuration file.",
	).Default("./config.yaml").String()

	sc = &collector.SafeConfig{
		C: &collector.Config{},
	}

	toolkitFlags = kingpinflag.AddFlags(kingpin.CommandLine, ":9030")

	logger log.Logger
)

func main() {

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.CommandLine.UsageWriter(os.Stdout)
	kingpin.HelpFlag.Short('h')
	kingpin.Version(version.Print("ssh-exporter"))
	kingpin.Parse()
	logger = promlog.New(promlogConfig)
	level.Info(logger).Log("msg", "Starting ssh-exporter", "version", version.Info())

	// load config
	file, err := os.Open("./config.yaml")
	if err != nil {
		stdlog.Println("Error opening file: %v", err)
	}
	defer file.Close()

	//  抽成配置
	if err := sc.ReloadConfig(logger, *configFile); err != nil {
		level.Error(logger).Log("msg", "Error parsing config file", "error", err)
		os.Exit(1)
	}

	// http server
	http.HandleFunc("/metrics", sshHandler)

	server := &http.Server{}
	if err := web.ListenAndServe(server, toolkitFlags, logger); err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}

func sshHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "'target' parameter must be specified", 400)
		return
	}

	// Remote scrape will not work without some kind of config, so be pedantic about it
	module := r.URL.Query().Get("module")
	if module == "" {
		module = "default"
	}

	registry := prometheus.NewRegistry()
	remoteCollector := collector.SshCollector{
		Logger: logger,
		Target: target,
		Module: module,
		Config: sc,
	}
	registry.MustRegister(remoteCollector)
	promhttp.HandlerFor(
		registry,
		promhttp.HandlerOpts{},
	).ServeHTTP(w, r)
}
