Prometheus Ssh Exporter
========================

This is a ssh exporter for [Prometheus][Prometheus].

[prometheus]: https://prometheus.io "Prometheus homepage"

It supports scrape remote host metric by ssh protocol, by the endpoint of "/metrics" 
that supports scrape smartctl、redis、mysql metrics, one ssh-exporter can be used 
to monitor a large number of hosts by passing the `target` and the `module` parameter
to a scrape

## Build from source
    go mod tidy
    go build -o trwe-exporter ./cmd/main/main.go
## Running

A minimal invocation looks like this:

    ./ipmi_exporter

Supported parameters include:

- `web.listen-address`: the address/port to listen on (default: `":9030"`)
- `config.file`: path to the configuration file (default: ./config.yaml)