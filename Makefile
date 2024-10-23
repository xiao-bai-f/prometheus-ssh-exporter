VERSION=1.0
HARBOR := docker.io
PROJECT := prometheus

ARCH := "amd64"
OS := "linux"

.PHONY: build
build:
	go build -o .build/$(OS)-$(ARCH)/ssh-exporter ./cmd/main/main.go

.PHONY: docker-push
docker-push:
	docker push $(HARBOR)/$(PROJECT)/ssh-exporter:$(VERSION)

.PHONY: docker-build
docker-build:
	docker build --no-cache -t $(HARBOR)/$(PROJECT)/ssh-exporter:$(VERSION) \
	 .