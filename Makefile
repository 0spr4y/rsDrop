# rsDrop build targets
#   make          build ./dist (rsDrop binary + web files), ready to run or copy to a server
#   make docker   build the Docker image (override the tag with IMAGE=name:tag)
#   make clean    remove ./dist and cargo build output

IMAGE ?= rsdrop:latest
MEMORY_LIMIT ?= 100m
DIST := dist

.PHONY: all dist docker clean

all: dist

dist:
	cargo build --release
	rm -rf $(DIST)
	mkdir -p $(DIST)
	cp target/release/rsDrop $(DIST)/rsDrop
	cp -r web $(DIST)/web
	@echo
	@echo "Built ./$(DIST). Run it with: cd $(DIST) && ./rsDrop --create-token"

docker:
	docker build -t $(IMAGE) .
	@echo
	@echo "Built $(IMAGE). Run it capped at $(MEMORY_LIMIT) of memory:"
	@echo "  docker run --rm -p 8080:8080 --memory=$(MEMORY_LIMIT) --memory-swap=$(MEMORY_LIMIT) --read-only --cap-drop=ALL --security-opt=no-new-privileges $(IMAGE) --create-token"

clean:
	cargo clean
	rm -rf $(DIST)
