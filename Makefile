# Makefile - Containerized P4_16 Compilation & Topology Execution
DOCKER_IMAGE = p4lang/p4app

P4C_FLAGS = --p4v 16 --p4runtime-files build/p4info.txt
SRC = p4src/main.p4
OUT_DIR = build

.PHONY: all compile run-topo clean

all: compile

compile: $(SRC)
	mkdir -p $(OUT_DIR)
	docker run --rm \
		--entrypoint "" \
		-v $(CURDIR):/workspace \
		-w /workspace \
		$(DOCKER_IMAGE) \
		p4c-bm2-ss $(P4C_FLAGS) -o $(OUT_DIR)/main.json $(SRC)

run-topo: compile
	tar -czf /tmp/app.tar.gz --exclude='.git' --exclude='build' .
	docker run --privileged --rm -it \
		-v /tmp/app.tar.gz:/tmp/app.tar.gz \
		-v /lib/modules:/lib/modules \
		$(DOCKER_IMAGE) /tmp/app.tar.gz

clean:
	rm -rf $(OUT_DIR)/* /tmp/app.tar.gz
