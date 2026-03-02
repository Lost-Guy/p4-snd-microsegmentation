# Makefile - Dockerized P4_16 Compilation Pipeline
DOCKER_IMAGE = p4lang/p4c
P4C_FLAGS = --p4v 16 --p4runtime-files build/p4info.txtpb
SRC = p4src/main.p4
OUT_DIR = build

.PHONY: all compile clean

all: compile

compile: $(SRC)
	mkdir -p $(OUT_DIR)
	docker run --rm -v $(CURDIR):/workspace -w /workspace $(DOCKER_IMAGE) \
		p4c-bm2-ss $(P4C_FLAGS) -o $(OUT_DIR)/main.json $(SRC)

clean:
	rm -rf $(OUT_DIR)/*
