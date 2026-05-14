BUILD_PRESET ?= dev
BUILD_DIR ?= build/$(BUILD_PRESET)
NPM ?= npm
CMAKE ?= cmake

.PHONY: bootstrap configure build build-backend build-frontend test lint package run-dev clean

bootstrap: frontend/node_modules configure

configure:
	$(CMAKE) --preset $(BUILD_PRESET)

build: build-backend build-frontend

build-backend:
	$(CMAKE) --build --preset $(BUILD_PRESET)

build-frontend: frontend/node_modules
	cd frontend && $(NPM) run build

test: build-backend frontend/node_modules
	ctest --test-dir $(BUILD_DIR) --output-on-failure
	cd frontend && $(NPM) run test -- --run

lint: frontend/node_modules
	cd frontend && $(NPM) run lint
	cd frontend && $(NPM) run typecheck

package: build-backend build-frontend
	$(CMAKE) --build --preset $(BUILD_PRESET) --target package

run-dev: build-backend frontend/node_modules
	./scripts/dev/run-dev.sh

clean:
	rm -rf build frontend/dist frontend/node_modules

frontend/node_modules: frontend/package.json frontend/package-lock.json
	cd frontend && $(NPM) ci

