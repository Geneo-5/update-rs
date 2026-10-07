# Makefile pour update-rs
# Usage : make <target>
# Voir AGENTS.md pour les détails

.PHONY: help docker-build docker-prune docker-shell docker-test docker-lint docker-fuzz docker-fuzz-short docker-fuzz-all docker-coverage docker-build-release docker-build-arm docker-clean build test lint fuzz coverage clean

# Variable pour le target de fuzzing (défaut : bundle_header)
TARGET ?= bundle_header
DURATION ?= 300

help: ## Afficher cette aide
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================================================
# Docker
# ============================================================================

docker-build: ## Construire l'image Docker
	docker build -t update-rs:dev -f docker/Dockerfile --target dev .

docker-prune: ## Prune l'image Docker
	docker builder prune -f

docker-shell: ## Lancer un shell interactif dans le conteneur
	docker compose -f docker/docker-compose.yml run --rm dev

docker-test: ## Lancer les tests dans le conteneur
	docker compose -f docker/docker-compose.yml run --rm test

docker-lint: ## Lancer le lint (clippy + rustfmt) dans le conteneur
	docker compose -f docker/docker-compose.yml run --rm lint

docker-fuzz: ## Lancer le fuzzing (TARGET=nom_cible, ex: make docker-fuzz TARGET=bundle_header)
	docker compose -f docker/docker-compose.yml run --rm fuzz cargo +nightly fuzz run $(TARGET) -- -max_total_time=$(DURATION)

docker-fuzz-short: ## Lancer 5 minutes de fuzzing sur la cible principale
	$(MAKE) docker-fuzz TARGET=bundle_header DURATION=300

docker-fuzz-all: ## Lancer 10 minutes de fuzzing sur toutes les cibles
	@for target in bundle_header bundle_chunk jail_manifest tpm_command state_machine; do \
		echo "Fuzzing $$target..."; \
		$(MAKE) docker-fuzz TARGET=$$target DURATION=600; \
	done

docker-coverage: ## Lancer la couverture de code dans le conteneur
	docker compose -f docker/docker-compose.yml run --rm coverage

docker-build-release: ## Build release natif (workspace complet)
	docker compose -f docker/docker-compose.yml run --rm build

docker-build-arm: ## (optionnel) Cross-compilation ARMv7 de updated/updatectl (docs/cross-compilation.md)
	docker compose -f docker/docker-compose.yml --profile cross run --rm build-arm

docker-clean: ## Nettoyer les conteneurs et volumes Docker du projet
	docker compose -f docker/docker-compose.yml --profile cross --profile runtime down -v --remove-orphans

# ============================================================================
# Build natif (pour référence, mais utiliser Docker en production)
# ============================================================================

build: ## Build local (workspace)
	cargo build --workspace

build-release: ## Build release local
	cargo build --workspace --release

build-arm: ## (optionnel) Build cross-compilation ARMv7 (docs/cross-compilation.md)
	cargo build --workspace --target armv7-unknown-linux-gnueabihf --release

# ============================================================================
# Tests
# ============================================================================

test: ## Lancer les tests
	cargo test --workspace --all-targets

test-release: ## Lancer les tests en mode release
	cargo test --workspace --all-targets --release

test-coverage: ## Lancer les tests avec couverture
	cargo tarpaulin --workspace --out Html

# ============================================================================
# Lint
# ============================================================================

lint: ## Lancer clippy et rustfmt
	cargo fmt --all --check
	cargo clippy --all-targets -- -D warnings

fmt: ## Formatter le code
	cargo fmt --all

# ============================================================================
# Fuzzing
# ============================================================================

fuzz: ## Lancer le fuzzing (nécessite nightly)
	cargo +nightly fuzz run $(TARGET) -- -max_total_time=$(DURATION)

fuzz-list: ## Lister les cibles de fuzzing
	cargo +nightly fuzz list

fuzz-cmin: ## Minimiser le corpus
	cargo +nightly fuzz cmin $(TARGET)

fuzz-tmin: ## Minimiser un crash (CRASH=chemin_vers_crash)
	cargo +nightly fuzz tmin $(TARGET) $(CRASH)

# ============================================================================
# Sécurité
# ============================================================================

audit: ## Vérifier les CVEs dans les dépendances
	cargo audit

# ============================================================================
# Nettoyage
# ============================================================================

clean: ## Nettoyer les artefacts de build
	cargo clean
	rm -rf target/

# ============================================================================
# CI (pré-merge gates)
# ============================================================================

ci-check: ## Vérifier tous les pre-merge gates (lint, test, audit)
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) audit
	@echo "✅ Tous les pre-merge gates passent"

ci-fuzz: ## Lancer 5 minutes de fuzzing sur chaque cible (pour CI)
	@for target in bundle_header bundle_chunk jail_manifest tpm_command state_machine; do \
		echo "Fuzzing $$target (5 minutes)..."; \
		cargo +nightly fuzz run $$target -- -max_total_time=300 || exit 1; \
	done
	@echo "✅ Fuzzing CI passé"

ci-coverage: ## Vérifier la couverture (≥ 80 %)
	cargo tarpaulin --workspace --fail-under 80
	@echo "✅ Couverture ≥ 80 %"

ci-all: ## Lancer tous les checks CI (lint, test, fuzz, coverage, audit)
	$(MAKE) ci-check
	$(MAKE) ci-fuzz
	$(MAKE) ci-coverage
	@echo "✅ Tous les checks CI passent"
