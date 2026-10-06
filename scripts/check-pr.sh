#!/usr/bin/env bash
# check-pr.sh — Vérifier tous les pre-merge gates avant de soumettre une PR
# Ce script doit être exécuté dans le conteneur Docker
#
# Usage :
#   ./scripts/check-pr.sh

set -euo pipefail

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Compteur de succès/échecs
SUCCESSES=0
FAILURES=0

# Fonction pour exécuter un check
run_check() {
    local name=$1
    local command=$2
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE} $name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if eval "$command"; then
        echo -e "${GREEN}✅ $name : PASSE${NC}"
        ((SUCCESSES++))
    else
        echo -e "${RED}❌ $name : ÉCHEC${NC}"
        ((FAILURES++))
    fi
    echo ""
}

echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  Vérification des pre-merge gates pour update-rs          ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Formatage
run_check "Formatage (rustfmt)" "cargo fmt --all --check"

# 2. Lint (clippy)
run_check "Lint (clippy)" "cargo clippy --all-targets -- -D warnings"

# 3. Tests (debug)
run_check "Tests (debug)" "cargo test --workspace --all-targets"

# 4. Tests (release)
run_check "Tests (release)" "cargo test --workspace --all-targets --release"

# 5. Audit de sécurité
run_check "Audit de sécurité (cargo audit)" "cargo audit"

# 6. Build debug
run_check "Build debug" "cargo build --workspace"

# 7. Build release
run_check "Build release" "cargo build --workspace --release"

# 8. Fuzzing court (2 minutes sur la cible principale)
if command -v cargo-fuzz &> /dev/null || cargo +nightly fuzz --version &> /dev/null 2>&1; then
    run_check "Fuzzing (2 min, bundle_header)" "cargo +nightly fuzz run bundle_header -- -max_total_time=120"
else
    echo -e "${YELLOW}⚠️  Fuzzing ignoré (cargo-fuzz non installé)${NC}"
    echo ""
fi

# 9. Cross-compilation ARMv7 (optionnel, seulement si le linker est disponible)
if command -v arm-linux-gnueabihf-gcc &> /dev/null; then
    run_check "Cross-compilation ARMv7" "cargo build --workspace --target armv7-unknown-linux-gnueabihf --release"
else
    echo -e "${YELLOW}⚠️  Cross-compilation ARMv7 ignorée (linker non disponible)${NC}"
    echo ""
fi

# Résumé
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  Résumé                                                   ║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Succès: ${GREEN}$SUCCESSES${NC}"
echo -e "Échecs: ${RED}$FAILURES${NC}"
echo ""

if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ Tous les pre-merge gates passent !                     ║${NC}"
    echo -e "${GREEN}║  Vous pouvez soumettre votre PR en toute confiance.        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ❌ $FAILURES check(s) ont échoué !                          ║${NC}"
    echo -e "${RED}║  Corrigez les erreurs avant de soumettre votre PR.         ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
