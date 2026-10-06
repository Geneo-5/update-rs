#!/usr/bin/env bash
# build.sh — Script de build pour update-rs
# Ce script doit être exécuté dans le conteneur Docker
#
# Usage :
#   ./scripts/build.sh              # Build debug
#   ./scripts/build.sh --release    # Build release
#   ./scripts/build.sh --arm        # Build cross-compilation ARMv7
#   ./scripts/build.sh --all        # Build tout (debug + release + ARMv7)

set -euo pipefail

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variables
MODE="debug"
TARGET=""
BUILD_ALL=false

# Afficher l'aide
show_help() {
    cat << EOF
Usage: build.sh [OPTIONS]

Script de build pour update-rs. Doit être exécuté dans le conteneur Docker.

Options:
  --release       Build en mode release (optimisé)
  --arm           Build cross-compilation ARMv7 (armv7-unknown-linux-gnueabihf)
  --all           Build tout (debug + release + ARMv7)
  -h, --help      Afficher cette aide

Exemples:
  ./scripts/build.sh              # Build debug (natif)
  ./scripts/build.sh --release    # Build release (natif)
  ./scripts/build.sh --arm        # Build cross-compilation ARMv7
  ./scripts/build.sh --all        # Build tout
EOF
}

# Build debug
build_debug() {
    echo -e "${BLUE}Build debug (natif)...${NC}"
    cargo build --workspace
    echo -e "${GREEN}✅ Build debug terminé${NC}"
}

# Build release
build_release() {
    echo -e "${BLUE}Build release (natif)...${NC}"
    cargo build --workspace --release
    echo -e "${GREEN}✅ Build release terminé${NC}"
}

# Build ARMv7
build_arm() {
    echo -e "${BLUE}Build cross-compilation ARMv7...${NC}"
    
    # Vérifier que le linker est disponible
    if ! command -v arm-linux-gnueabihf-gcc &> /dev/null; then
        echo -e "${RED}Erreur: arm-linux-gnueabihf-gcc n'est pas installé${NC}"
        echo "Ce script doit être exécuté dans le conteneur Docker."
        exit 1
    fi
    
    cargo build --workspace --target armv7-unknown-linux-gnueabihf --release
    echo -e "${GREEN}✅ Build ARMv7 terminé${NC}"
    
    # Afficher les binaires générés
    echo ""
    echo "Binaires ARMv7 générés :"
    ls -lh target/armv7-unknown-linux-gnueabihf/release/updated 2>/dev/null || true
    ls -lh target/armv7-unknown-linux-gnueabihf/release/updatectl 2>/dev/null || true
}

# Parser les arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            MODE="release"
            shift
            ;;
        --arm)
            TARGET="arm"
            shift
            ;;
        --all)
            BUILD_ALL=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Option inconnue: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Exécuter le build
if [ "$BUILD_ALL" = true ]; then
    build_debug
    echo ""
    build_release
    echo ""
    build_arm
elif [ "$TARGET" = "arm" ]; then
    build_arm
elif [ "$MODE" = "release" ]; then
    build_release
else
    build_debug
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN} Build terminé avec succès${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
