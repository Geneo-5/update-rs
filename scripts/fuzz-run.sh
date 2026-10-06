#!/usr/bin/env bash
# fuzz-run.sh — Interface CLI pour le fuzzing
# Permet aux agents de lancer le fuzzer, vérifier les crashes, et générer des rapports
#
# Usage :
#   ./scripts/fuzz-run.sh --target <nom_cible> --duration <secondes> [--report json|text]
#   ./scripts/fuzz-run.sh --check-crashes --target <nom_cible>
#   ./scripts/fuzz-run.sh --coverage --target <nom_cible>
#   ./scripts/fuzz-run.sh --minimize --target <nom_cible> --crash <chemin>

set -euo pipefail

# Couleurs pour la sortie
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables par défaut
TARGET=""
DURATION=300
REPORT_FORMAT="text"
ACTION="run"
CRASH_PATH=""

# Afficher l'aide
show_help() {
    cat << EOF
Usage: fuzz-run.sh [OPTIONS]

Interface CLI pour le fuzzing de update-rs. Permet aux agents de lancer
le fuzzer, vérifier les crashes, et générer des rapports.

Options:
  --target <nom>          Nom de la cible de fuzzing (requis pour --run)
  --duration <secondes>   Durée du fuzzing en secondes (défaut: 300)
  --report <format>       Format du rapport: json ou text (défaut: text)
  --check-crashes         Vérifier si des crashes existent pour la cible
  --coverage              Générer un rapport de couverture
  --minimize              Minimiser un crash (avec --crash)
  --crash <chemin>        Chemin vers le crash à minimiser
  --list-targets          Lister toutes les cibles de fuzzing
  -h, --help              Afficher cette aide

Actions:
  --run (défaut)          Lancer le fuzzer sur la cible spécifiée
  --check-crashes         Vérifier si des crashes existent
  --coverage              Générer un rapport de couverture
  --minimize              Minimiser un crash

Exemples:
  # Lancer 5 minutes de fuzzing sur bundle_header
  ./scripts/fuzz-run.sh --target bundle_header --duration 300

  # Vérifier si des crashes existent
  ./scripts/fuzz-run.sh --check-crashes --target bundle_header

  # Générer un rapport de couverture en JSON
  ./scripts/fuzz-run.sh --coverage --target bundle_header --report json

  # Minimiser un crash
  ./scripts/fuzz-run.sh --minimize --target bundle_header --crash fuzz/artifacts/bundle_header/crash-abc123

Cibles disponibles:
  bundle_header    Parsing du header de bundle
  bundle_chunk     Décryptage et validation d'un chunk
  jail_manifest    Parsing CBOR du manifeste de jail
  tpm_command      Parsing des commandes/réponses TPM
  state_machine    Séquences d'états du démon
EOF
}

# Lister les cibles de fuzzing
list_targets() {
    echo -e "${BLUE}Cibles de fuzzing disponibles :${NC}"
    echo ""
    echo "  bundle_header    Parsing du header de bundle"
    echo "  bundle_chunk     Décryptage et validation d'un chunk"
    echo "  jail_manifest    Parsing CBOR du manifeste de jail"
    echo "  tpm_command      Parsing des commandes/réponses TPM"
    echo "  state_machine    Séquences d'états du démon"
    echo ""
    echo "Pour lancer le fuzzing : ./scripts/fuzz-run.sh --target <nom> --duration <secondes>"
}

# Lancer le fuzzer
run_fuzzer() {
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Erreur: --target est requis pour l'action --run${NC}"
        exit 1
    fi

    echo -e "${BLUE}Lancement du fuzzing sur ${TARGET} pendant ${DURATION} secondes...${NC}"
    echo ""

    # Créer les répertoires nécessaires
    mkdir -p "fuzz/corpus/$TARGET"
    mkdir -p "fuzz/artifacts/$TARGET"

    # Lancer le fuzzer
    local start_time=$(date +%s)
    if cargo +nightly fuzz run "$TARGET" -- -max_total_time="$DURATION" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        echo ""
        echo -e "${GREEN}✅ Fuzzing terminé sans crash après ${duration} secondes${NC}"
        
        # Générer le rapport
        generate_report "$TARGET" "$duration" "success"
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        echo ""
        echo -e "${RED}❌ Crash détecté après ${duration} secondes${NC}"
        echo -e "${YELLOW}Les crashes sont sauvegardés dans fuzz/artifacts/$TARGET/${NC}"
        
        # Générer le rapport
        generate_report "$TARGET" "$duration" "crash"
        exit 1
    fi
}

# Vérifier les crashes
check_crashes() {
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Erreur: --target est requis pour --check-crashes${NC}"
        exit 1
    fi

    local artifacts_dir="fuzz/artifacts/$TARGET"
    
    if [ ! -d "$artifacts_dir" ]; then
        echo -e "${GREEN}✅ Aucun artifact trouvé pour $TARGET${NC}"
        echo "Le fuzzer n'a pas encore été lancé sur cette cible."
        exit 0
    fi

    local crash_count=$(find "$artifacts_dir" -name "crash-*" 2>/dev/null | wc -l)
    local timeout_count=$(find "$artifacts_dir" -name "timeout-*" 2>/dev/null | wc -l)
    local oom_count=$(find "$artifacts_dir" -name "oom-*" 2>/dev/null | wc -l)

    if [ "$crash_count" -eq 0 ] && [ "$timeout_count" -eq 0 ] && [ "$oom_count" -eq 0 ]; then
        echo -e "${GREEN}✅ Aucun crash, timeout ou OOM détecté pour $TARGET${NC}"
        exit 0
    else
        echo -e "${RED}❌ Problèmes détectés pour $TARGET :${NC}"
        [ "$crash_count" -gt 0 ] && echo "  - Crashes: $crash_count"
        [ "$timeout_count" -gt 0 ] && echo "  - Timeouts: $timeout_count"
        [ "$oom_count" -gt 0 ] && echo "  - OOM: $oom_count"
        echo ""
        echo "Artifacts dans : $artifacts_dir"
        echo ""
        echo "Pour minimiser un crash :"
        echo "  ./scripts/fuzz-run.sh --minimize --target $TARGET --crash $artifacts_dir/crash-<hash>"
        exit 1
    fi
}

# Générer un rapport de couverture
generate_coverage() {
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Erreur: --target est requis pour --coverage${NC}"
        exit 1
    fi

    echo -e "${BLUE}Génération du rapport de couverture pour $TARGET...${NC}"
    
    # Utiliser cargo-tarpaulin pour la couverture
    if cargo tarpaulin --workspace --out Json --output-dir "fuzz/coverage/$TARGET" 2>&1; then
        echo -e "${GREEN}✅ Rapport de couverture généré dans fuzz/coverage/$TARGET/${NC}"
        
        if [ "$REPORT_FORMAT" = "json" ]; then
            cat "fuzz/coverage/$TARGET/tarpaulin-report.json"
        else
            echo ""
            echo "Couverture par crate :"
            cargo tarpaulin --workspace --out Stdout 2>&1 | grep -E "^[a-z_-]+.*%" || true
        fi
    else
        echo -e "${RED}❌ Erreur lors de la génération du rapport de couverture${NC}"
        exit 1
    fi
}

# Minimiser un crash
minimize_crash() {
    if [ -z "$TARGET" ] || [ -z "$CRASH_PATH" ]; then
        echo -e "${RED}Erreur: --target et --crash sont requis pour --minimize${NC}"
        exit 1
    fi

    if [ ! -f "$CRASH_PATH" ]; then
        echo -e "${RED}Erreur: Le fichier crash n'existe pas: $CRASH_PATH${NC}"
        exit 1
    fi

    echo -e "${BLUE}Minimisation du crash: $CRASH_PATH${NC}"
    
    if cargo +nightly fuzz tmin "$TARGET" "$CRASH_PATH" 2>&1; then
        echo -e "${GREEN}✅ Crash minimisé${NC}"
        echo "Le crash minimisé se trouve dans le même répertoire que l'original."
    else
        echo -e "${RED}❌ Erreur lors de la minimisation${NC}"
        exit 1
    fi
}

# Générer un rapport
generate_report() {
    local target=$1
    local duration=$2
    local status=$3

    if [ "$REPORT_FORMAT" = "json" ]; then
        cat << EOF
{
  "target": "$target",
  "duration_seconds": $duration,
  "status": "$status",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "artifacts_dir": "fuzz/artifacts/$target",
  "corpus_dir": "fuzz/corpus/$target"
}
EOF
    else
        echo ""
        echo "═══════════════════════════════════════"
        echo " Rapport de fuzzing"
        echo "═══════════════════════════════════════"
        echo " Cible:     $target"
        echo " Durée:     ${duration}s"
        echo " Statut:    $status"
        echo " Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo " Artifacts: fuzz/artifacts/$target/"
        echo " Corpus:    fuzz/corpus/$target/"
        echo "═══════════════════════════════════════"
    fi
}

# Parser les arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --report)
            REPORT_FORMAT="$2"
            shift 2
            ;;
        --check-crashes)
            ACTION="check-crashes"
            shift
            ;;
        --coverage)
            ACTION="coverage"
            shift
            ;;
        --minimize)
            ACTION="minimize"
            shift
            ;;
        --crash)
            CRASH_PATH="$2"
            shift 2
            ;;
        --list-targets)
            list_targets
            exit 0
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

# Exécuter l'action
case $ACTION in
    run)
        run_fuzzer
        ;;
    check-crashes)
        check_crashes
        ;;
    coverage)
        generate_coverage
        ;;
    minimize)
        minimize_crash
        ;;
    *)
        echo -e "${RED}Action inconnue: $ACTION${NC}"
        show_help
        exit 1
        ;;
esac
