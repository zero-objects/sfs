#!/usr/bin/env bash
# ============================================================================
# Build script: paper.tex → PDF (arXiv-style preprint)
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="/Library/TeX/texbin:$PATH"

MAIN="paper"
OUTPUT_NAME="sfs_Paper_Preprint"

if [[ "${1:-}" == "clean" ]]; then
  rm -f "${MAIN}".{aux,bbl,blg,log,out,toc,fdb_latexmk,fls,synctex.gz}
  rm -f sections/*.aux
  echo "Done."
  exit 0
fi

echo "==========================================================="
echo "  Build: ${MAIN}.tex → ${MAIN}.pdf"
echo "==========================================================="

pdflatex -interaction=nonstopmode -halt-on-error "${MAIN}.tex" > /dev/null 2>&1 || {
  echo "  X Error in pass 1. Tail of log:"
  tail -40 "${MAIN}.log"
  exit 1
}
echo "  ok pass 1/4"

bibtex "${MAIN}" > /dev/null 2>&1 || echo "  ! BibTeX warning (continuing)"
echo "  ok pass 2/4"

pdflatex -interaction=nonstopmode "${MAIN}.tex" > /dev/null 2>&1
echo "  ok pass 3/4"

pdflatex -interaction=nonstopmode "${MAIN}.tex" > /dev/null 2>&1
echo "  ok pass 4/4"

if [[ -f "${MAIN}.pdf" ]]; then
  cp "${MAIN}.pdf" "${OUTPUT_NAME}.pdf"
  SIZE=$(du -h "${OUTPUT_NAME}.pdf" | cut -f1)
  echo "==========================================================="
  echo "  ok ${OUTPUT_NAME}.pdf built (${SIZE})"
  echo "==========================================================="
fi
