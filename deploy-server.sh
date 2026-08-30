#!/bin/bash
# ============================================================
# DreamSpire Backend Deployment Script
# Builds & deploys the Node.js orchestrator to production
# ============================================================
#
# USAGE (Docker):
#   chmod +x deploy-server.sh
#   ./deploy-server.sh docker
#
# USAGE (Render):
#   ./deploy-server.sh render
# ============================================================

set -e

SERVER_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="dreamspire-orchestrator"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  DREAMSPIRE BACKEND DEPLOYMENT                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

MODE="${1:-docker}"

if [ "$MODE" = "docker" ]; then
  echo "▸ Building Docker image: $IMAGE_NAME..."
  docker build -t "$IMAGE_NAME" "$SERVER_DIR"
  
  echo ""
  echo "▸ Docker image built successfully."
  echo ""
  echo "  To run locally:"
  echo "    docker run -p 4000:4000 --env-file $SERVER_DIR/.env $IMAGE_NAME"
  echo ""
  echo "  To push to a registry:"
  echo "    docker tag $IMAGE_NAME your-registry.com/$IMAGE_NAME:latest"
  echo "    docker push your-registry.com/$IMAGE_NAME:latest"
  echo ""

elif [ "$MODE" = "render" ]; then
  echo "▸ Deploying to Render via render.yaml..."
  echo ""
  echo "  1. Push your server/ directory to a Git repo."
  echo "  2. Connect the repo to Render at https://dashboard.render.com"
  echo "  3. Render will auto-detect render.yaml and deploy."
  echo ""
  echo "  Or use the Render CLI:"
  echo "    render deploy --yaml $SERVER_DIR/render.yaml"
  echo ""

else
  echo "✗ Unknown mode: $MODE"
  echo "  Usage: ./deploy-server.sh [docker|render]"
  exit 1
fi

echo "╔══════════════════════════════════════════════════╗"
echo "║  ✓ DEPLOYMENT READY                             ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
