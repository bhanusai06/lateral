#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# LateralShield + TrapWeave — Quick Start Script
# Usage: bash start.sh
# ─────────────────────────────────────────────────────────────
set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}"
echo "  ██╗      █████╗ ████████╗███████╗██████╗  █████╗ ██╗"
echo "  ██║     ██╔══██╗╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║"
echo "  ██║     ███████║   ██║   █████╗  ██████╔╝███████║██║"
echo "  ██║     ██╔══██║   ██║   ██╔══╝  ██╔══██╗██╔══██║██║"
echo "  ███████╗██║  ██║   ██║   ███████╗██║  ██║██║  ██║███████╗"
echo "  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝"
echo "  SHIELD + TRAPWEAVE — VisionX 2026${NC}"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
  echo -e "${RED}✗ Docker not found. Please install Docker Desktop first.${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Docker found${NC}"

# Check Docker is running
if ! docker info &> /dev/null; then
  echo -e "${RED}✗ Docker is not running. Please start Docker Desktop.${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Docker is running${NC}"

# Copy env if not exists
if [ ! -f .env ]; then
  cp .env.example .env
  echo -e "${GREEN}✓ Created .env from .env.example${NC}"
fi

# Step 1: Train models
echo ""
echo -e "${YELLOW}[1/3] Training ML models (this takes ~2 minutes)...${NC}"
docker compose --profile training run --rm trainer
echo -e "${GREEN}✓ Models trained${NC}"

# Step 2: Start services
echo ""
echo -e "${YELLOW}[2/3] Starting all services...${NC}"
docker compose up -d
echo -e "${GREEN}✓ Services starting${NC}"

# Step 3: Wait for health
echo ""
echo -e "${YELLOW}[3/3] Waiting for backend to be ready...${NC}"
for i in $(seq 1 30); do
  if curl -sf http://localhost:5000/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Backend is healthy${NC}"
    break
  fi
  echo -n "."
  sleep 2
done

echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  LateralShield is running!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""
echo -e "  🖥️  Dashboard:   ${CYAN}http://localhost:3000${NC}"
echo -e "  🔌  Backend API: ${CYAN}http://localhost:5000/api/health${NC}"
echo -e "  🗄️  MongoDB:     ${CYAN}localhost:27017${NC}"
echo -e "  🪤  Honeypot 1:  ${CYAN}localhost:8445${NC} (AdminServer_Fake01)"
echo -e "  🪤  Honeypot 2:  ${CYAN}localhost:8433${NC} (DB-Server_Fake02)"
echo ""
echo -e "  To stop: ${YELLOW}docker compose down${NC}"
echo ""
