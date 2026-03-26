.PHONY: help setup train start stop clean logs

help:
	@echo ""
	@echo "  LateralShield + TrapWeave — Make Commands"
	@echo "  ==========================================="
	@echo "  make setup    — Copy .env and install deps"
	@echo "  make train    — Generate dataset + train models"
	@echo "  make start    — Start all Docker services"
	@echo "  make stop     — Stop all Docker services"
	@echo "  make logs     — Tail logs for all services"
	@echo "  make clean    — Remove containers + volumes"
	@echo "  make dev      — Run backend + frontend locally"
	@echo ""

setup:
	@cp -n .env.example .env 2>/dev/null || true
	@echo "[OK] .env ready"

train: setup
	@echo "Generating synthetic dataset..."
	@python data/pipeline/download_dataset.py
	@echo "Training ML models..."
	@python backend/models/train.py

train-docker: setup
	@docker compose --profile training run --rm trainer

start:
	@docker compose up -d
	@echo "[OK] All services started — http://localhost:3000"

stop:
	@docker compose down

logs:
	@docker compose logs -f

clean:
	@docker compose down -v --remove-orphans
	@rm -rf backend/models/saved/*.pkl
	@echo "[OK] Cleaned"

dev:
	@echo "Starting backend..."
	@cd backend && python app.py &
	@echo "Starting frontend..."
	@cd frontend && npm run dev

test-api:
	@echo "Testing analyze endpoint..."
	@curl -s -X POST http://localhost:5000/api/analyze \
	  -H "Content-Type: application/json" \
	  -d '{"ct_src_ltm":47,"sbytes":2400000,"dur":0.003,"proto":1}' | python -m json.tool
