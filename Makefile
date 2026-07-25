.PHONY: up down logs seed scan k8s-up k8s-down test build

up:
	docker compose up --build -d

down:
	docker compose down -v

logs:
	docker compose logs -f

seed:
	docker compose exec platform-api /app/seed

build:
	docker compose build

test:
	cd platform && go test ./...

# Trivy image + config scan of every image this repo builds.
# Install trivy first: brew install trivy
scan: build
	./scripts/trivy-scan.sh

k8s-up:
	kubectl apply -k deploy/k8s/overlays/local

k8s-down:
	kubectl delete -k deploy/k8s/overlays/local
