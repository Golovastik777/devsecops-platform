# Local entry points; CI calls the same scripts.
PYTHON ?= python3
VENV   := .venv
export REPORTS_DIR ?= reports

.PHONY: venv test scan policies image dast e2e gate clean

venv:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q --require-hashes -r app/requirements.txt -r app/requirements-dev.txt -r ci/requirements.txt

test: venv
	cd app && ../$(VENV)/bin/python -m pytest
	$(VENV)/bin/python -m pytest -q ci/tests triage/tests

scan: venv
	bash ci/scan-secrets.sh
	bash ci/scan-sast.sh
	bash ci/scan-deps.sh
	bash ci/scan-iac.sh
	bash ci/build-image.sh
	$(VENV)/bin/python ci/security_gate.py

policies:
	bash ci/test-policies.sh

image:
	bash ci/build-image.sh

# On macOS (Docker Desktop) run: make dast DOCKER_NETWORK=bridge TARGET_URL=http://host.docker.internal:8080
dast: image
	bash ci/run-app.sh
	bash ci/dast.sh

e2e: image
	bash ci/e2e-kind.sh

gate: venv
	$(VENV)/bin/python ci/security_gate.py

clean:
	rm -rf reports .cache $(VENV)
	-docker rm -f kb-assistant-dast
