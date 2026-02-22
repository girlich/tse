# TSE/DSFinV-K QR signature verification tests
# make test     - run Python on all .tse files, time-offset trials, and Java tests
# make test-python - run Python on each .tse file
# make test-time-offset - try ±2h, ±1h, 0 on 2025-12-02-Im_Angebot.tse to find working offset
# make test-java - run Java reference tests (mvn test)

PYTHON   := python3
TSE_PY   := tse.py
TSE_FILES := test-java-256.tse test-java-384.tse test-quirks.tse test-standard.tse

# Virtualenv for test dependencies
VENV := .venv
PY := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip
PYFLAKES := $(VENV)/bin/pyflakes
# Java reference repo: set TSE_JAVA_DIR or we clone into .java-ref
TSE_JAVA_DIR ?= .java-ref
JAVA_REPO_URL := https://github.com/berohndo/tse_signature_verification.git

.PHONY: test test-python test-flakes test-java venv ensure-java-ref

# top-level test: ensure venv, run static checks, python and java tests
test: venv test-flakes test-python test-java

# Run Python verifier on each .tse file; print file and signature_verified
test-python:
	@echo "=== Python verification ($(TSE_FILES)) ==="
	@for f in $(TSE_FILES); do \
		result=$$($(PY) $(TSE_PY) < "$$f" 2>/dev/null | $(PY) -c "import sys,json; d=json.load(sys.stdin); print('PASS' if d.get('signature_verified') else 'FAIL')" 2>/dev/null); \
		echo "  $$f: $$result"; \
	done

# Run pyflakes in the venv
test-flakes: venv
	@echo "=== Pyflakes static check ==="
	@$(PYFLAKES) $(TSE_PY)

# Try time offsets (seconds) on Im_Angebot to find the one that makes signature verify.
# DER time is just Unix seconds; TSE might have signed with +1h or -1h interpretation.
# Result: 2025-12-02-Im_Angebot.tse verifies with TIME_OFFSET_SECONDS=3600 (+1h).
# test-time-offset removed (debug-only)

# Run Java reference tests (clone repo if needed; skip if mvn not available)
test-java: ensure-java-ref
	@echo "=== Java reference (mvn test) ==="
	@command -v mvn >/dev/null 2>&1 || { echo "  (mvn not found, skip)"; exit 0; }; \
	cd $(TSE_JAVA_DIR) && mvn -q test 2>&1 && echo "  Java tests: PASS" || echo "  Java tests: FAIL"

ensure-java-ref:
	@if [ ! -d "$(TSE_JAVA_DIR)/.git" ]; then \
		echo "Cloning Java reference into $(TSE_JAVA_DIR)..."; \
		git clone --depth 1 $(JAVA_REPO_URL) $(TSE_JAVA_DIR); \
	fi


# Create virtualenv and install requirements + pyflakes
venv:
	@command -v python3 >/dev/null 2>&1 || { echo "python3 not found"; exit 1; }
	@test -d $(VENV) || python3 -m venv $(VENV)
	@$(PIP) install --upgrade pip >/dev/null
	@$(PIP) install -r requirements.txt pyflakes >/dev/null
