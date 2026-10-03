#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
bash -n xray_deploy.sh
python3 test_parser.py
bash test_atomic_config.sh
