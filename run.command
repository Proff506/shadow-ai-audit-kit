#!/bin/bash
#
# elect-rix AUDIT-KIT — macOS launcher (double-click this file)
# Delegates to run.sh which delegates to audit-kit.py
#
exec bash "$(dirname "$0")/run.sh" "$@"
