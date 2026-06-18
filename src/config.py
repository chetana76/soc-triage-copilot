"""Central configuration. Thresholds live here so reviewers can find the policy."""

import os
from dotenv import load_dotenv
load_dotenv()

# A human must approve any auto-action when the CVSS base score is at or above
# this value. 8.0 sits inside the CVSS "High" band; tune to taste.
PAUSE_THRESHOLD = float(os.getenv("PAUSE_THRESHOLD", "8.0"))

# --- Nebius Token Factory (OpenAI-compatible endpoint) -----------------------
# The bootcamp requires >= 1 model call through Nebius. Get the exact base_url
# and model string from your Nebius console / course materials and put them in
# a .env file (see .env.example). If NEBIUS_API_KEY is unset, the LLM helper
# falls back to a templated response so the pipeline still runs offline.
NEBIUS_API_KEY = os.getenv("NEBIUS_API_KEY", "")
NEBIUS_BASE_URL = os.getenv("NEBIUS_BASE_URL", "https://api.studio.nebius.com/v1")
NEBIUS_MODEL = os.getenv("NEBIUS_MODEL", "meta-llama/Meta-Llama-3.1-8B-Instruct")

# Set to "1" to let the Monitor agent hit the live NVD/CISA APIs. Off by default
# so the demo never breaks on a network hiccup mid-recording.
ENABLE_LIVE_NVD = os.getenv("ENABLE_LIVE_NVD", "0") == "1"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # optional, raises NVD rate limit

# --- Notifications ---
# Slack: create an Incoming Webhook for a channel and export the URL.
# If unset, Slack posts are skipped (the pipeline still runs).
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# Email is produced as a reviewable .eml DRAFT in the outbox (never auto-sent),
# consistent with the human-in-the-loop philosophy for send actions.
INCIDENT_EMAIL_TO = os.getenv("INCIDENT_EMAIL_TO", "soc-oncall@example.com")
INCIDENT_EMAIL_FROM = os.getenv("INCIDENT_EMAIL_FROM", "soc-copilot@example.com")
OUTBOX_DIR = os.getenv("OUTBOX_DIR", "outbox")
