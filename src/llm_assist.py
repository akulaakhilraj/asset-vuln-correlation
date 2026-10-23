"""Optional AI step: ask an LLM to suggest owners for assets the rules could not attribute.

Suggestions are written to a review file and never applied automatically, so a person
confirms them and adds a rule to config/pipeline.yaml. Runs only if ANTHROPIC_API_KEY is set.
"""
import json
import os
from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parents[1]
API_URL = "https://api.anthropic.com/v1/messages"


def suggest_owners(attributed: pd.DataFrame, owners: pd.DataFrame, model: str = "claude-sonnet-4-5") -> pd.DataFrame | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    unowned = attributed[attributed.match_rule == "none"]
    if not key or unowned.empty:
        return None
    prompt = (
        "You help attribute IT assets to owning teams. Known owners:\n"
        f"{owners[['hostname', 'team']].to_csv(index=False)}\n"
        "For each unattributed asset below, suggest the most likely team or 'unknown', "
        "with a one-line reason. Reply only with a JSON list of {asset_id, suggested_team, reason}.\n"
        f"{unowned[['asset_id', 'hostname', 'ip']].to_csv(index=False)}"
    )
    r = requests.post(API_URL, timeout=60, headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        json={"model": model, "max_tokens": 800, "messages": [{"role": "user", "content": prompt}]})
    r.raise_for_status()
    text = r.json()["content"][0]["text"]
    df = pd.DataFrame(json.loads(text[text.find("["): text.rfind("]") + 1]))
    df.to_csv(ROOT / "outputs" / "llm_owner_suggestions_for_review.csv", index=False)
    return df
