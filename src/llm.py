"""
Thin LLM helper that talks to Nebius Token Factory via the OpenAI-compatible API.

If NEBIUS_API_KEY is not set, it returns a clearly-marked templated string so the
whole pipeline still runs end-to-end offline (useful for tests and for grading
the deterministic/safety core without burning tokens).
"""

from . import config

_USED_LIVE_LLM = False  # observability: did we actually hit Nebius this run?


def llm_was_used() -> bool:
    return _USED_LIVE_LLM


def chat(system: str, user: str, max_tokens: int = 400) -> str:
    global _USED_LIVE_LLM
    if not config.NEBIUS_API_KEY:
        return _offline_fallback(system, user)
    try:
        from openai import OpenAI

        client = OpenAI(api_key=config.NEBIUS_API_KEY, base_url=config.NEBIUS_BASE_URL)
        resp = client.chat.completions.create(
            model=config.NEBIUS_MODEL,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
            max_tokens=max_tokens,
        )
        _USED_LIVE_LLM = True
        return resp.choices[0].message.content.strip()
    except Exception as e:  # graceful degradation - never crash the pipeline
        return f"[LLM unavailable: {e}]\n" + _offline_fallback(system, user)


def _offline_fallback(system: str, user: str) -> str:
    return (
        "[OFFLINE FALLBACK - set NEBIUS_API_KEY for real generation]\n"
        + user[:600]
    )
