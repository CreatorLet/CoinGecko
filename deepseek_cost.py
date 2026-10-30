"""DeepSeek token-cost accounting for the CoinGecko Hunter.

Rates are USD per 1M tokens from DeepSeek's published rate card. The estimator
uses the peak weekday rate during listed peak UTC windows and the off-peak
rate otherwise. It deliberately prices unknown model aliases at the highest
published tier so budgets are not silently undercounted.
"""
from datetime import datetime, timezone


# USD per 1,000,000 tokens: cache-hit input, cache-miss input, output.
_RATES = {
    "deepseek-flash": {
        "off_peak": {"cache_hit": 0.003, "cache_miss": 0.15, "output": 0.60},
        "peak": {"cache_hit": 0.006, "cache_miss": 0.30, "output": 1.20},
    },
    "deepseek-v4-pro": {
        "off_peak": {"cache_hit": 0.022, "cache_miss": 0.66, "output": 1.98},
        "peak": {"cache_hit": 0.044, "cache_miss": 1.32, "output": 3.96},
    },
}


def _rate_key(model):
    name = (model or "").strip().lower()
    if name in {"deepseek-flash", "deepseek-v4-flash"}:
        return "deepseek-flash"
    if name in {"deepseek-v4-pro"}:
        return "deepseek-v4-pro"
    # Unknown aliases are priced at the highest listed tier rather than $0.
    return "deepseek-v4-pro"


def _pricing_window(timestamp=None):
    now = datetime.fromtimestamp(timestamp, timezone.utc) if timestamp is not None else datetime.now(timezone.utc)
    # DeepSeek lists peak pricing at 01:00-04:00 and 06:00-10:00 UTC,
    # Monday-Friday. Treat possible Chinese public holidays as peak (conservative).
    peak = now.weekday() < 5 and (1 <= now.hour < 4 or 6 <= now.hour < 10)
    return "peak" if peak else "off_peak"


def usage_cost(model, usage, timestamp=None):
    """Return a detailed cost estimate from a DeepSeek API usage object.

    Returns None when usage counters are absent; callers should fail closed
    rather than pretending an unmetered request was free.
    """
    if not isinstance(usage, dict):
        return None

    try:
        prompt_tokens = usage.get("prompt_tokens", usage.get("input_tokens"))
        completion_tokens = usage.get("completion_tokens", usage.get("output_tokens"))
        if prompt_tokens is None or completion_tokens is None:
            return None
        prompt_tokens = max(0, int(prompt_tokens))
        completion_tokens = max(0, int(completion_tokens))
        details = usage.get("prompt_tokens_details") or usage.get("input_tokens_details") or {}
        cache_hit = usage.get("prompt_cache_hit_tokens")
        if cache_hit is None:
            cache_hit = details.get("prompt_cache_hit_tokens", details.get("cached_tokens", 0))
        cache_miss = usage.get("prompt_cache_miss_tokens")
        if cache_miss is None:
            cache_miss = details.get("prompt_cache_miss_tokens")
        cache_hit = max(0, min(prompt_tokens, int(cache_hit or 0)))
        if cache_miss is None:
            cache_miss = max(0, prompt_tokens - cache_hit)
        cache_miss = max(0, int(cache_miss))
        if cache_hit + cache_miss < prompt_tokens:
            cache_miss += prompt_tokens - cache_hit - cache_miss
    except (TypeError, ValueError, OverflowError):
        return None

    rate_model = _rate_key(model)
    window = _pricing_window(timestamp)
    rates = _RATES[rate_model][window]
    input_cost = (
        cache_hit * rates["cache_hit"] + cache_miss * rates["cache_miss"]
    ) / 1_000_000
    output_cost = completion_tokens * rates["output"] / 1_000_000
    return {
        "cost_usd": round(input_cost + output_cost, 12),
        "input_cost_usd": round(input_cost, 12),
        "output_cost_usd": round(output_cost, 12),
        "prompt_tokens": prompt_tokens,
        "prompt_cache_hit_tokens": cache_hit,
        "prompt_cache_miss_tokens": cache_miss,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
        "model": model,
        "pricing_model": rate_model,
        "pricing_window": window,
    }
