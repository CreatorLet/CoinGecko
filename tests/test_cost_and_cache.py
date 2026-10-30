import os
import tempfile
import unittest
from datetime import datetime, timezone

from deepseek_cost import usage_cost
from persistent_cache import cache_get, cache_set


class DeepSeekCostTests(unittest.TestCase):
    def test_flash_off_peak_uses_actual_cache_hit_and_miss_counts(self):
        saturday = datetime(2026, 10, 31, 12, tzinfo=timezone.utc).timestamp()
        cost = usage_cost("deepseek-flash", {
            "prompt_tokens": 100,
            "completion_tokens": 100,
            "prompt_cache_hit_tokens": 20,
            "prompt_cache_miss_tokens": 80,
        }, saturday)
        self.assertEqual(cost["pricing_window"], "off_peak")
        self.assertAlmostEqual(cost["cost_usd"], 0.00007206, places=12)

    def test_weekday_peak_output_rate_is_higher(self):
        friday_peak = datetime(2026, 10, 30, 7, tzinfo=timezone.utc).timestamp()
        cost = usage_cost("deepseek-flash", {
            "prompt_tokens": 0,
            "completion_tokens": 1000,
        }, friday_peak)
        self.assertEqual(cost["pricing_window"], "peak")
        self.assertAlmostEqual(cost["cost_usd"], 0.0012, places=12)

    def test_missing_usage_counters_are_not_treated_as_free(self):
        self.assertIsNone(usage_cost("deepseek-flash", None))
        self.assertIsNone(usage_cost("deepseek-flash", {"prompt_tokens": 5}))


class PersistentCacheTests(unittest.TestCase):
    def test_cache_round_trip_and_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            old = os.environ.get("COINGECKO_CACHE_DIR")
            os.environ["COINGECKO_CACHE_DIR"] = directory
            try:
                key = {"url": "https://example.invalid/data", "params": {"page": 1}}
                self.assertTrue(cache_set("unit_test", key, {"value": 7}))
                hit, value = cache_get("unit_test", key, 60)
                self.assertTrue(hit)
                self.assertEqual(value, {"value": 7})
                expired, _ = cache_get("unit_test", key, 0)
                self.assertFalse(expired)
            finally:
                if old is None:
                    os.environ.pop("COINGECKO_CACHE_DIR", None)
                else:
                    os.environ["COINGECKO_CACHE_DIR"] = old


if __name__ == "__main__":
    unittest.main()
