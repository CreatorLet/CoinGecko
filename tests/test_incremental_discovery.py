import unittest
from unittest.mock import patch

import frontier
import hunter


class IncrementalDiscoveryTests(unittest.TestCase):
    def test_sourcify_uses_after_match_id_cursor(self):
        payload = {"results": [{
            "address": "0x1111111111111111111111111111111111111111",
            "match": "exact_match", "matchId": "456",
            "verifiedAt": "2026-10-30T10:00:00Z",
        }]}
        with patch("frontier.get_json", return_value=payload) as get_json:
            rows = frontier.discover_verified("bsc", limit=200, after_match_id="123")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sourcify_match_id"], "456")
        params = get_json.call_args.kwargs["params"]
        self.assertEqual(params, {"limit": 200, "sort": "desc", "afterMatchId": "123"})

    def test_geckoterminal_page_parser_returns_token_pool(self):
        address = "0x2222222222222222222222222222222222222222"
        payload = {"data": [{
            "attributes": {
                "address": "0x3333333333333333333333333333333333333333",
                "name": "TOKEN / WBNB",
                "pool_created_at": "2026-10-30T10:00:00Z",
                "reserve_in_usd": "900",
                "volume_usd": {"h24": "1200"},
            },
            "relationships": {
                "base_token": {"data": {"id": "bsc_" + address}},
                "quote_token": {"data": {"id": "bsc_0x4444444444444444444444444444444444444444"}},
            },
        }]}
        with patch("hunter.get_json", return_value=payload) as get_json:
            rows = hunter.discover_gecko_page("bsc", 3)
        self.assertEqual(rows[0]["base_token"], address)
        self.assertEqual(rows[0]["reserve_usd"], "900")
        self.assertEqual(get_json.call_args.args[1], {"page": 3})

    def test_autopilot_advances_both_source_cursors_and_keeps_pending_rows(self):
        pending = {
            "network": "bsc",
            "address": "0x5555555555555555555555555555555555555555",
            "target_kind": "verified_contract",
        }
        pool = {
            "network": "bsc",
            "base_token": "0x6666666666666666666666666666666666666666",
            "name": "New pool",
            "reserve_usd": "700",
        }
        verified = {
            "network": "bsc",
            "address": "0x7777777777777777777777777777777777777777",
            "sourcify_match_id": "200",
            "verified_at": "2026-10-30T10:00:00Z",
        }
        state = {
            "network": "bsc",
            "gecko_page_next": 4,
            "gecko_pass_complete": False,
            "include_verified": True,
            "sourcify_after_match_id": "100",
            "sourcify_pass_complete": False,
            "candidates": [pending],
            "next_index": 0,
            "processed_addresses": set(),
            "current": None,
            "max_candidates": 0,
            "cycle_candidate_count": 1,
            "records": [],
            "out_path": "unused-report.json",
            "checkpoint_path": "unused-checkpoint.json",
        }
        with patch("hunter.discover_gecko_page", return_value=[pool]) as gecko, \
             patch("frontier.discover_verified", return_value=[verified]) as sourcify, \
             patch("hunter._save_autopilot_state"):
            result = hunter._discover_autopilot_candidates(state)
        gecko.assert_called_once_with("bsc", 4)
        sourcify.assert_called_once_with("bsc", limit=200, after_match_id="100")
        self.assertEqual(state["gecko_page_next"], 5)
        self.assertEqual(state["sourcify_after_match_id"], "200")
        self.assertEqual([row["address"] for row in state["candidates"]], [
            pending["address"], pool["base_token"], verified["address"],
        ])
        self.assertEqual(result["new_unique_candidates"], 2)


if __name__ == "__main__":
    unittest.main()
