import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from frontier import (
    _active_cantina_status,
    _candidate_contract_paths,
    _immunefi_status,
    _parse_datetime,
    analyze_fund_handling,
    analyze_source,
)
from hunter import (candidate_review_gate, inspect_unprivileged_surface, rank, source_risk_signals)


class FrontierTriageTests(unittest.TestCase):
    def test_datetime_parser_normalizes_utc(self):
        parsed = _parse_datetime("2026-10-29T16:00:03Z")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tzinfo, timezone.utc)
        self.assertEqual(parsed.year, 2026)

    def test_candidate_paths_skip_tests_scripts_and_fixtures(self):
        tree = [
            {"type": "blob", "path": "contracts/Vault.sol"},
            {"type": "blob", "path": "script/Deploy.s.sol"},
            {"type": "blob", "path": "test/Vault.t.sol"},
            {"type": "blob", "path": "fixtures/MockToken.sol"},
            {"type": "blob", "path": "lib/openzeppelin-contracts/contracts/utils/Address.sol"},
            {"type": "blob", "path": "contracts/test-helpers/MockERC20.sol"},
            {"type": "blob", "path": "contracts/VaultTest.sol"},
            {"type": "blob", "path": ".deps/npm/hardhat@3.21.0/console.sol"},
            {"type": "blob", "path": "node_modules/pkg/Math.sol"},
        ]
        paths, _, _ = _candidate_contract_paths(tree)
        self.assertEqual(
            [row["path"] for row in paths],
            ["contracts/Vault.sol"],
        )

    def test_guarded_erc20_helper_and_loop_counter_are_not_source_signals(self):
        source = """
        contract Example {
            function _callOptionalReturn() private {
                (bool ok, bytes memory ret) = address(token).call(payload);
                require(ok);
            }
            function loop(uint256 n) external {
                for (uint256 i = 0; i < n; ) {
                    unchecked { ++i; }
                }
            }
        }
        """
        signals = analyze_source("Solidity", source, "TokenOps.sol")
        self.assertNotIn("low-level-call", [row["signal"] for row in signals])
        self.assertNotIn("unchecked", [row["signal"] for row in signals])

    def test_paywall_asset_flow_is_detected_without_labeling_it_a_bug(self):
        source = """
        contract ContentPaywall {
            function unlockDocument(uint256 docId) external {
                usdcToken.safeTransferFrom(msg.sender, author, authorShare);
                isUnlocked[docId][msg.sender] = true;
            }
        }
        """
        signals = analyze_fund_handling("Solidity", source, "ContentPaywall.sol")
        surfaces = {row["surface"] for row in signals}
        self.assertIn("token-transfer", surfaces)
        self.assertIn("financial-entrypoint", surfaces)
        self.assertTrue(all("score" not in row for row in signals))

    def test_unrelated_low_level_call_remains_visible(self):
        source = """
        contract Example {
            function send(address destination, bytes calldata data) external {
                (bool ok, ) = destination.call(data);
                require(ok);
            }
        }
        """
        signals = analyze_source("Solidity", source, "Example.sol")
        self.assertIn("low-level-call", [row["signal"] for row in signals])

    def test_vendored_sources_do_not_drive_risk_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vendored = Path("lib/layerzero/protocol-v2/contracts/interfaces/ISendLib.sol")
            file_path = root / vendored
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(
                "contract Example { function withdraw() external { target.delegatecall(data); } }",
                encoding="utf-8",
            )
            score, signals = source_risk_signals(root, [vendored])
        self.assertEqual(score, 0)
        self.assertEqual(signals, [])

    def test_cantina_completed_contest_is_not_active(self):
        row = {
            "status": "complete",
            "timeframe": {
                "start": "2026-10-01T00:00:00Z",
                "end": "2026-10-08T00:00:00Z",
            },
        }
        result = _active_cantina_status(row, datetime(2026, 10, 29, tzinfo=timezone.utc))
        self.assertIsNone(result[0])

    def test_cantina_stale_live_badge_does_not_override_past_end_date(self):
        row = {
            "status": "live",
            "timeframe": {
                "start": "2026-10-01T00:00:00Z",
                "end": "2026-10-08T00:00:00Z",
            },
        }
        result = _active_cantina_status(row, datetime(2026, 10, 29, tzinfo=timezone.utc))
        self.assertIsNone(result[0])

    def test_immunefi_expired_program_is_not_active(self):
        row = {"launchDate": "2026-01-01T00:00:00Z", "endDate": "2026-10-01T00:00:00Z"}
        status, _, _ = _immunefi_status(row, datetime(2026, 10, 29, tzinfo=timezone.utc))
        self.assertEqual(status, "ended")

    def test_immunefi_paused_program_is_not_active(self):
        row = {
            "launchDate": "2026-01-01T00:00:00Z",
            "endDate": None,
            "isPaused": True,
        }
        status, _, _ = _immunefi_status(row, datetime(2026, 10, 29, tzinfo=timezone.utc))
        self.assertEqual(status, "paused")


class HunterRankingTests(unittest.TestCase):
    def test_openzeppelin_muldiv_xor_false_positive_is_not_scored(self):
        detector = {
            "check": "incorrect-exp",
            "impact": "High",
            "confidence": "High",
            "description": "Math.mulDiv has bitwise-xor operator ^ instead of **: inverse = (3 * denominator) ^ 2",
        }
        score, findings = rank([detector])
        self.assertEqual(score, 0)
        self.assertEqual(findings[0]["triage_status"], "known_pattern_low_priority")
        self.assertIn("modular inverse", findings[0]["triage_note"])

    def test_generic_medium_finding_is_still_scored(self):
        detector = {
            "check": "reentrancy-no-eth",
            "impact": "Medium",
            "confidence": "Medium",
            "description": "Generic reentrancy detector finding outside common library patterns.",
        }
        score, findings = rank([detector])
        self.assertEqual(score, 8)
        self.assertEqual(findings[0]["triage_status"], "untriaged")


class HunterAutopilotGateTests(unittest.TestCase):
    def test_weirdly_named_public_forwarder_is_kept_as_intermediary(self):
        source = [{
            "path": "contracts/Forwarder.sol",
            "content": """
                contract Forwarder {
                    function x7(address destination, bytes calldata payload) external {
                        (bool ok, ) = destination.call(payload);
                        require(ok);
                    }
                }
            """,
        }]
        surface = inspect_unprivileged_surface(source, [])
        self.assertTrue(surface["unprivileged_candidate"])
        self.assertTrue(surface["intermediary_candidate"])
        self.assertEqual(surface["unprivileged_asset_functions"][0]["function"], "x7")

    def test_public_token_flow_is_unprivileged_without_conventional_function_name(self):
        source = [{
            "path": "contracts/Router.sol",
            "content": """
                contract Router {
                    function f9(address asset, address receiver, uint256 qty) external {
                        IERC20(asset).safeTransferFrom(msg.sender, receiver, qty);
                    }
                }
            """,
        }]
        surface = inspect_unprivileged_surface(source, [])
        self.assertTrue(surface["unprivileged_candidate"])
        self.assertFalse(surface["intermediary_candidate"])

    def test_owner_only_withdrawal_does_not_qualify_as_unprivileged(self):
        source = [{
            "path": "contracts/Vault.sol",
            "content": """
                contract Vault {
                    function z(address receiver, uint256 amount) external onlyOwner {
                        token.safeTransfer(receiver, amount);
                    }
                }
            """,
        }]
        surface = inspect_unprivileged_surface(source, [])
        self.assertFalse(surface["unprivileged_candidate"])
        self.assertFalse(surface["intermediary_candidate"])

    def test_500_usd_minimum_is_inclusive(self):
        surface = {"unprivileged_candidate": True, "intermediary_candidate": False}
        self.assertTrue(candidate_review_gate(
            {"economic_exposure_usd_estimate": 500}, surface, 500
        )["eligible"])
        self.assertFalse(candidate_review_gate(
            {"economic_exposure_usd_estimate": 499.99}, surface, 500
        )["eligible"])

    def test_intermediary_exception_does_not_remove_unprivileged_requirement(self):
        intermediary = {"unprivileged_candidate": True, "intermediary_candidate": True}
        privileged = {"unprivileged_candidate": False, "intermediary_candidate": False}
        below_threshold = {"economic_exposure_usd_estimate": 20}
        self.assertTrue(candidate_review_gate(below_threshold, intermediary, 500)["eligible"])
        self.assertFalse(candidate_review_gate(below_threshold, privileged, 500)["eligible"])



if __name__ == "__main__":
    unittest.main()
