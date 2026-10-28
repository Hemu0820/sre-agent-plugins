import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import impact_mapper as mapper


NOW = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"


def page(ids, total, token=None, truncated=False):
    result = {
        "data": [{"id": resource_id} for resource_id in ids],
        "totalRecords": total,
        "resultTruncated": truncated,
    }
    if token is not None:
        result["$skipToken"] = token
    return result


class TrackingIdTests(unittest.TestCase):
    def test_normalizes_valid_id(self):
        self.assertEqual(mapper.validate_tracking_id("abcd-123"), "ABCD-123")

    def test_rejects_unsafe_or_unbounded_values(self):
        for value in ("", "A" * 65, "ABC\n", "ABC\r", "A B", "A'B", 'A"B',
                      "A|B", "A;B", "$(cmd)", "-ABC", "A/B", "A_B", "\u00e9", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mapper.validate_tracking_id(value)


class WindowTests(unittest.TestCase):
    def test_active_end_is_execution_not_a_future_mitigation(self):
        result = mapper.derive_windows({
            "impactStart": "2026-10-28T10:00:00Z",
            "impactEnd": "2026-10-28T15:00:00Z",
            "status": "Active",
        }, NOW)
        self.assertEqual(result["analysisStartUtc"], "2026-10-28T09:30:00Z")
        self.assertEqual(result["analysisEndUtc"], "2026-10-28T12:00:00Z")
        self.assertEqual(result["effectiveImpactEndUtc"], result["analysisEndUtc"])
        self.assertEqual(result["declaredImpactEndUtc"], "2026-10-28T15:00:00Z")
        self.assertEqual(result["baselineStartUtc"], "2026-10-21T09:30:00Z")
        self.assertEqual(result["baselineEndUtc"], result["analysisStartUtc"])
        self.assertIn("provisional", result["mode"])

    def test_completed_window_adds_recovery_and_respects_telemetry_cap(self):
        event = {"properties": {
            "ImpactStartTime": "2026-10-28T11:00:00+02:00",
            "ImpactMitigationTime": "2026-10-28T10:00:00Z",
            "Status": "Resolved",
        }}
        result = mapper.derive_windows(event, NOW)
        self.assertEqual(result["impactStartUtc"], "2026-10-28T09:00:00Z")
        self.assertEqual(result["analysisEndUtc"], "2026-10-28T10:30:00Z")
        event["latestTelemetryUtc"] = "2026-10-28T10:15:00Z"
        result = mapper.derive_windows(event, NOW)
        self.assertEqual(result["analysisEndUtc"], "2026-10-28T10:15:00Z")

    def test_future_declared_end_is_preserved_but_query_is_capped(self):
        result = mapper.derive_windows({
            "impactStart": "2026-10-28T10:00:00Z",
            "impactEnd": "2026-10-28T15:00:00Z",
            "status": "Resolved",
        }, NOW)
        self.assertEqual(result["declaredImpactEndUtc"], "2026-10-28T15:00:00Z")
        self.assertEqual(result["effectiveImpactEndUtc"], "2026-10-28T12:00:00Z")
        self.assertEqual(result["analysisEndUtc"], "2026-10-28T12:00:00Z")
        self.assertTrue(result["limitations"])

    def test_future_advisory_uses_readiness_not_future_telemetry(self):
        result = mapper.derive_windows({
            "impactStart": "2026-11-01T10:00:00Z",
            "eventType": "HealthAdvisory", "status": "Active",
        }, NOW)
        self.assertEqual(result["mode"], "Future advisory - readiness assessment")
        self.assertEqual(result["analysisStartUtc"], "2026-10-28T11:30:00Z")
        self.assertEqual(result["analysisEndUtc"], "2026-10-28T12:00:00Z")
        self.assertIsNone(result["effectiveImpactEndUtc"])

    def test_missing_reversed_or_unusable_windows_cannot_classify(self):
        for event in (
            {"status": "Active"},
            {"impactStart": "2026-10-28T10:00:00Z", "status": "Resolved",
             "lastUpdate": "2026-10-28T11:00:00Z"},
            {"impactStart": "2026-10-28T10:00:00Z", "impactEnd": "2026-10-27T10:00:00Z"},
            {"impactStart": "2026-11-01T10:00:00Z", "status": "Active"},
            {"impactStart": "2026-10-28T10:00:00Z", "impactEnd": "2026-10-28T11:00:00Z",
             "latestTelemetryUtc": "2026-10-27T10:00:00Z"},
            {"impactStart": "2026-10-28T10:00:00Z", "impactEnd": "2026-10-28T11:00:00Z",
             "latestTelemetryUtc": "2026-10-28T09:45:00Z"},
        ):
            with self.subTest(event=event):
                result = mapper.derive_windows(event, NOW)
                self.assertFalse(result["telemetryWindowAvailable"])
                self.assertIsNone(result["analysisStartUtc"])
                self.assertTrue(result["limitations"])

    def test_rejects_ambiguous_timestamps_and_invalid_event_shapes(self):
        for event in ([], {"properties": []}, {"impactStart": "not-a-date"},
                      {"impactStart": "2026-10-28T10:00:00"}, {"status": []}):
            with self.subTest(event=event), self.assertRaises(ValueError):
                mapper.derive_windows(event, NOW)


class PaginationTests(unittest.TestCase):
    def test_follows_token_until_all_resources_are_returned(self):
        fetch = Mock(side_effect=[
            page(["/a"], 2, token="next", truncated=True),
            page(["/b"], 2),
        ])
        result = mapper.paged_resources(fetch, 5)
        self.assertEqual(result["status"], "Complete")
        self.assertEqual(result["pageCount"], 2)
        self.assertEqual(result["returnedCount"], 2)
        self.assertEqual([call.args[0] for call in fetch.call_args_list], [None, "next"])
        self.assertNotIn("next", json.dumps(result))

    def test_empty_inventory_is_complete_only_with_complete_metadata(self):
        result = mapper.paged_resources(Mock(return_value=page([], 0)), 1)
        self.assertEqual(result["status"], "Complete")
        self.assertEqual(result["returnedCount"], 0)

    def test_missing_token_or_total_mismatch_is_partial(self):
        for response in (page(["/a"], 2), page(["/a"], 1, truncated=True)):
            with self.subTest(response=response):
                result = mapper.paged_resources(Mock(return_value=response), 2)
                self.assertEqual(result["status"], "Partial")

    def test_page_limit_preserves_rows_and_marks_partial(self):
        result = mapper.paged_resources(
            Mock(return_value=page(["/a"], 2, token="more", truncated=True)), 1,
        )
        self.assertEqual(result["status"], "Partial")
        self.assertEqual(result["returnedCount"], 1)
        self.assertEqual(result["continuationState"], "Present")

    def test_repeated_tokens_do_not_loop_and_ids_are_deduplicated(self):
        fetch = Mock(side_effect=[
            page(["/A"], 2, token="same", truncated=True),
            page(["/a"], 2, token="same", truncated=True),
        ])
        result = mapper.paged_resources(fetch, 10)
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(result["status"], "Partial")
        self.assertEqual(result["returnedCount"], 1)
        self.assertEqual(result["rawReturnedCount"], 2)
        self.assertEqual(result["data"][0]["id"], "/a")

    def test_count_changes_and_out_of_order_results_are_partial(self):
        fetch = Mock(side_effect=[
            page(["/b"], 2, token="next"),
            page(["/a", "/c"], 3),
        ])
        result = mapper.paged_resources(fetch, 5)
        self.assertEqual(result["status"], "Partial")
        self.assertEqual(len(result["limitations"]), 2)

    def test_query_failure_keeps_prior_rows_without_exposing_error_details(self):
        fetch = Mock(side_effect=[page(["/a"], 2, token="next"), OSError("sensitive details")])
        result = mapper.paged_resources(fetch, 5)
        self.assertEqual(result["status"], "Partial")
        self.assertEqual(result["returnedCount"], 1)
        self.assertNotIn("sensitive details", json.dumps(result))

    def test_invalid_page_is_not_complete(self):
        for response in ({}, {"data": [], "totalRecords": 0},
                         page(["not-an-arm-id"], 1), dict(page([], 0), data=None)):
            with self.subTest(response=response):
                result = mapper.paged_resources(Mock(return_value=response), 1)
                self.assertEqual(result["status"], "Partial")


class ResourceGraphTests(unittest.TestCase):
    @patch.object(mapper, "urlopen")
    @patch.object(mapper.subprocess, "run")
    @patch.object(mapper.shutil, "which", return_value="az")
    def test_read_only_request_keeps_query_and_scope_and_token_out_of_output(
        self, which, run, urlopen,
    ):
        run.return_value = Mock(returncode=0, stdout="test-token\n")
        urlopen.side_effect = [
            io.BytesIO(json.dumps(page(["/a"], 2, token="next")).encode()),
            io.BytesIO(json.dumps(page(["/b"], 2)).encode()),
        ]
        reader = mapper.resource_graph_reader("resources | project id, name", [SUBSCRIPTION], 1000)
        result = mapper.paged_resources(reader, 5)
        requests = [call.args[0] for call in urlopen.call_args_list]
        bodies = [json.loads(request.data) for request in requests]
        self.assertEqual(result["status"], "Complete")
        self.assertEqual(bodies[0]["query"], bodies[1]["query"])
        self.assertEqual(bodies[0]["subscriptions"], [SUBSCRIPTION])
        self.assertEqual(bodies[1]["options"]["$skipToken"], "next")
        self.assertTrue(all(request.full_url == mapper.GRAPH_URL for request in requests))
        self.assertTrue(all(request.method == "POST" for request in requests))
        self.assertNotIn("test-token", json.dumps(result))
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch.object(mapper.subprocess, "run")
    def test_invalid_scope_and_truncating_queries_fail_before_authentication(self, run):
        for query, scope in (("resources | take 1", SUBSCRIPTION),
                             ("resources", "invalid-subscription")):
            with self.subTest(query=query), self.assertRaises(ValueError):
                mapper.resource_graph_reader(query, [scope], 1000)
        run.assert_not_called()


class CommandTests(unittest.TestCase):
    def test_cli_emits_normalized_id_or_safe_failure(self):
        for tracking_id, expected in (("abcd-123", 0), ("bad;command", 2)):
            with self.subTest(tracking_id=tracking_id), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(mapper.main(["validate-tracking-id", tracking_id]), expected)
                result = json.loads(out.getvalue())
                if expected == 0:
                    self.assertEqual(result["trackingId"], "ABCD-123")
                else:
                    self.assertNotIn("bad;command", out.getvalue())

    def test_windows_cli_returns_nonzero_when_no_window_can_be_derived(self):
        with tempfile.TemporaryDirectory() as directory:
            event_file = Path(directory) / "event.json"
            for event, expected in (({"status": "Active"}, 2),
                                    ({"status": "Active", "impactStart": "2026-10-28T10:00:00Z"}, 0)):
                event_file.write_text(json.dumps(event), encoding="utf-8")
                with self.subTest(event=event), contextlib.redirect_stdout(io.StringIO()) as out:
                    code = mapper.main(["windows", "--event-file", str(event_file),
                                        "--now", "2026-10-28T12:00:00Z"])
                    self.assertEqual(code, expected)
                    self.assertEqual(json.loads(out.getvalue())["telemetryWindowAvailable"],
                                     expected == 0)


if __name__ == "__main__":
    unittest.main()
