"""Read-only, deterministic helpers for the Service Health Impact Mapper."""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.request import Request, urlopen
from uuid import UUID


UTC = timezone.utc
RESOURCE_MANAGER = "https://management.azure.com/"
GRAPH_URL = RESOURCE_MANAGER + "providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01"


def validate_tracking_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", value):
        raise ValueError("Tracking ID must be 1-64 ASCII letters, digits, or hyphens.")
    return value.upper()


def parse_time(value):
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError("Timestamps must be ISO 8601 strings with a timezone.")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamps must include a timezone.")
    return parsed.astimezone(UTC)


def format_time(value):
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


def derive_windows(event, now):
    if not isinstance(event, dict):
        raise ValueError("Event input must be one JSON object.")
    properties = event.get("properties", event)
    if not isinstance(properties, dict):
        raise ValueError("Event properties must be a JSON object.")
    start = parse_time(properties.get("ImpactStartTime", event.get("impactStart")))
    end = parse_time(properties.get("ImpactMitigationTime", event.get("impactEnd")))
    latest = parse_time(event.get("latestTelemetryUtc"))
    event_type = properties.get("EventType", event.get("eventType", ""))
    status = properties.get("Status", event.get("status", ""))
    if not isinstance(event_type, str) or not isinstance(status, str):
        raise ValueError("Event type and status must be strings.")
    limits = []
    result = {
        "impactStartUtc": format_time(start),
        "declaredImpactEndUtc": format_time(end),
        "effectiveImpactEndUtc": None,
        "analysisStartUtc": None,
        "analysisEndUtc": None,
        "baselineStartUtc": None,
        "baselineEndUtc": None,
        "executionTimeUtc": format_time(now),
        "mode": "Unable to assess",
        "telemetryWindowAvailable": False,
        "limitations": limits,
    }
    if start is None:
        limits.append("Missing impact start; continue inventory without telemetry classification.")
        return result
    if end is not None and end < start:
        limits.append("Impact end precedes impact start; event timestamps require correction.")
        return result
    if start > now and event_type.casefold().endswith("advisory"):
        result["mode"] = "Future advisory - readiness assessment"
        analysis_start = now - timedelta(minutes=30)
        analysis_end = min(now, latest) if latest is not None else now
        limits.append("Future scope is potential exposure, not evidence of completed impact.")
    elif start > now:
        limits.append("Impact start is in the future; no observed-impact window is available.")
        return result
    elif status.casefold() == "active":
        result["mode"] = "Active event - provisional end"
        result["effectiveImpactEndUtc"] = format_time(now)
        analysis_start, analysis_end = start - timedelta(minutes=30), now
        limits.append("Recovery pending; rerun at least 30 minutes after mitigation.")
    elif end is not None:
        result["mode"] = "Completed event"
        result["effectiveImpactEndUtc"] = format_time(min(end, now))
        analysis_start = start - timedelta(minutes=30)
        analysis_end = min(end + timedelta(minutes=30), now)
        if latest is not None:
            analysis_end = min(analysis_end, latest)
        if end > now:
            limits.append("Declared end is in the future; rerun after the declared end.")
    else:
        limits.append("No authoritative impact end or Active status; window cannot be derived.")
        return result
    if analysis_end <= analysis_start or (
        result["mode"] != "Future advisory - readiness assessment" and analysis_end <= start
    ):
        limits.append("Available telemetry does not overlap a usable analysis window.")
        return result
    result.update({
        "analysisStartUtc": format_time(analysis_start),
        "analysisEndUtc": format_time(analysis_end),
        "baselineStartUtc": format_time(analysis_start - timedelta(days=7)),
        "baselineEndUtc": format_time(analysis_start),
        "telemetryWindowAvailable": True,
    })
    return result


def paged_resources(fetch_page, max_pages):
    resources, limits, tokens = {}, [], set()
    token, total, raw_count, page_count = None, None, 0, 0
    last_id = None
    for _ in range(max_pages):
        try:
            page = fetch_page(token)
            rows, page_total = page["data"], page["totalRecords"]
            if not isinstance(rows, list) or type(page_total) is not int or page_total < 0:
                raise ValueError("Invalid Resource Graph page.")
            if any(not isinstance(row, dict) or not isinstance(row.get("id"), str)
                   or not row["id"].startswith("/") for row in rows):
                raise ValueError("Resource Graph rows require scalar ARM IDs.")
            next_token = page.get("$skipToken")
            if next_token is not None and (not isinstance(next_token, str) or not next_token):
                raise ValueError("Invalid continuation token.")
            truncated = page.get("resultTruncated")
            if truncated not in (True, False, "true", "false"):
                raise ValueError("Missing or invalid truncation metadata.")
        except (OSError, ValueError, RuntimeError, KeyError, TypeError):
            limits.append("Resource Graph request failed or returned an invalid page.")
            break
        page_count += 1
        if total is not None and total != page_total:
            limits.append("Resource count changed during pagination.")
        total = page_total
        for row in rows:
            resource_id = row["id"].lower()
            if last_id is not None and resource_id <= last_id:
                limits.append("Duplicate or out-of-order resource ID during pagination.")
            last_id = resource_id
            resources.setdefault(resource_id, dict(row, id=resource_id))
        raw_count += len(rows)
        token = next_token
        if token is None:
            if truncated in (True, "true") or len(resources) != total:
                limits.append("Results are incomplete without a continuation token.")
            break
        if token in tokens:
            limits.append("Repeated continuation token; pagination stopped.")
            break
        tokens.add(token)
    else:
        limits.append("Page limit reached before discovery completed.")
    if token is not None and not limits:
        limits.append("Discovery stopped with a continuation token.")
    return {
        "status": "Partial" if limits else "Complete",
        "pageCount": page_count,
        "returnedCount": len(resources),
        "rawReturnedCount": raw_count,
        "totalRecords": total,
        "continuationState": "Present" if token is not None else "None",
        "truncated": bool(limits),
        "limitations": list(dict.fromkeys(limits)),
        "data": [resources[key] for key in sorted(resources)],
    }


def resource_graph_reader(query, subscriptions, page_size):
    if re.search(r"(?:^|\|)\s*(take|limit|sample)\b", query, re.IGNORECASE):
        raise ValueError("Remove take, limit, or sample before paging resource inventory.")
    subscriptions = [str(UUID(value)) for value in subscriptions]
    query = query.rstrip().rstrip(";") + "\n| extend id=tolower(tostring(id)) | order by id asc"
    az = shutil.which("az")
    if az is None:
        raise ValueError("Authenticated Azure CLI is required for Resource Graph discovery.")
    # No evidence or caller-supplied values are passed to the CLI executable.
    credentials = subprocess.run(
        [az, "account", "get-access-token", "--resource", RESOURCE_MANAGER,
         "--query", "accessToken", "--output", "tsv", "--only-show-errors"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if credentials.returncode or not credentials.stdout.strip():
        raise ValueError("Could not obtain an Azure Resource Manager token from Azure CLI.")
    access_token = credentials.stdout.strip()

    def fetch_page(token):
        options = {"$top": page_size, "resultFormat": "objectArray"}
        if token is not None:
            options["$skipToken"] = token
        body = {"query": query, "subscriptions": subscriptions, "options": options}
        request = Request(
            GRAPH_URL, data=json.dumps(body).encode("utf-8"), method="POST",
            headers={"Authorization": "Bearer " + access_token, "Content-Type": "application/json"},
        )
        with urlopen(request, timeout=60) as response:
            return json.load(response)

    return fetch_page


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Value must be positive.")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-tracking-id")
    validate.add_argument("tracking_id")
    windows = commands.add_parser("windows")
    windows.add_argument("--event-file", type=Path, required=True)
    windows.add_argument("--now", help="ISO 8601 execution time with timezone; default: current UTC.")
    resources = commands.add_parser("resources")
    resources.add_argument("--query-file", type=Path, required=True)
    resources.add_argument("--subscriptions", nargs="+", required=True)
    resources.add_argument("--page-size", type=positive_int, default=1000)
    resources.add_argument("--max-pages", type=positive_int, default=100)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-tracking-id":
            result = {"trackingId": validate_tracking_id(args.tracking_id)}
        elif args.command == "windows":
            event = json.loads(args.event_file.read_text(encoding="utf-8-sig"))
            now = parse_time(args.now) if args.now is not None else datetime.now(UTC)
            if now is None:
                raise ValueError("Execution time cannot be empty.")
            result = derive_windows(event, now)
        else:
            if args.page_size > 1000:
                raise ValueError("Resource Graph page size cannot exceed 1000.")
            query = args.query_file.read_text(encoding="utf-8-sig")
            if not query.strip():
                raise ValueError("Resource Graph query cannot be empty.")
            fetch_page = resource_graph_reader(query, args.subscriptions, args.page_size)
            result = paged_resources(fetch_page, args.max_pages)
    except (OSError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"status": "Unable to assess",
                          "error": "Invalid input or helper unavailable; check inputs and Azure CLI access."}))
        return 2
    print(json.dumps(result, indent=2))
    if result.get("status") == "Partial" or result.get("telemetryWindowAvailable") is False:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
