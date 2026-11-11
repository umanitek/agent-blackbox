"""Reading the node's durable catch-up job: denied, which job, and its status."""

from __future__ import annotations

from typing import Any

from ..kernel.dkg_client import DkgClient, DkgError


def _catchup_job_id(catchup: Any) -> str:
    if not isinstance(catchup, dict):
        return ""
    nested = catchup.get("catchup")
    if isinstance(nested, dict):
        catchup = nested
    return str(catchup.get("jobId") or catchup.get("job_id") or catchup.get("id") or "")


def _catchup_status(
    client: DkgClient,
    context_graph_id: str,
    job_id: str = "",
) -> tuple[dict[str, Any], bool]:
    """Read an exact catch-up job when supported, otherwise the graph latest."""
    if job_id:
        try:
            return client.catchup_status(context_graph_id, job_id=job_id), True
        except TypeError as exc:
            # Compatibility for older plugin clients and test doubles that do
            # not yet accept the keyword. Do not hide unrelated TypeErrors.
            if "job_id" not in str(exc):
                raise
        except DkgError as exc:
            # The daemon bounds its job history. If the exact job was evicted,
            # inspect the latest job and adopt it in the caller. Transport and
            # server failures must keep the caller pinned to this exact job.
            if exc.status_code not in {404, 410}:
                raise
    return client.catchup_status(context_graph_id), False
