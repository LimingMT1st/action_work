from __future__ import annotations

import asyncio

from gha_cascade_analyzer.enums import RefType
from gha_cascade_analyzer.models import ActionNode, DriftEvent, RefObservation
from gha_cascade_analyzer.storage.checkpoint import CheckpointStore
from gha_cascade_analyzer.utils.parsing import stable_id
from gha_cascade_analyzer.utils.time import utc_now


class GitRefTracker:
    def __init__(self, checkpoint_store: CheckpointStore, git_bin: str = "git") -> None:
        self.checkpoint_store = checkpoint_store
        self.git_bin = git_bin

    async def observe_action_refs(self, action_nodes: list[ActionNode]) -> tuple[list[RefObservation], list[DriftEvent]]:
        if not action_nodes:
            return [], []

        remote_url = f"https://github.com/{action_nodes[0].owner}/{action_nodes[0].repo}.git"
        tag_refs = await self._ls_remote(remote_url, "--tags")
        branch_names = sorted({node.ref for node in action_nodes if node.ref_type == RefType.BRANCH})
        branch_refs = await self._ls_remote(remote_url, "--heads", *(f"refs/heads/{name}" for name in branch_names)) if branch_names else {}

        observed_at = utc_now()
        observations: list[RefObservation] = []
        drift_events: list[DriftEvent] = []

        for action_node in action_nodes:
            resolved = self._resolve_observed_ref(action_node, tag_refs, branch_refs)
            if resolved is None:
                continue
            ref_name, ref_type, sha = resolved
            observations.append(
                RefObservation(
                    action_id=action_node.action_id,
                    owner=action_node.owner,
                    repo=action_node.repo,
                    ref_name=ref_name,
                    ref_type=ref_type,
                    sha=sha,
                    observed_at=observed_at,
                )
            )

            previous = self.checkpoint_store.load_ref_state(action_node.action_id, ref_name, ref_type.value)
            if previous and previous[0] != sha:
                drift_events.append(
                    DriftEvent(
                        drift_id=stable_id(action_node.action_id, ref_type.value, ref_name, previous[0], sha, observed_at.isoformat()),
                        action_id=action_node.action_id,
                        tag_name=ref_name,
                        ref_type=ref_type,
                        previous_sha=previous[0],
                        new_sha=sha,
                        detected_at=observed_at,
                        first_seen_at=None,
                        last_seen_at=observed_at,
                        source="tag_move" if ref_type == RefType.TAG else "branch_head_change",
                        notes=f"Observed mutable ref repoint from {previous[0]} to {sha}",
                    )
                )
            self.checkpoint_store.save_ref_state(
                action_node.action_id,
                ref_name,
                ref_type.value,
                sha,
                observed_at.isoformat(),
            )

        return observations, drift_events

    async def _ls_remote(self, remote_url: str, *args: str) -> dict[str, str]:
        command = [self.git_bin, "ls-remote"]
        options: list[str] = []
        patterns: list[str] = []
        for arg in args:
            if arg.startswith("--"):
                options.append(arg)
            else:
                patterns.append(arg)
        command.extend(options)
        command.append(remote_url)
        command.extend(patterns)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(stderr.decode("utf-8", errors="replace"))

        refs: dict[str, str] = {}
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            sha, ref_name = line.split("\t", 1)
            if ref_name.endswith("^{}"):
                continue
            refs[ref_name] = sha
        return refs

    def _resolve_observed_ref(
        self,
        action_node: ActionNode,
        tag_refs: dict[str, str],
        branch_refs: dict[str, str],
    ) -> tuple[str, RefType, str] | None:
        if action_node.ref_type == RefType.TAG:
            ref_name = f"refs/tags/{action_node.ref}"
            sha = tag_refs.get(ref_name)
            if sha is None:
                return None
            return action_node.ref, RefType.TAG, sha
        if action_node.ref_type == RefType.BRANCH:
            ref_name = f"refs/heads/{action_node.ref}"
            sha = branch_refs.get(ref_name)
            if sha is None:
                return None
            return action_node.ref, RefType.BRANCH, sha
        return None
