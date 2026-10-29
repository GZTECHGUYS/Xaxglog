"""Phase 8: team workspaces, comments and assignments.

The collaboration layer is intentionally thin: evidence stays in the existing
case/graph tables, while workspaces provide shared context, discussion and
task ownership.  No second evidence store is created.
"""
from __future__ import annotations

from typing import Any

from . import store


def allowed_ids(username: str, role: str) -> set[int] | None:
    """Return accessible workspace ids, or None for an admin (all)."""
    if role == "admin":
        return None
    return {w["id"] for w in store.workspace_list(username, role)}


def can_access(workspace_id: int, username: str, role: str) -> bool:
    if role == "admin":
        return True
    return int(workspace_id) in (allowed_ids(username, role) or set())


def can_manage(workspace_id: int, username: str, role: str) -> bool:
    if role == "admin":
        return True
    ws = store.workspace_get(workspace_id)
    if not ws:
        return False
    return any(m.get("username") == username and m.get("role") in ("owner", "admin")
               for m in ws.get("members", []))


def overview(username: str, role: str = "viewer") -> dict:
    workspaces = store.workspace_list(username, role)
    allowed = allowed_ids(username, role)
    assignments = store.assignments(limit=200)
    comments = store.comments(limit=200)
    if allowed is not None:
        assignments = [a for a in assignments if a.get("workspace_id") in allowed]
        comments = [c for c in comments if c.get("workspace_id") in allowed]
    return {
        "status": "ok",
        "username": username,
        "role": role,
        "workspaces": workspaces,
        "count": len(workspaces),
        "assignments": assignments,
        "recent_comments": comments,
    }


def create_workspace(name: str, description: str, username: str) -> dict:
    return {"status": "ok", "workspace": store.workspace_create(name, description, username)}


def add_member(workspace_id: int, username: str, role: str = "analyst") -> dict:
    return {"status": "ok", "member": store.workspace_add_member(workspace_id, username, role)}


def add_comment(workspace_id: int | None, author: str, body: str, *,
                case_id: Any = 0, artifact_id: int | None = None,
                entity_id: int | None = None) -> dict:
    return {"status": "ok", "comment": store.comment_add(
        workspace_id, author, body, case_id=case_id,
        artifact_id=artifact_id, entity_id=entity_id)}


def list_comments(workspace_id: int | None = None, case_id: Any = None) -> dict:
    rows = store.comments(workspace_id, case_id)
    return {"status": "ok", "count": len(rows), "comments": rows}


def resolve_comment(comment_id: int, resolved: bool = True) -> dict:
    return {"status": "ok", "comment": store.comment_resolve(comment_id, resolved)}


def add_assignment(workspace_id: int | None, title: str, created_by: str, *,
                   case_id: Any = 0, detail: str = "", assignee: str = "",
                   due_at: str | None = None) -> dict:
    return {"status": "ok", "assignment": store.assignment_add(
        workspace_id, title, created_by, case_id=case_id, detail=detail,
        assignee=assignee, due_at=due_at)}


def list_assignments(workspace_id: int | None = None, case_id: Any = None,
                     status: str | None = None) -> dict:
    rows = store.assignments(workspace_id, case_id, status)
    return {"status": "ok", "count": len(rows), "assignments": rows}


def update_assignment(assignment_id: int, **fields: Any) -> dict:
    return {"status": "ok", "assignment": store.assignment_update(assignment_id, **fields)}
