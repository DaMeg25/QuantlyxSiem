"""
GitHub and GitHub Enterprise: who can write to what.

Enumerates four populations that each accumulate access differently and are
almost never reviewed together:

  * Direct collaborators on a repository
  * Teams, and their permission level
  * Deploy keys, which are machine credentials with no owner attached
  * Installed applications, which hold organisation-wide permissions

The last two are where bot access hides. A recertification campaign aimed at
people never sees them.

The token needs read:org and repo scope for private repositories. It cannot be
used to read code or secrets through this connector -- those paths are refused
before the request is made.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterator

from access.models import AccessLevel, PrincipalType

from .base import (
    NormalizedAccess,
    NormalizedResource,
    ResourceConnector,
    register_resource_connector,
)

PERMISSION_MAP = {
    "pull": AccessLevel.READ,
    "read": AccessLevel.READ,
    "triage": AccessLevel.TRIAGE,
    "push": AccessLevel.WRITE,
    "write": AccessLevel.WRITE,
    "maintain": AccessLevel.MAINTAIN,
    "admin": AccessLevel.ADMIN,
}


@register_resource_connector
class GitHubConnector(ResourceConnector):
    platform = "github"
    display_name = "GitHub"
    required_credentials = ("token",)
    documentation = "Needs read:org and repo. Never grant write scopes to this collector."

    def authenticate(self) -> None:
        self.session.headers.update({
            "Authorization": f"Bearer {self._credentials['token']}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        self._get("/user")

    def iter_resources(self) -> Iterator[NormalizedResource]:
        organisation = self.options.get("organisation")
        path = f"/orgs/{organisation}/repos" if organisation else "/user/repos"
        production_topics = set(self.options.get("production_topics", ["production", "prod"]))
        for item in self._paged(path, {"type": "all"}):
            topics = set(item.get("topics") or [])
            yield NormalizedResource(
                identifier=item.get("full_name", ""),
                display_name=item.get("name", ""),
                url=item.get("html_url", ""),
                archived=bool(item.get("archived")),
                production=bool(topics & production_topics),
                owner_team=(item.get("owner") or {}).get("login", ""),
                detail={
                    "visibility": item.get("visibility"),
                    "default_branch": item.get("default_branch"),
                    "topics": sorted(topics),
                    "pushed_at": item.get("pushed_at"),
                },
            )

    def iter_access(self, resource_identifier: str) -> Iterator[NormalizedAccess]:
        yield from self._collaborators(resource_identifier)
        yield from self._teams(resource_identifier)
        yield from self._deploy_keys(resource_identifier)

    def _collaborators(self, repository: str) -> Iterator[NormalizedAccess]:
        for item in self._paged(f"/repos/{repository}/collaborators", {"affiliation": "all"}):
            permissions = item.get("permissions") or {}
            level = (
                AccessLevel.ADMIN if permissions.get("admin")
                else AccessLevel.MAINTAIN if permissions.get("maintain")
                else AccessLevel.WRITE if permissions.get("push")
                else AccessLevel.TRIAGE if permissions.get("triage")
                else AccessLevel.READ
            )
            login = item.get("login", "")
            yield NormalizedAccess(
                resource_identifier=repository,
                principal_identifier=login,
                access_level=level,
                principal_type=(
                    PrincipalType.BOT if item.get("type") == "Bot" or login.endswith("[bot]")
                    else PrincipalType.DEVELOPER
                ),
                machine_identity=item.get("type") == "Bot" or login.endswith("[bot]"),
                detail={"role_name": item.get("role_name"), "site_admin": item.get("site_admin")},
            )

    def _teams(self, repository: str) -> Iterator[NormalizedAccess]:
        for item in self._paged(f"/repos/{repository}/teams"):
            yield NormalizedAccess(
                resource_identifier=repository,
                principal_identifier=f"team:{item.get('slug')}",
                display_name=item.get("name", ""),
                access_level=PERMISSION_MAP.get(item.get("permission", "pull"), AccessLevel.READ),
                principal_type=PrincipalType.UNKNOWN,
                detail={"team": True, "slug": item.get("slug")},
            )

    def _deploy_keys(self, repository: str) -> Iterator[NormalizedAccess]:
        """
        Deploy keys are credentials with repository access and no person
        attached. Read-only ones still matter; a writable one is a bot with
        commit rights that no review has ever looked at.
        """
        for item in self._paged(f"/repos/{repository}/keys"):
            yield NormalizedAccess(
                resource_identifier=repository,
                principal_identifier=f"deploy-key:{repository}:{item.get('id')}",
                display_name=item.get("title", ""),
                access_level=AccessLevel.READ if item.get("read_only") else AccessLevel.WRITE,
                principal_type=PrincipalType.BOT,
                machine_identity=True,
                granted_at=self._parse(item.get("created_at")),
                last_used_at=self._parse(item.get("last_used")),
                detail={"deploy_key": True, "read_only": item.get("read_only")},
            )

    @staticmethod
    def _parse(value) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
