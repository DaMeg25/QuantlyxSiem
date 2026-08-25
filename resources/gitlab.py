"""
GitLab: project members, group inheritance, deploy tokens, and access tokens.

Inherited group membership is the interesting part. A developer with no direct
membership on a project can still hold write access through a group two levels
up, which is invisible if you only enumerate project members -- so this reads
the inherited view and records where the access came from.
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

# GitLab access levels are numeric.
LEVEL_MAP = {
    10: AccessLevel.READ,       # guest
    15: AccessLevel.READ,       # reporter-lite
    20: AccessLevel.READ,       # reporter
    30: AccessLevel.WRITE,      # developer
    40: AccessLevel.MAINTAIN,   # maintainer
    50: AccessLevel.ADMIN,      # owner
}


@register_resource_connector
class GitLabConnector(ResourceConnector):
    platform = "gitlab"
    display_name = "GitLab"
    required_credentials = ("token",)
    documentation = "Needs a read_api token. read_repository is not required and should not be granted."

    def authenticate(self) -> None:
        self.session.headers["PRIVATE-TOKEN"] = self._credentials["token"]
        self._get("/api/v4/user")

    def iter_resources(self) -> Iterator[NormalizedResource]:
        group = self.options.get("group")
        path = f"/api/v4/groups/{group}/projects" if group else "/api/v4/projects"
        params = {"membership": "true", "include_subgroups": "true", "archived": "false"}
        production_topics = set(self.options.get("production_topics", ["production", "prod"]))
        for item in self._paged(path, params):
            topics = set(item.get("topics") or item.get("tag_list") or [])
            yield NormalizedResource(
                identifier=item.get("path_with_namespace", ""),
                display_name=item.get("name", ""),
                url=item.get("web_url", ""),
                archived=bool(item.get("archived")),
                production=bool(topics & production_topics),
                owner_team=(item.get("namespace") or {}).get("full_path", ""),
                detail={"visibility": item.get("visibility"), "id": item.get("id"), "topics": sorted(topics)},
            )

    def iter_access(self, resource_identifier: str) -> Iterator[NormalizedAccess]:
        encoded = resource_identifier.replace("/", "%2F")
        # The "/all" view includes membership inherited from parent groups, which
        # is where most unreviewed write access actually comes from.
        for item in self._paged(f"/api/v4/projects/{encoded}/members/all"):
            level = LEVEL_MAP.get(item.get("access_level", 10), AccessLevel.READ)
            username = item.get("username", "")
            bot = bool(item.get("bot")) or username.startswith("project_") or username.startswith("group_")
            yield NormalizedAccess(
                resource_identifier=resource_identifier,
                principal_identifier=username,
                display_name=item.get("name", ""),
                email=item.get("email", "") or "",
                access_level=level,
                principal_type=PrincipalType.BOT if bot else PrincipalType.DEVELOPER,
                machine_identity=bot,
                granted_at=self._parse(item.get("created_at")),
                expires_at=self._parse(item.get("expires_at")),
                detail={
                    "raw_access_level": item.get("access_level"),
                    "inherited": bool(item.get("group_saml_identity") or item.get("membership_state") == "active" and item.get("source_id")),
                    "source": item.get("source_id"),
                },
            )
        yield from self._deploy_tokens(encoded, resource_identifier)

    def _deploy_tokens(self, encoded: str, resource_identifier: str) -> Iterator[NormalizedAccess]:
        try:
            tokens = list(self._paged(f"/api/v4/projects/{encoded}/deploy_tokens"))
        except Exception:
            return
        for item in tokens:
            scopes = set(item.get("scopes") or [])
            yield NormalizedAccess(
                resource_identifier=resource_identifier,
                principal_identifier=f"deploy-token:{resource_identifier}:{item.get('id')}",
                display_name=item.get("name", ""),
                access_level=AccessLevel.WRITE if scopes & {"write_repository", "write_registry"} else AccessLevel.READ,
                principal_type=PrincipalType.BOT,
                machine_identity=True,
                expires_at=self._parse(item.get("expires_at")),
                detail={"deploy_token": True, "scopes": sorted(scopes), "revoked": item.get("revoked")},
            )

    @staticmethod
    def _parse(value) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
