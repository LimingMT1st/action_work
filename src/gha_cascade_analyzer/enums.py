from enum import Enum


class EdgeType(str, Enum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"


class RefType(str, Enum):
    TAG = "tag"
    SHA = "sha"
    BRANCH = "branch"
    UNKNOWN = "unknown"


class ActionType(str, Enum):
    JAVASCRIPT = "javascript"
    DOCKER = "docker"
    COMPOSITE = "composite"
    REUSABLE_WORKFLOW = "reusable_workflow"
    UNKNOWN = "unknown"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    UNKNOWN = "unknown"


class CrawlStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
