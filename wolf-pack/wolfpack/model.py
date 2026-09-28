from dataclasses import dataclass, field


@dataclass
class Sighting:
    algo: str
    file: str
    line: int
    evidence: str
    scout: str
    snippet: str = ""
    lang: str = ""
    params: dict = field(default_factory=dict)
    context: set = field(default_factory=set)
    confidence: float = 0.0
    verdict: str = "pending"
    reason: str = ""


@dataclass
class Library:
    name: str
    ecosystem: str
    manifest: str
    line: int
    version: str = ""
    imports: tuple = ()
    used_in: list = field(default_factory=list)
    implies: tuple = ()
    pq: bool = False
    note: str = ""


@dataclass
class Artifact:
    kind: str
    file: str
    line: int
    algo: str
    params: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)


@dataclass
class Asset:
    ref: str
    algo: str
    variant: str
    params: dict
    sightings: list
    confidence: float
    tier: str = ""
    score: float = 0.0
    why: str = ""
    action: str = ""
    nist: str = ""
    exposure: str = ""
    test_only: bool = False
    new_files: list = field(default_factory=list)
    policy: list = field(default_factory=list)
