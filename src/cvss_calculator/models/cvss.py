import dataclasses

from cvss_calculator.enums.level import CVSSLevelsEnum


@dataclasses.dataclass
class CVSSModel:
    score: float
    level: CVSSLevelsEnum
    compiled_level: str
    version: str
