from enum import StrEnum


class CVSSLevelsEnum(StrEnum):
    Low = "Низкий"
    Medium = "Средний"
    High = "Высокий"
    Critical = "Критический"

    @classmethod
    def get_level(cls, score: float):
        level = CVSSLevelsEnum.Low
        if score <= 3.9:
            level = CVSSLevelsEnum.Low
        elif 4.0 <= score <= 6.9:
            level = CVSSLevelsEnum.Medium
        elif 7.0 <= score <= 8.9:
            level = CVSSLevelsEnum.High
        elif 9.0 <= score <= 10.0:
            level = CVSSLevelsEnum.Critical
        return level

    @classmethod
    def stringify(cls, score: float):
        level = cls.get_level(score)
        return f"{level} ({score})"
