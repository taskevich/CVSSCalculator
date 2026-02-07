from utils import round_up


class CVSS2:
    COEFFICIENTS = {
        "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
        "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
        "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
        "C": {"N": 0.0, "P": 0.275, "C": 0.660},
        "I": {"N": 0.0, "P": 0.275, "C": 0.660},
        "A": {"N": 0.0, "P": 0.275, "C": 0.660},
    }

    REQUIRED_METRICS = {"AV", "AC", "Au", "C", "I", "A"}

    def __init__(self):
        self.params: dict[str, float] = {}

    def calc(self, cvss: str) -> float | None:
        """
        Расчет CVSS v2 base score.
        Возвращает None, если вектор невалиден.
        """
        try:
            self.params.clear()
            self._fill_coefficients(cvss.split("/"))
            if not self.REQUIRED_METRICS.issubset(self.params):
                return None
            return self._calc_base_metrics()
        except (ValueError, KeyError):
            return None

    def _calc_base_metrics(self) -> float:
        c, i, a = self.params["C"], self.params["I"], self.params["A"]
        av, ac, au = self.params["AV"], self.params["AC"], self.params["Au"]

        impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
        exploitability = 20 * av * ac * au
        factor = 1.176 if impact > 0 else 0

        score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * factor
        return round_up(score)

    def _fill_coefficients(self, parts: list[str]) -> None:
        for part in parts:
            if not part:
                continue

            metric, value = part.split(":", 1)
            self.params[metric] = self.COEFFICIENTS[metric][value]


if __name__ == "__main__":
    calculator = CVSS2()

    vectors = [
        "AV:N/AC:L/Au:N/C:N/I:N/A:C",
        "AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:N",
    ]

    for cvss in vectors:
        score = calculator.calc(cvss)
        if score is None:
            print(cvss, "isn't cvss2!")
        else:
            print(cvss, "score", score)
