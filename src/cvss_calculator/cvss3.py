from utils import round_up


class CVSS3:
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC = {"L": 0.77, "H": 0.44}
    UI = {"N": 0.85, "R": 0.62}

    CIA = {
        "H": 0.56,
        "L": 0.22,
        "N": 0.0,
    }

    PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}

    REQUIRED = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

    def __init__(self):
        self.params: dict[str, float | bool | str] = {}

    def calc(self, cvss: str) -> float | None:
        """
        Расчет CVSS v3 base score.
        Возвращает None, если вектор невалиден.
        """
        try:
            self.params.clear()
            self._parse_vector(cvss.split("/"))
            if not self.REQUIRED.issubset(self.params):
                return None
            return self._calc_base_metrics()
        except (KeyError, ValueError):
            return None

    def _calc_base_metrics(self) -> float:
        av = self.params["AV"]
        ac = self.params["AC"]
        pr = self.params["PR"]
        ui = self.params["UI"]

        c = self.params["C"]
        i = self.params["I"]
        a = self.params["A"]
        scope_changed = self.params["S"]

        exploitability = 8.22 * av * ac * pr * ui
        iscb = 1 - ((1 - c) * (1 - i) * (1 - a))

        if iscb <= 0:
            return 0.0

        if scope_changed:
            impact = 7.52 * (iscb - 0.029) - 3.25 * ((iscb - 0.02) ** 15)
            score = 1.08 * (impact + exploitability)
        else:
            impact = 6.42 * iscb
            score = impact + exploitability

        return round_up(min(score, 10.0))

    def _parse_vector(self, parts: list[str]) -> None:
        raw_pr = None

        for part in parts:
            if not part:
                continue

            metric, value = part.split(":", 1)

            match metric:
                case "AV":
                    self.params["AV"] = self.AV[value]
                case "AC":
                    self.params["AC"] = self.AC[value]
                case "UI":
                    self.params["UI"] = self.UI[value]
                case "PR":
                    raw_pr = value
                case "S":
                    self.params["S"] = value == "C"
                case "C" | "I" | "A":
                    self.params[metric] = self.CIA[value]

        if raw_pr is None or "S" not in self.params:
            raise KeyError("PR or S missing")

        pr_table = self.PR_C if self.params["S"] else self.PR_U
        self.params["PR"] = pr_table[raw_pr]


if __name__ == "__main__":
    calculator = CVSS3()

    vectors = [
        "AV:N/AC:L/Au:N/C:N/I:N/A:C",
        "AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:N",
    ]

    for cvss in vectors:
        score = calculator.calc(cvss)
        if score is None:
            print(cvss, "isn't cvss3!")
        else:
            print(cvss, "score", score)
