from cvss2 import CVSS2
from cvss3 import CVSS3
from cvss_calculator.models.cvss import CVSSModel


class CVSSCalculator:

    @staticmethod
    def calc(cvss: str) -> CVSSModel | None:
        """
        Попытка расчета cvss оценки
        по вектору.

        Пытается по двум разным реализациям посчитать
        оценку.

        Отдает None, если не удалось ничего посчитать.
        """
        calculator = CVSS2()
        model = calculator.calc(cvss)

        if not model:
            calculator = CVSS3()
            model = calculator.calc(cvss)

        return model


if __name__ == "__main__":

    vectors = [
        "AV:N/AC:L/Au:N/C:N/I:N/A:C",
        "AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:N",
    ]

    for cvss in vectors:
        score = CVSSCalculator.calc(cvss)
        if score is None:
            print(cvss, "isn't cvss2!")
        else:
            print(cvss, "score", score)
