# cvs_calculator

Калькулятор базовых CVSS версий(2, 3) по ФСТЭК

## Установка 

Установка из репозитория
```shell
pip install .
```

Установка из pypi
```shell
pip install cvss_calculator
```

## Использование

```python
from cvss_calculator.cvss2 import CVSS2
from cvss_calculator.cvss3 import CVSS3

calculator_2 = CVSS2()
calculator_3 = CVSS3()

vectors = [
    "AV:N/AC:L/Au:N/C:N/I:N/A:C",
    "AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:N",
]

for cvss in vectors:
    score = calculator_2.calc(cvss)
    print(cvss, "score cvss2", score)
    
for cvss in vectors:
    score = calculator_3.calc(cvss)
    print(cvss, "score cvss3", score)
```