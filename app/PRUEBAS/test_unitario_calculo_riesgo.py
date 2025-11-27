# test_unitario_calculo_riesgo.py
import pytest

def calcular_nivel_riesgo(probabilidad: int, impacto: int) -> int:

    if not (0 <= probabilidad <= 100) or not (0 <= impacto <= 100):
        raise ValueError("Probabilidad e Impacto deben estar entre 0 y 100")
    return probabilidad * impacto

@pytest.mark.unit
@pytest.mark.parametrize(
    "probabilidad,impacto,nivel_esperado",
    [
        (50, 50, 2500),
        (75, 80, 6000),
        (30, 40, 1200),
        (0, 0, 0),
        (0, 100, 0),
        (100, 0, 0),
        (100, 100, 10000),
        (99, 99, 9801),
        (1, 100, 100),
        (100, 1, 100),
    ],
)
def test_calculo_nivel_riesgo_valores_validos(probabilidad, impacto, nivel_esperado):
    resultado = calcular_nivel_riesgo(probabilidad, impacto)
    assert resultado == nivel_esperado

@pytest.mark.unit
@pytest.mark.parametrize(
    "probabilidad,impacto",
    [
        (-1, 50),
        (50, -1),
        (101, 50),
        (50, 101),
        (-10, -10),
        (150, 150),
    ],
)
def test_calculo_nivel_riesgo_valores_invalidos(probabilidad, impacto):
    with pytest.raises(ValueError):
        calcular_nivel_riesgo(probabilidad, impacto)

@pytest.mark.unit
def test_calculo_nivel_riesgo_clasificacion():
    nivel_bajo = calcular_nivel_riesgo(25, 25)
    assert nivel_bajo < 2500

    nivel_medio = calcular_nivel_riesgo(50, 50)
    assert 2500 <= nivel_medio <= 5000

    nivel_alto = calcular_nivel_riesgo(80, 80)
    assert nivel_alto > 5000
