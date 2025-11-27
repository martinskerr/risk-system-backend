import pytest
import requests
from datetime import datetime
import json

BASE_URL = "http://127.0.0.1:8000"

def obtener_token_analista() -> str:
    resp = requests.post(
        f"{BASE_URL}/auth/login",
        json={"email": "Emiliano@Emiliano.com", "password": "Emiliano123"},
    )
    assert resp.status_code == 200, f"Error login analista: {resp.status_code} - {resp.text}"
    data = resp.json()
    token = data.get("access_token") or data.get("token")
    assert token, f"No se encontró token en respuesta de login: {data}"
    return token

@pytest.mark.integration
def test_flujo_completo_riesgo_incidente_auditoria():
    """
    Flujo end-to-end:
    1. Crear riesgo
    2. Registrar incidente vinculado
    3. Editar riesgo
    4. Verificar auditoría de CREAR/ACTUALIZAR riesgo y CREAR incidente
    """
    token = obtener_token_analista()
    headers = {"Authorization": f"Bearer {token}"}

    # PASO 1: Crear riesgo
    print("\n=== PASO 1: Creando riesgo ===")
    datos_riesgo = {
        "titulo": "Falla en sistema de respaldo",
        "descripcion": "Sistema de respaldo presenta fallos intermitentes",
        "categoria": "Tecnológico",
        "area_proceso": "TI",
        "probabilidad": 4,      # escala 1-5
        "impacto": 5,           # escala 1-5
        "estado": "Identificado",
        "responsable_id": 1,    # ajusta a un UsuarioID existente
    }
    resp = requests.post(f"{BASE_URL}/riesgos", json=datos_riesgo, headers=headers)
    assert resp.status_code in (200, 201), f"Error al crear riesgo: {resp.status_code} - {resp.text}"
    data_riesgo = resp.json()
    riesgo_id = data_riesgo.get("riesgo_id") or data_riesgo.get("id")
    assert riesgo_id, f"No se encontró ID del riesgo en la respuesta: {data_riesgo}"
    print(f"✓ Riesgo creado con ID: {riesgo_id}")

    # PASO 2: Crear incidente vinculado al riesgo
    print("\n=== PASO 2: Registrando incidente ===")
    datos_incidente = {
        "riesgo_id": riesgo_id,
        "descripcion": "Sistema de respaldo no funcionó durante 2 horas",
        "fecha_ocurrencia": datetime.now().isoformat(),
        "estado": "Ocurrido",
    }
    resp = requests.post(f"{BASE_URL}/incidentes", json=datos_incidente, headers=headers)
    assert resp.status_code in (200, 201), f"Error al crear incidente: {resp.status_code} - {resp.text}"
    data_inc = resp.json()
    incidente_id = data_inc.get("incidente_id") or data_inc.get("id")
    assert incidente_id, f"No se encontró ID de incidente en la respuesta: {data_inc}"
    print(f"✓ Incidente registrado con ID: {incidente_id}")

    # Verificar vinculación
    resp = requests.get(f"{BASE_URL}/incidentes/{incidente_id}", headers=headers)
    assert resp.status_code == 200, f"Error al obtener incidente: {resp.status_code} - {resp.text}"
    assert resp.json().get("riesgo_id") == riesgo_id, "Incidente debe estar vinculado al riesgo"

    # PASO 3: Actualizar riesgo
    print("\n=== PASO 3: Actualizando riesgo ===")
    datos_actualizados = {
        "titulo": "Falla en sistema de respaldo",
        "descripcion": "Sistema de respaldo presenta fallos intermitentes",
        "categoria": "Tecnológico",
        "area_proceso": "TI",
        "probabilidad": 5,      # cambio 4 -> 5
        "impacto": 5,
        "estado": "Crítico",    # cambio estado
        "responsable_id": 1,
    }
    resp = requests.put(f"{BASE_URL}/riesgos/{riesgo_id}", json=datos_actualizados, headers=headers)
    assert resp.status_code in (200, 204), f"Error al actualizar riesgo: {resp.status_code} - {resp.text}"
    print("✓ Riesgo actualizado correctamente")

    # PASO 4: Verificar auditoría
    print("\n=== PASO 4: Verificando auditoría ===")
    # Ajusta la ruta/params a tu endpoint real de auditoría
    resp = requests.get(
        f"{BASE_URL}/auditoria?entidad=Riesgo&entidad_id={riesgo_id}",
        headers=headers,
    )
    assert resp.status_code == 200, f"Error al obtener auditoría de riesgo: {resp.status_code} - {resp.text}"
    registros_riesgo = resp.json()
    assert len(registros_riesgo) >= 2, "Debe haber al menos CREAR y ACTUALIZAR para el riesgo"

    crear = [r for r in registros_riesgo if r.get("accion") == "CREAR"]
    actualizar = [r for r in registros_riesgo if r.get("accion") == "ACTUALIZAR"]
    assert crear, "Debe existir registro de CREAR riesgo"
    assert actualizar, "Debe existir registro de ACTUALIZAR riesgo"

    ultimo = actualizar[-1]
    datos_ant = json.loads(ultimo.get("datos_anteriores") or "{}")
    datos_nue = json.loads(ultimo.get("datos_nuevos") or "{}")
    assert datos_ant.get("probabilidad") == 4
    assert datos_nue.get("probabilidad") == 5
    assert datos_ant.get("estado") == "Identificado"
    assert datos_nue.get("estado") == "Crítico"
    print("✓ Auditoría de ACTUALIZAR riesgo verificada")

    # Auditoría de incidente
    resp = requests.get(
        f"{BASE_URL}/auditoria?entidad=Incidente&entidad_id={incidente_id}",
        headers=headers,
    )
    assert resp.status_code == 200, f"Error al obtener auditoría de incidente: {resp.status_code} - {resp.text}"
    registros_inc = resp.json()
    assert registros_inc, "Debe haber al menos un registro de CREAR incidente"
    print("✓ Auditoría de incidente verificada")

    print("\n=== ✓ FLUJO COMPLETO EXITOSO ===")
