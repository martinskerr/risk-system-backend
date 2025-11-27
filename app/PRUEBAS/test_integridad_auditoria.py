import pytest
import requests
import pyodbc
import json

BASE_URL = "http://127.0.0.1:8000"

SERVER   = "risksystem.czcv02nmtikw.us-east-1.rds.amazonaws.com"
DATABASE = "ryskSystem"
USERNAME = "admin"
PASSWORD = "admin12345"

CONN_STR = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    f"SERVER={SERVER};"
    f"DATABASE={DATABASE};"
    f"UID={USERNAME};"
    f"PWD={PASSWORD};"
    "Encrypt=yes;"
    "TrustServerCertificate=yes;"
)

def obtener_token_admin() -> str:
    resp = requests.post(
        f"{BASE_URL}/auth/login",
        json={"email": "admin@riesgos.local", "password": "Admin1"},
    )
    assert resp.status_code == 200, f"Error login admin: {resp.status_code} - {resp.text}"
    data = resp.json()
    token = data.get("access_token") or data.get("token")
    assert token, f"No se encontró token en respuesta de login: {data}"
    return token

@pytest.mark.functional
def test_auditoria_registra_creacion_riesgo():
    """Verifica que al crear un riesgo se genere registro de auditoría."""
    token = obtener_token_admin()
    headers = {"Authorization": f"Bearer {token}"}

    datos_riesgo = {
        "titulo": "Riesgo de prueba auditoría",
        "descripcion": "Riesgo para verificar registro de auditoría",
        "categoria": "Operacional",
        "area_proceso": "Operaciones",
        "probabilidad": 3,
        "impacto": 4,
        "estado": "Identificado",
        "responsable_id": 1,
    }
    resp = requests.post(f"{BASE_URL}/riesgos", json=datos_riesgo, headers=headers)
    assert resp.status_code in (200, 201), f"Error al crear riesgo: {resp.status_code} - {resp.text}"
    data_riesgo = resp.json()
    riesgo_id = data_riesgo.get("riesgo_id") or data_riesgo.get("id")
    assert riesgo_id, f"No se encontró ID de riesgo en respuesta: {data_riesgo}"

    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT TOP 1 UsuarioNombre, Accion, Entidad, EntidadID, DatosNuevos
        FROM Auditoria
        WHERE Entidad = 'Riesgo' AND EntidadID = ? AND Accion = 'CREAR'
        ORDER BY FechaHora DESC
        """,
        riesgo_id,
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    assert row is not None, "No se encontró registro de auditoría para creación de riesgo"
    assert row.Accion == "CREAR"
    assert row.Entidad == "Riesgo"
    assert row.EntidadID == riesgo_id
    assert row.DatosNuevos, "DatosNuevos debe contener JSON de los datos creados"

@pytest.mark.security
def test_auditoria_campos_inmutables():
    """
    Verifica que los registros de auditoría no puedan modificarse.
    Si el UPDATE funciona, se considera defecto (pytest.fail).
    """
    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT TOP 1 AuditoriaID FROM Auditoria ORDER BY AuditoriaID DESC")
        row = cursor.fetchone()
        if not row:
            pytest.skip("No hay registros en Auditoria para probar inmutabilidad")

        auditoria_id = row[0]
        try:
            cursor.execute(
                "UPDATE Auditoria SET Accion = 'MODIFICADO_TEST' WHERE AuditoriaID = ?",
                auditoria_id,
            )
            conn.commit()
            pytest.fail("DEFECTO: La tabla Auditoria permite modificaciones (no es inmutable).")
        except pyodbc.Error:
            conn.rollback()
    finally:
        cursor.close()
        conn.close()

@pytest.mark.functional
def test_auditoria_registra_datos_anteriores_en_actualizacion():
    """Verifica que al actualizar se guarden datos anteriores y nuevos en auditoría."""
    token = obtener_token_admin()
    headers = {"Authorization": f"Bearer {token}"}

    # Crear riesgo inicial
    datos_inicial = {
        "titulo": "Riesgo para test actualización",
        "descripcion": "Descripción inicial",
        "categoria": "Financiero",
        "area_proceso": "Finanzas",
        "probabilidad": 2,
        "impacto": 3,
        "estado": "Identificado",
        "responsable_id": 1,
    }
    resp = requests.post(f"{BASE_URL}/riesgos", json=datos_inicial, headers=headers)
    assert resp.status_code in (200, 201), f"Error al crear riesgo: {resp.status_code} - {resp.text}"
    data_riesgo = resp.json()
    riesgo_id = data_riesgo.get("riesgo_id") or data_riesgo.get("id")
    assert riesgo_id, f"No se encontró ID de riesgo en respuesta: {data_riesgo}"

    # Actualizar riesgo
    datos_actualizados = {
        "titulo": "Riesgo para test actualización",
        "descripcion": "Descripción inicial",
        "categoria": "Financiero",
        "area_proceso": "Finanzas",
        "probabilidad": 4,
        "impacto": 5,
        "estado": "Crítico",
        "responsable_id": 1,
    }
    resp = requests.put(f"{BASE_URL}/riesgos/{riesgo_id}", json=datos_actualizados, headers=headers)
    assert resp.status_code in (200, 204), f"Error al actualizar riesgo: {resp.status_code} - {resp.text}"

    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT TOP 1 DatosAnteriores, DatosNuevos
        FROM Auditoria
        WHERE Entidad = 'Riesgo' AND EntidadID = ? AND Accion = 'ACTUALIZAR'
        ORDER BY FechaHora DESC
        """,
        riesgo_id,
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    assert row is not None, "No se encontró registro de auditoría para actualización de riesgo"
    datos_ant = json.loads(row.DatosAnteriores or "{}")
    datos_nue = json.loads(row.DatosNuevos or "{}")

    assert datos_ant.get("probabilidad") == 2
    assert datos_nue.get("probabilidad") == 4
    assert datos_ant.get("estado") == "Identificado"
    assert datos_nue.get("estado") == "Crítico"
