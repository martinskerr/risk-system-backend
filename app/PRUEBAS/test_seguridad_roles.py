import pytest
import requests

BASE_URL = "http://127.0.0.1:8000"

# Credenciales reales
CREDENCIALES = {
    "admin":    {"email": "admin@riesgos.local",   "password": "Admin1"},
    "analista": {"email": "Emiliano@Emiliano.com", "password": "Emiliano123"},
    "usuario":  {"email": "Prueba@Usuario.com",    "password": "Prueba123"},
}

def obtener_token(rol: str) -> str:
    """Obtiene token JWT para el rol especificado."""
    resp = requests.post(
        f"{BASE_URL}/auth/login",
        json=CREDENCIALES[rol]
    )
    assert resp.status_code == 200, f"Error al autenticar {rol}: {resp.status_code} - {resp.text}"
    data = resp.json()
    # Ajusta si tu API usa otro nombre de campo
    token = data.get("access_token") or data.get("token")
    assert token, f"No se encontró token en respuesta de login para {rol}: {data}"
    return token

@pytest.mark.security
@pytest.mark.parametrize(
    "rol,endpoint,metodo,debe_permitir",
    [
        # Admin debe tener acceso a todo
        ("admin",    "/usuarios", "GET",  True),
        ("admin",    "/usuarios", "POST", True),
        ("admin",    "/riesgos",  "GET",  True),

        # Analista: puede ver usuarios, no crearlos; sí puede crear riesgos
        ("analista", "/usuarios", "GET",  True),
        ("analista", "/usuarios", "POST", False),
        ("analista", "/riesgos",  "GET",  True),
        ("analista", "/riesgos",  "POST", True),

        # Usuario: solo consulta riesgos, nada de usuarios ni creación
        ("usuario",  "/usuarios", "GET",  False),
        ("usuario",  "/usuarios", "POST", False),
        ("usuario",  "/riesgos",  "GET",  True),
        ("usuario",  "/riesgos",  "POST", False),
    ],
)
def test_control_acceso_por_rol(rol, endpoint, metodo, debe_permitir):
    """
    Verifica que cada rol tenga los permisos correctos:
    - Admin: CRUD usuarios y riesgos
    - Analista: ver usuarios, CRUD riesgos
    - Usuario: solo ver riesgos
    """
    token = obtener_token(rol)
    headers = {"Authorization": f"Bearer {token}"}

    if metodo == "GET":
        resp = requests.get(f"{BASE_URL}{endpoint}", headers=headers)

    elif metodo == "POST":
        # Datos según endpoint
        if endpoint == "/usuarios":
            # Modelo: UsuarioCreate (nombre, email, password, rol_id, activo)
            datos = {
                "nombre": f"Usuario Test {rol}",
                "email": f"test_{rol}_{abs(hash(rol))}@test.com",
                "password": "TestPassword123!",
                "rol_id": 3,      # ajusta si tu rol "USUARIO" tiene otro ID
                "activo": True,
            }
        elif endpoint == "/riesgos":
            datos = {
                "titulo": "Riesgo de prueba",
                "descripcion": "Riesgo creado desde pruebas automatizadas",
                "categoria": "Operacional",
                "area_proceso": "Operaciones",
                "probabilidad": 3,    # escala 1-5
                "impacto": 3,         # escala 1-5
                "estado": "Identificado",
                "responsable_id": 1,  # ajusta a un UsuarioID existente
            }
        else:
            pytest.fail(f"Endpoint desconocido en test: {endpoint}")

        resp = requests.post(f"{BASE_URL}{endpoint}", json=datos, headers=headers)

    else:
        pytest.fail(f"Método HTTP no soportado en test: {metodo}")

    if debe_permitir:
        assert resp.status_code in (200, 201), (
            f"{rol} debería tener acceso a {metodo} {endpoint}, "
            f"pero obtuvo {resp.status_code}: {resp.text}"
        )
    else:
        assert resp.status_code in (401, 403), (
            f"{rol} NO debería tener acceso a {metodo} {endpoint} "
            f"(esperado 401/403, obtuvo {resp.status_code}: {resp.text})"
        )

@pytest.mark.security
def test_token_expiracion():
    """Smoke: el token actual funciona para llamar un endpoint protegido."""
    token = obtener_token("analista")
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/riesgos", headers=headers)
    assert resp.status_code == 200
