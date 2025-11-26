from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from security import verificar_password, crear_token, decodificar_token
import pyodbc
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import logging

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
# ==================== CONFIGURACIONES ====================
SECRET_KEY = "SUPER_SECRETO_RIESGOS_123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configuración BD
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

# CORS
origins = [
    "http://localhost:4200",
    "http://127.0.0.1:4200",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== MODELOS PYDANTIC ====================

class LoginRequest(BaseModel):
    email: str
    password: str

class RiesgoCreate(BaseModel):
    titulo: str
    descripcion: str
    categoria: str
    area_proceso: str
    probabilidad: int
    impacto: int
    responsable_id: int
    estado: Optional[str] = "Identificado"

class RiesgoUpdate(BaseModel):
    titulo: str
    descripcion: str
    categoria: str
    area_proceso: str
    probabilidad: int
    impacto: int
    estado: str
    responsable_id: int

# ==================== AUTH ENDPOINTS ====================

@app.post("/auth/login")
def login(data: LoginRequest):
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()

        cursor.execute("EXEC sp_Usuario_LoginData ?", data.email)
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")

        if row.Activo == 0:
            raise HTTPException(status_code=403, detail="Usuario deshabilitado")

        if not verificar_password(data.password, row.HashPassword):
            raise HTTPException(status_code=401, detail="Contraseña incorrecta")

        payload = {
            "sub": str(row.UsuarioID),
            "rol": row.RolNombre,
        }

        token = crear_token(payload)

        return {
            "access_token": token,
            "token_type": "bearer",
            "usuario": {
                "id": row.UsuarioID,
                "nombre": row.Nombre,
                "email": row.Email,
                "rol": row.RolNombre
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/auth/me")
def auth_me(token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")

    usuario_id = int(payload["sub"])

    conn = pyodbc.connect(CONN_STR)
    cursor = conn.cursor()

    cursor.execute("EXEC sp_Usuario_GetById ?", usuario_id)
    row = cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return {
        "id": row.UsuarioID,
        "nombre": row.Nombre,
        "email": row.Email,
        "rol": row.RolNombre,
        "activo": row.Activo
    }

# ==================== RIESGOS ENDPOINTS ====================

@app.get("/riesgos")
def get_riesgos(token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                RiesgoID,
                Titulo,
                Descripcion,
                Categoria,
                AreaProceso,
                Probabilidad,
                Impacto,
                NivelRiesgo,
                Estado,
                FechaAlta,
                ResponsableID
            FROM Riesgos
            ORDER BY NivelRiesgo DESC
        """)

        rows = cursor.fetchall()
        result = []

        for r in rows:
            result.append({
                "riesgo_id": r[0],
                "titulo": r[1],
                "descripcion": r[2],
                "categoria": r[3],
                "area_proceso": r[4],
                "probabilidad": r[5],
                "impacto": r[6],
                "nivel_riesgo": r[7],
                "estado": r[8],
                "fecha_alta": str(r[9]) if r[9] else None,
                "responsable_id": r[10]
            })

        return result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


@app.post("/riesgos")
def crear_riesgo(riesgo: RiesgoCreate, token: str = Depends(oauth2_scheme)):
    print("=" * 50)
    print("INICIO crear_riesgo")
    print(f"Token recibido: {token[:20]}...")
    
    payload = decodificar_token(token)
    print(f"Payload decodificado: {payload}")
    
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    print(f"Datos del riesgo: {riesgo}")
    
    if not (1 <= riesgo.probabilidad <= 5):
        raise HTTPException(status_code=400, detail="Probabilidad debe estar entre 1 y 5")
    
    if not (1 <= riesgo.impacto <= 5):
        raise HTTPException(status_code=400, detail="Impacto debe estar entre 1 y 5")
    
    nivel_riesgo = riesgo.probabilidad * riesgo.impacto
    print(f"Nivel de riesgo calculado: {nivel_riesgo}")
    
    conn = None
    try:
        print("Intentando conectar a BD...")
        conn = pyodbc.connect(CONN_STR)
        print("Conexión exitosa")
        
        cursor = conn.cursor()
        
        print(f"Verificando responsable ID: {riesgo.responsable_id}")
        cursor.execute("SELECT UsuarioID FROM Usuarios WHERE UsuarioID = ?", riesgo.responsable_id)
        responsable = cursor.fetchone()
        print(f"Responsable encontrado: {responsable}")
        
        if not responsable:
            raise HTTPException(status_code=400, detail=f"Usuario con ID {riesgo.responsable_id} no existe")
        
        print("Ejecutando INSERT...")
        cursor.execute("""
            INSERT INTO Riesgos 
            (Titulo, Descripcion, Categoria, AreaProceso, Probabilidad, Impacto, NivelRiesgo, Estado, ResponsableID, FechaAlta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE())
        """, 
        riesgo.titulo, 
        riesgo.descripcion, 
        riesgo.categoria, 
        riesgo.area_proceso, 
        riesgo.probabilidad, 
        riesgo.impacto, 
        nivel_riesgo,
        riesgo.estado,
        riesgo.responsable_id
        )
        
        print("INSERT ejecutado, haciendo commit...")
        conn.commit()
        print("Commit exitoso")
        
        print("Obteniendo ID...")
        cursor.execute("SELECT @@IDENTITY AS id")
        nuevo_id = cursor.fetchone()[0]
        print(f"Nuevo ID obtenido: {nuevo_id}")
        
        print("=" * 50)
        return {
            "mensaje": "Riesgo creado exitosamente",
            "riesgo_id": int(nuevo_id)
        }
        
    except pyodbc.Error as db_err:
        print(f"ERROR DE BASE DE DATOS: {db_err}")
        print(f"Tipo: {type(db_err)}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error de BD: {str(db_err)}")
    
    except HTTPException:
        raise
    
    except Exception as e:
        print(f"ERROR GENERAL: {e}")
        print(f"Tipo: {type(e)}")
        import traceback
        traceback.print_exc()
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    
    finally:
        if conn:
            print("Cerrando conexión...")
            conn.close()
            print("Conexión cerrada")


@app.put("/riesgos/{riesgo_id}")
def actualizar_riesgo(riesgo_id: int, riesgo: RiesgoUpdate, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    if not (1 <= riesgo.probabilidad <= 5):
        raise HTTPException(status_code=400, detail="Probabilidad debe estar entre 1 y 5")
    
    if not (1 <= riesgo.impacto <= 5):
        raise HTTPException(status_code=400, detail="Impacto debe estar entre 1 y 5")
    
    nivel_riesgo = riesgo.probabilidad * riesgo.impacto
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE Riesgos 
            SET Titulo=?, Descripcion=?, Categoria=?, AreaProceso=?,
                Probabilidad=?, Impacto=?, NivelRiesgo=?, Estado=?, ResponsableID=?
            WHERE RiesgoID=?
        """, 
        riesgo.titulo, 
        riesgo.descripcion, 
        riesgo.categoria, 
        riesgo.area_proceso,
        riesgo.probabilidad, 
        riesgo.impacto, 
        nivel_riesgo, 
        riesgo.estado,
        riesgo.responsable_id,
        riesgo_id
        )
        
        conn.commit()
        
        return {"mensaje": "Riesgo actualizado exitosamente"}
        
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


@app.delete("/riesgos/{riesgo_id}")
def eliminar_riesgo(riesgo_id: int, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        cursor.execute("SELECT RiesgoID FROM Riesgos WHERE RiesgoID=?", riesgo_id)
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Riesgo no encontrado")
        
        cursor.execute("DELETE FROM Riesgos WHERE RiesgoID=?", riesgo_id)
        conn.commit()
        
        return {"mensaje": "Riesgo eliminado exitosamente"}
        
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()

class IncidenteCreate(BaseModel):
    riesgo_id: int
    descripcion: str
    estado: Optional[str] = "En Investigación"

@app.get("/incidentes")
def get_incidentes(token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                i.IncidenteID,
                i.RiesgoID,
                i.Descripcion,
                i.Estado,
                i.FechaIncidente,
                r.Titulo as RiesgoTitulo
            FROM Incidentes i
            LEFT JOIN Riesgos r ON i.RiesgoID = r.RiesgoID
            ORDER BY i.FechaIncidente DESC
        """)

        rows = cursor.fetchall()
        result = []

        for row in rows:
            result.append({
                "incidente_id": row[0],
                "riesgo_id": row[1],
                "descripcion": row[2],
                "estado": row[3],
                "fecha_incidente": str(row[4]) if row[4] else None,
                "riesgo_titulo": row[5]
            })

        return result
    
    except Exception as e:
        print(f"ERROR GET INCIDENTES: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


@app.post("/incidentes")
def crear_incidente(incidente: IncidenteCreate, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        # Verificar que el riesgo existe
        cursor.execute("SELECT RiesgoID FROM Riesgos WHERE RiesgoID = ?", incidente.riesgo_id)
        if not cursor.fetchone():
            raise HTTPException(status_code=400, detail=f"Riesgo con ID {incidente.riesgo_id} no existe")
        
        cursor.execute("""
            INSERT INTO Incidentes 
            (RiesgoID, Descripcion, Estado, FechaIncidente)
            VALUES (?, ?, ?, GETDATE())
        """, 
        incidente.riesgo_id,
        incidente.descripcion,
        incidente.estado
        )
        
        conn.commit()
        
        cursor.execute("SELECT @@IDENTITY AS id")
        nuevo_id = cursor.fetchone()[0]
        
        return {
            "mensaje": "Incidente creado exitosamente",
            "incidente_id": int(nuevo_id)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR POST INCIDENTE: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()



@app.get("/usuarios")
def get_usuarios(token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT UsuarioID, Nombre, Email, Activo
            FROM Usuarios
            WHERE Activo = 1
            ORDER BY Nombre
        """)

        rows = cursor.fetchall()
        result = []

        for r in rows:
            result.append({
                "id": r[0],
                "nombre": r[1],
                "email": r[2],
                "activo": r[3]
            })

        return result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


