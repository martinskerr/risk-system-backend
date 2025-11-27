from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from security import verificar_password, crear_token, decodificar_token, hash_password, verify_password
import pyodbc
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import logging
import json
from datetime import datetime
import bcrypt


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

class UsuarioCreate(BaseModel):
    nombre: str
    email: str
    password: str
    rol_id: int = 3  # Por defecto Usuario (RolID = 3)
    activo: bool = True

class UsuarioUpdate(BaseModel):
    nombre: str
    email: str
    rol_id: int
    activo: bool



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

        # ← AGREGAR 'nombre' y 'email' al payload
        payload = {
            "sub": str(row.UsuarioID),
            "nombre": row.Nombre,  # ← Agregar
            "email": row.Email,    # ← Agregar
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
        
        # ← AGREGAR AUDITORÍA
        registrar_auditoria(
            usuario_id=int(payload.get('sub')),
            usuario_nombre=payload.get('nombre'),
            accion="CREAR",
            entidad="Riesgo",
            entidad_id=nuevo_id,
            descripcion=f"Creó el riesgo: {riesgo.titulo}",
            datos_nuevos={
                "titulo": riesgo.titulo,
                "categoria": riesgo.categoria,
                "nivel_riesgo": nivel_riesgo
            }
        )
        
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
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        # ← PRIMERO: OBTENER DATOS ANTERIORES (ANTES del UPDATE)
        cursor.execute("""
            SELECT Titulo, Categoria, NivelRiesgo, Estado, Probabilidad, Impacto
            FROM Riesgos 
            WHERE RiesgoID = ?
        """, riesgo_id)
        
        datos_ant = cursor.fetchone()
        if not datos_ant:
            raise HTTPException(status_code=404, detail="Riesgo no encontrado")
        
        datos_anteriores = {
            "titulo": datos_ant[0],
            "categoria": datos_ant[1],
            "nivel_riesgo": datos_ant[2],
            "estado": datos_ant[3],
            "probabilidad": datos_ant[4],
            "impacto": datos_ant[5]
        }
        
        # Calcular nuevo nivel de riesgo
        nivel_riesgo = riesgo.probabilidad * riesgo.impacto
        
        # AHORA SÍ: Actualizar el riesgo
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
        
        # ← AUDITORÍA con datos ANTERIORES y NUEVOS
        registrar_auditoria(
            usuario_id=int(payload.get('sub')),
            usuario_nombre=payload.get('nombre', 'Usuario'),
            accion="ACTUALIZAR",
            entidad="Riesgo",
            entidad_id=riesgo_id,
            descripcion=f"Actualizó el riesgo: {riesgo.titulo}",
            datos_anteriores=datos_anteriores,
            datos_nuevos={
                "titulo": riesgo.titulo,
                "categoria": riesgo.categoria,
                "nivel_riesgo": nivel_riesgo,
                "estado": riesgo.estado,
                "probabilidad": riesgo.probabilidad,
                "impacto": riesgo.impacto
            }
        )
        
        return {"mensaje": "Riesgo actualizado exitosamente"}
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR PUT RIESGO: {e}")
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
        
        # ← OBTENER DATOS para auditoría
        cursor.execute("SELECT Titulo FROM Riesgos WHERE RiesgoID=?", riesgo_id)
        riesgo = cursor.fetchone()
        if not riesgo:
            raise HTTPException(status_code=404, detail="Riesgo no encontrado")
        
        titulo = riesgo[0]
        
        cursor.execute("DELETE FROM Riesgos WHERE RiesgoID=?", riesgo_id)
        conn.commit()
        
        # ← AGREGAR AUDITORÍA
        registrar_auditoria(
            usuario_id=int(payload.get('sub')),
            usuario_nombre=payload.get('nombre'),
            accion="ELIMINAR",
            entidad="Riesgo",
            entidad_id=riesgo_id,
            descripcion=f"Eliminó el riesgo: {titulo}",
            datos_anteriores={"titulo": titulo}
        )
        
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



# ========== ENDPOINTS DE USUARIOS ==========

# ========== MODELOS PYDANTIC PARA USUARIOS ==========
class UsuarioCreate(BaseModel):
    nombre: str
    email: str
    password: str
    rol_id: int = 3  # Por defecto Usuario (RolID = 3)
    activo: bool = True

class UsuarioUpdate(BaseModel):
    nombre: str
    email: str
    rol_id: int
    activo: bool



# ========== ENDPOINTS USUARIOS ==========

@app.get("/usuarios")
def get_usuarios(token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        # JOIN con UsuarioRoles para obtener el rol
        cursor.execute("""
            SELECT 
                u.UsuarioID, 
                u.Nombre, 
                u.Email, 
                u.Activo, 
                u.FechaCreacion,
                ur.RolID
            FROM Usuarios u
            LEFT JOIN UsuarioRoles ur ON u.UsuarioID = ur.UsuarioID
            ORDER BY u.FechaCreacion DESC
        """)

        rows = cursor.fetchall()
        result = []

        for r in rows:
            # Mapear RolID a nombre
            rol_nombre = "Usuario"
            rol_id = 3
            if r[5]:
                rol_id = r[5]
                if r[5] == 1:
                    rol_nombre = "ADMIN"
                elif r[5] == 2:
                    rol_nombre = "Analista"
            
            result.append({
                "id": r[0],
                "nombre": r[1],
                "email": r[2],
                "rol": rol_nombre,
                "rol_id": rol_id,
                "activo": bool(r[3]),
                "fecha_registro": str(r[4]) if r[4] else None
            })

        return result
    
    except Exception as e:
        print(f"ERROR GET USUARIOS: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


# ========== ENDPOINT CREAR USUARIO ==========

def hash_password_func(password: str) -> str:
    """Hashea una contraseña usando bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verificar_password(password: str, hash_password: str) -> bool:
    """Verifica si una contraseña coincide con su hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hash_password.encode('utf-8'))


@app.post("/usuarios")
def crear_usuario(usuario: UsuarioCreate, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    # Solo ADMIN puede crear usuarios
    if payload.get('rol') != 'ADMIN':
        raise HTTPException(status_code=403, detail="No tienes permisos para crear usuarios")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        # Verificar si el email ya existe
        cursor.execute("SELECT UsuarioID FROM Usuarios WHERE Email = ?", usuario.email)
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="El email ya está registrado")
        
        # Hash de la contraseña
        hash_password = hash_password_func(usuario.password)
        
        # Insertar usuario
        cursor.execute("""
            INSERT INTO Usuarios (Nombre, Email, HashPassword, Activo, FechaCreacion)
            VALUES (?, ?, ?, ?, GETDATE())
        """,
        usuario.nombre,
        usuario.email,
        hash_password,
        usuario.activo
        )
        
        conn.commit()
        
        # Obtener ID del nuevo usuario
        cursor.execute("SELECT @@IDENTITY AS id")
        nuevo_id = int(cursor.fetchone()[0])
        
        # Asignar rol
        cursor.execute("""
            INSERT INTO UsuarioRoles (UsuarioID, RolID)
            VALUES (?, ?)
        """, nuevo_id, usuario.rol_id)
        
        conn.commit()
        
        # Auditoría
        registrar_auditoria(
            usuario_id=int(payload.get('sub')),
            usuario_nombre=payload.get('nombre', 'Admin'),
            accion="CREAR",
            entidad="Usuario",
            entidad_id=nuevo_id,
            descripcion=f"Creó el usuario: {usuario.nombre}",
            datos_nuevos={
                "nombre": usuario.nombre,
                "email": usuario.email,
                "rol_id": usuario.rol_id,
                "activo": usuario.activo
            }
        )
        
        return {
            "mensaje": "Usuario creado exitosamente",
            "usuario_id": nuevo_id
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR POST USUARIO: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()



@app.put("/usuarios/{usuario_id}")
def actualizar_usuario(usuario_id: int, usuario: UsuarioUpdate, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    # Solo ADMIN puede editar usuarios
    if payload.get('rol') != 'ADMIN':
        raise HTTPException(status_code=403, detail="No tienes permisos para editar usuarios")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        # Verificar que el usuario existe
        cursor.execute("SELECT UsuarioID FROM Usuarios WHERE UsuarioID = ?", usuario_id)
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        # Verificar si el email ya existe en otro usuario
        cursor.execute("SELECT UsuarioID FROM Usuarios WHERE Email = ? AND UsuarioID != ?", usuario.email, usuario_id)
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="El email ya está en uso")
        
        # Actualizar usuario
        cursor.execute("""
            UPDATE Usuarios 
            SET Nombre=?, Email=?, Activo=?
            WHERE UsuarioID=?
        """, 
        usuario.nombre,
        usuario.email,
        usuario.activo,
        usuario_id
        )
        
        # Actualizar rol en UsuarioRoles
        cursor.execute("SELECT * FROM UsuarioRoles WHERE UsuarioID = ?", usuario_id)
        if cursor.fetchone():
            # Ya tiene rol, actualizar
            cursor.execute("""
                UPDATE UsuarioRoles 
                SET RolID=?
                WHERE UsuarioID=?
            """, usuario.rol_id, usuario_id)
        else:
            # No tiene rol, insertar
            cursor.execute("""
                INSERT INTO UsuarioRoles (UsuarioID, RolID)
                VALUES (?, ?)
            """, usuario_id, usuario.rol_id)
        
        conn.commit()
        
        return {"mensaje": "Usuario actualizado exitosamente"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR PUT USUARIO: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


@app.delete("/usuarios/{usuario_id}")
def eliminar_usuario(usuario_id: int, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    # Solo ADMIN puede eliminar usuarios
    if payload.get('rol') != 'ADMIN':
        raise HTTPException(status_code=403, detail="No tienes permisos para eliminar usuarios")
    
    # No permitir eliminar al propio usuario
    user_id_from_token = int(payload.get('sub', 0))
    if user_id_from_token == usuario_id:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propio usuario")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        cursor.execute("SELECT UsuarioID FROM Usuarios WHERE UsuarioID=?", usuario_id)
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        # Desactivar en lugar de eliminar
        cursor.execute("UPDATE Usuarios SET Activo=0 WHERE UsuarioID=?", usuario_id)
        conn.commit()
        
        return {"mensaje": "Usuario desactivado exitosamente"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR DELETE USUARIO: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()

# ========== MODELOS PYDANTIC PARA CONTROLES ==========
class ControlCreate(BaseModel):
    riesgo_id: int
    descripcion: str
    tipo: str = "Preventivo"
    responsable_id: Optional[int] = None
    fecha_inicio: Optional[str] = None
    fecha_limite: Optional[str] = None
    estado: str = "Pendiente"
    efectividad: int = 0

class ControlUpdate(BaseModel):
    descripcion: str
    tipo: str
    responsable_id: Optional[int] = None
    fecha_inicio: Optional[str] = None
    fecha_limite: Optional[str] = None
    estado: str
    efectividad: int


# ========== ENDPOINTS CONTROLES ==========

@app.get("/controles/riesgo/{riesgo_id}")
def get_controles_por_riesgo(riesgo_id: int, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                c.ControlID,
                c.RiesgoID,
                c.Descripcion,
                c.Tipo,
                c.ResponsableID,
                u.Nombre as ResponsableNombre,
                c.FechaInicio,
                c.FechaLimite,
                c.Estado,
                c.Efectividad,
                c.FechaCreacion
            FROM Controles c
            LEFT JOIN Usuarios u ON c.ResponsableID = u.UsuarioID
            WHERE c.RiesgoID = ?
            ORDER BY c.FechaCreacion DESC
        """, riesgo_id)
        
        rows = cursor.fetchall()
        result = []
        
        for r in rows:
            result.append({
                "control_id": r[0],
                "riesgo_id": r[1],
                "descripcion": r[2],
                "tipo": r[3],
                "responsable_id": r[4],
                "responsable_nombre": r[5] if r[5] else "Sin asignar",
                "fecha_inicio": str(r[6]) if r[6] else None,
                "fecha_limite": str(r[7]) if r[7] else None,
                "estado": r[8],
                "efectividad": r[9],
                "fecha_creacion": str(r[10]) if r[10] else None
            })
        
        return result
    
    except Exception as e:
        print(f"ERROR GET CONTROLES: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


@app.get("/controles")
def get_todos_controles(token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                c.ControlID,
                c.RiesgoID,
                r.Titulo as RiesgoTitulo,
                c.Descripcion,
                c.Tipo,
                c.ResponsableID,
                u.Nombre as ResponsableNombre,
                c.FechaInicio,
                c.FechaLimite,
                c.Estado,
                c.Efectividad,
                c.FechaCreacion
            FROM Controles c
            INNER JOIN Riesgos r ON c.RiesgoID = r.RiesgoID
            LEFT JOIN Usuarios u ON c.ResponsableID = u.UsuarioID
            ORDER BY c.FechaCreacion DESC
        """)
        
        rows = cursor.fetchall()
        result = []
        
        for r in rows:
            result.append({
                "control_id": r[0],
                "riesgo_id": r[1],
                "riesgo_titulo": r[2],
                "descripcion": r[3],
                "tipo": r[4],
                "responsable_id": r[5],
                "responsable_nombre": r[6] if r[6] else "Sin asignar",
                "fecha_inicio": str(r[7]) if r[7] else None,
                "fecha_limite": str(r[8]) if r[8] else None,
                "estado": r[9],
                "efectividad": r[10],
                "fecha_creacion": str(r[11]) if r[11] else None
            })
        
        return result
    
    except Exception as e:
        print(f"ERROR GET CONTROLES: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


@app.post("/controles")
def crear_control(control: ControlCreate, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        # Verificar que el riesgo existe
        cursor.execute("SELECT RiesgoID FROM Riesgos WHERE RiesgoID = ?", control.riesgo_id)
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Riesgo no encontrado")
        
        cursor.execute("""
            INSERT INTO Controles 
            (RiesgoID, Descripcion, Tipo, ResponsableID, FechaInicio, FechaLimite, Estado, Efectividad, FechaCreacion)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, GETDATE())
        """,
        control.riesgo_id,
        control.descripcion,
        control.tipo,
        control.responsable_id,
        control.fecha_inicio,
        control.fecha_limite,
        control.estado,
        control.efectividad
        )
        
        conn.commit()
        
        cursor.execute("SELECT @@IDENTITY AS id")
        nuevo_id = cursor.fetchone()[0]
        
        return {
            "mensaje": "Control creado exitosamente",
            "control_id": int(nuevo_id)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR POST CONTROL: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


@app.put("/controles/{control_id}")
def actualizar_control(control_id: int, control: ControlUpdate, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        cursor.execute("SELECT ControlID FROM Controles WHERE ControlID = ?", control_id)
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Control no encontrado")
        
        cursor.execute("""
            UPDATE Controles
            SET Descripcion=?, Tipo=?, ResponsableID=?, FechaInicio=?, FechaLimite=?, Estado=?, Efectividad=?
            WHERE ControlID=?
        """,
        control.descripcion,
        control.tipo,
        control.responsable_id,
        control.fecha_inicio,
        control.fecha_limite,
        control.estado,
        control.efectividad,
        control_id
        )
        
        conn.commit()
        
        return {"mensaje": "Control actualizado exitosamente"}
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR PUT CONTROL: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


@app.delete("/controles/{control_id}")
def eliminar_control(control_id: int, token: str = Depends(oauth2_scheme)):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        cursor.execute("SELECT ControlID FROM Controles WHERE ControlID = ?", control_id)
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Control no encontrado")
        
        cursor.execute("DELETE FROM Controles WHERE ControlID = ?", control_id)
        conn.commit()
        
        return {"mensaje": "Control eliminado exitosamente"}
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR DELETE CONTROL: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


# Función para registrar auditoría
def registrar_auditoria(
    usuario_id: int,
    usuario_nombre: str,
    accion: str,
    entidad: str,
    entidad_id: int = None,
    descripcion: str = "",
    datos_anteriores: dict = None,
    datos_nuevos: dict = None,
    ip: str = None
):
    """
    Registra una acción en la tabla de auditoría
    """
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        # Convertir dicts a JSON
        datos_ant_json = json.dumps(datos_anteriores, ensure_ascii=False) if datos_anteriores else None
        datos_nue_json = json.dumps(datos_nuevos, ensure_ascii=False) if datos_nuevos else None
        
        cursor.execute("""
            INSERT INTO Auditoria 
            (UsuarioID, UsuarioNombre, Accion, Entidad, EntidadID, Descripcion, DatosAnteriores, DatosNuevos, DireccionIP)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        usuario_id,
        usuario_nombre,
        accion,
        entidad,
        entidad_id,
        descripcion,
        datos_ant_json,
        datos_nue_json,
        ip
        )
        
        conn.commit()
        print(f"[AUDITORIA] {usuario_nombre} - {accion} {entidad} ID:{entidad_id}")
        
    except Exception as e:
        print(f"ERROR AUDITORIA: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()


# ========== ENDPOINTS AUDITORÍA ==========

@app.get("/auditoria")
def get_auditoria(
    limit: int = 100,
    entidad: str = None,
    usuario_id: int = None,
    token: str = Depends(oauth2_scheme)
):
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        # Construir query base
        query = """
            SELECT TOP (?)
                AuditoriaID,
                UsuarioID,
                UsuarioNombre,
                Accion,
                Entidad,
                EntidadID,
                Descripcion,
                DatosAnteriores,
                DatosNuevos,
                FechaHora,
                DireccionIP
            FROM Auditoria
            WHERE 1=1
        """
        
        params = [limit]
        
        if entidad:
            query += " AND Entidad = ?"
            params.append(entidad)
        
        if usuario_id:
            query += " AND UsuarioID = ?"
            params.append(usuario_id)
        
        query += " ORDER BY FechaHora DESC"
        
        cursor.execute(query, *params)
        rows = cursor.fetchall()
        
        result = []
        for r in rows:
            result.append({
                "auditoria_id": r[0],
                "usuario_id": r[1],
                "usuario_nombre": r[2],
                "accion": r[3],
                "entidad": r[4],
                "entidad_id": r[5],
                "descripcion": r[6],
                "datos_anteriores": json.loads(r[7]) if r[7] else None,
                "datos_nuevos": json.loads(r[8]) if r[8] else None,
                "fecha_hora": str(r[9]),
                "direccion_ip": r[10]
            })
        
        return result
    
    except Exception as e:
        print(f"ERROR GET AUDITORIA: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()


@app.get("/auditoria/entidad/{entidad}/{entidad_id}")
def get_auditoria_entidad(
    entidad: str,
    entidad_id: int,
    token: str = Depends(oauth2_scheme)
):
    """
    Obtener historial de una entidad específica
    """
    payload = decodificar_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = None
    try:
        conn = pyodbc.connect(CONN_STR)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                AuditoriaID,
                UsuarioNombre,
                Accion,
                Descripcion,
                DatosAnteriores,
                DatosNuevos,
                FechaHora
            FROM Auditoria
            WHERE Entidad = ? AND EntidadID = ?
            ORDER BY FechaHora DESC
        """, entidad, entidad_id)
        
        rows = cursor.fetchall()
        result = []
        
        for r in rows:
            result.append({
                "auditoria_id": r[0],
                "usuario_nombre": r[1],
                "accion": r[2],
                "descripcion": r[3],
                "datos_anteriores": json.loads(r[4]) if r[4] else None,
                "datos_nuevos": json.loads(r[5]) if r[5] else None,
                "fecha_hora": str(r[6])
            })
        
        return result
    
    except Exception as e:
        print(f"ERROR GET AUDITORIA ENTIDAD: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        if conn:
            conn.close()