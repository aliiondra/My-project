from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from flask_sqlalchemy import SQLAlchemy

from contextlib import contextmanager
import os, logging

logger = logging.getLogger(__name__)
db = SQLAlchemy()

# Configuración para conectarse a la base de datos remota del servidor
# Opción 1: Conexión directa al servidor
DB_USER = 'db_user_placeholder'
DB_PASSWORD = 'db_password_placeholder'
DB_HOST = 'db_host_placeholder'  # IP del servidor remoto 
DB_PORT = 'db_port_placeholder'  # Puerto MySQL estándar
DB_NAME = 'db_name_placeholder'
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
# DATABASE_URL = "sqlite:///pruebas.db"

# Opción 2: Para usar con túnel SSH (descomenta las líneas siguientes si usas túnel SSH)
# DB_USER = 'db_user_placeholder'
# DB_PASSWORD = 'db_password_placeholder'
# DB_HOST = 'db_host_placeholder'  # Localhost a través del túnel
# DB_PORT = 'db_port_placeholder'       # Puerto local del túnel SSH
# DB_NAME = 'db_name_placeholder'
# DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"


# Configuración del engine con opciones de conexión 
# Configuración mejorada del engine en database.py
# Configuración del engine en database.py
engine = create_engine( 
    DATABASE_URL, 
    pool_size=20,                   # Tamaño del pool de conexiones 
    max_overflow=30,                # Máximo de conexiones adicionales 
    pool_timeout=60,                # Tiempo máximo de espera para obtener una conexión
    pool_recycle=1800,              # Reciclar conexiones después de 30 minutos
    pool_pre_ping=True,             # Verificar conexiones antes de usarlas 
    connect_args={ 
        'connect_timeout': 30,      # Timeout de conexión en segundos
        'read_timeout': 90,         # Timeout de lectura en segundos
        'write_timeout': 90,        # Timeout de escritura en segundos
        'max_allowed_packet': 1073741824  # 1GB - Aumentar el tamaño máximo de paquete
    } 
)

# Función para verificar la conectividad de la base de datos
def check_database_connection(): 
    try: 
        connection = engine.connect() 
        connection.close() 
        logger.info("✅ Conexión a la base de datos establecida correctamente")
        return True 
    except Exception as e: 
        logger.error(f"❌ Error de conexión a la base de datos: {str(e)}") 
        return False

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

@contextmanager
def session_scope():
    """Proporciona un contexto transaccional para las operaciones."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        logger.error(f"Error en la transacción: {str(e)}")
        session.rollback()
        raise
    finally:
        session.close()