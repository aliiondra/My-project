from sqlalchemy import SmallInteger, types
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, Boolean, Float, event, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.types import LargeBinary
from datetime import datetime, timedelta
from database import Base

class LongBlob(types.TypeDecorator):
    impl = LargeBinary

    def load_dialect_impl(self, dialect):
        if dialect.name == 'mysql':
            return dialect.type_descriptor(types.LargeBinary(length=4294967295))
        else:
            return self.impl
        
# Modelo de Login
class Login(Base):
    __tablename__ = 'login'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    email = Column(String(255), unique=True, index=True)
    password = Column(String(255), nullable=False)
    admin = Column(Boolean, default=False)

    user_academia = relationship("UserAcademia", back_populates="login", cascade="all, delete")
    user_campus = relationship("UserCampus", back_populates="login", cascade="all, delete")

# Modelo de Academia
class Academia(Base):
    __tablename__ = 'academias'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    num_alums = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    max_consultas = Column(Integer, nullable=True)
    dominio = Column(String(255), nullable=False)

    user_academia = relationship("UserAcademia", back_populates="academia", cascade="all, delete-orphan")
    oposiciones_rel = relationship("AcademiaOposiciones", back_populates="academia", cascade="all, delete-orphan")
    oposiciones = relationship("Oposicion", secondary="academia_oposiciones", back_populates="academias")

# Modelo de Oposicion
class Oposicion(Base):
    __tablename__ = "opos"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True)
    update_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    punto_correctas = Column(Float, nullable=False)
    punto_incorrectas = Column(Float, nullable=False)

    exam = relationship('Exam', back_populates="oposicion")
    tutor = relationship("Tutor", back_populates="opos")
    examinator = relationship("Examinator", back_populates="opos")
    academias_rel = relationship("AcademiaOposiciones", back_populates="oposicion", cascade="all, delete-orphan")
    academias = relationship("Academia", secondary="academia_oposiciones", back_populates="oposiciones")

# Modelo de Corrección
class Correction(Base):
    __tablename__ = 'corrections'

    id = Column(Integer, primary_key=True, index=True)
    exam_id = Column(Integer, ForeignKey('exams.id'), unique=True, nullable=False)
    correction_content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    exam = relationship("Exam", back_populates="corrections")

# Modelo de Usuario que pertenece a una academia
class UserAcademia(Base):
    __tablename__ = 'users_academia'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    first_surname = Column(String(255), nullable=False)
    second_surname= Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    login_id = Column(Integer, ForeignKey("login.id", ondelete="CASCADE"), nullable=False)
    tutor_id = Column(Integer, ForeignKey("tutors.id"), nullable=True)
    examinator_id = Column(Integer, ForeignKey("examinators.id"), nullable=True)
    academia_id = Column(Integer, ForeignKey('academias.id'), nullable=False)
    multidominio = Column(SmallInteger, default=0)

    academia = relationship('Academia', back_populates='user_academia')
    nota_media_mensual_parte_academia = relationship('NotasMediaMensualParteAcademia', back_populates='user_academia', cascade="all, delete-orphan")
    user_exam_academia = relationship('UserExamAcademia', back_populates='user_academia', cascade="all, delete-orphan")
    tutor = relationship("Tutor", back_populates="user_academia")
    examinator = relationship("Examinator", back_populates="user_academia")
    login = relationship("Login", back_populates="user_academia", single_parent=True, cascade="all, delete-orphan")
    consultas_guardadas = relationship("ConsultasGuardadas", back_populates="user_academia")
    user_ip_academia = relationship("UserIPAcademia", back_populates="user_academia", cascade="all, delete-orphan")

# Evento que se dispara al añadir un registro en User
@event.listens_for(UserAcademia, 'after_insert')
def after_insert_child(mapper, connection, target):
    connection.execute(
        Academia.__table__.update().
            where(Academia.__table__.c.id == target.academia_id).
            values(num_alums=Academia.__table__.c.num_alums + 1)
    )

# Evento que se dispara después de eliminar un registro en User
@event.listens_for(UserAcademia, 'after_delete')
def after_delete_child(mapper, connection, target):
    connection.execute(
        Academia.__table__.update().
            where(Academia.__table__.c.id == target.academia_id).
            values(num_alums=Academia.__table__.c.num_alums - 1)
    )
# Modelo de Usuario que pertenece al Campus
class UserCampus(Base):
    __tablename__ = 'users_campus'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    first_surname = Column(String(255), nullable=False)
    second_surname= Column(String(255), nullable=True)
    email = Column(String(255), nullable=False, unique=True)
    phone = Column(String(15), nullable=False)
    province = Column(String(255), nullable=False)
    city = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    login_id = Column(Integer, ForeignKey("login.id", ondelete="CASCADE"), nullable=False)
    examinator_id = Column(Integer, ForeignKey("examinators.id"), nullable=True)
    is_trial = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)

    nota_media_mensual_parte_campus = relationship('NotasMediaMensualParteCampus', back_populates='user_campus', cascade="all, delete-orphan")
    user_exam_campus = relationship('UserExamCampus', back_populates='user_campus', cascade="all, delete-orphan")
    examinator = relationship("Examinator", back_populates="user_campus")
    login = relationship("Login", back_populates="user_campus", single_parent=True, cascade="all, delete-orphan")
    user_ip_campus = relationship("UserIPCampus", back_populates="user_campus", cascade="all, delete-orphan")
    subscripcion = relationship('Subscripcion', back_populates='user_campus', cascade="all, delete-orphan")
    historial_pagos = relationship('HistorialPagos', back_populates='user_campus', cascade="all, delete-orphan")

# Modelo de Historial de Pagos
class HistorialPagos(Base):
    __tablename__ = 'historial_pagos'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users_campus.id', ondelete="CASCADE"))
    pay_day = Column(DateTime, default=datetime.utcnow)
    months_subscribed = Column(Integer, default=0)

    user_campus = relationship('UserCampus', back_populates='historial_pagos')

# Modelo de Suscripciones
class Subscripcion(Base):
    __tablename__ = 'subscripcion'

    id = Column(Integer, primary_key=True, index=True)
    stripe_subscription_id = Column(String(255))
    user_id = Column(Integer, ForeignKey('users_campus.id', ondelete="CASCADE"))
    active = Column(Boolean, default=False)
    cancel_at_period_end = Column(Boolean)

    user_campus = relationship('UserCampus', back_populates='subscripcion')

# Tabla intermedia entre User y Exam de usuarios pertenecientes a academias (exámenes realizados) 
class UserExamAcademia(Base):
    __tablename__ = 'user_exam_academia'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users_academia.id', ondelete="CASCADE"))
    exam_id = Column(Integer, ForeignKey('exams.id'), nullable=True)
    part = Column(String(255), ForeignKey('exams.part'), nullable=False)
    nota = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    time_spend = Column(Float, nullable=False) #tiempo en segundos que recibe de la base de datos

    user_academia = relationship('UserAcademia', back_populates='user_exam_academia')
    exam = relationship('Exam', back_populates='exam_associations_academia', foreign_keys=[exam_id])

# Tabla intermedia entre User y Exam de usuarios pertenecientes a academias (exámenes resalizados) 
class UserExamCampus(Base):
    __tablename__ = 'user_exam_campus'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users_campus.id', ondelete="CASCADE"))
    exam_id = Column(Integer, ForeignKey('exams.id'), nullable=True)
    part = Column(String(255), ForeignKey('exams.part'), nullable=False)
    nota = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    time_spend = Column(Float, nullable=False) #tiempo en segundos que recibe de la base de datos

    user_campus = relationship('UserCampus', back_populates='user_exam_campus')
    exam = relationship('Exam', back_populates='exam_associations_campus', foreign_keys=[exam_id])

# Modelo de Examen
class Exam(Base):
    __tablename__ = 'exams'

    id = Column(Integer, primary_key=True, index=True)
    part = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    context = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    oposicion_id = Column(Integer, ForeignKey('opos.id'), nullable=False)
    total_preguntas = Column(Integer)
    
    oposicion = relationship("Oposicion", back_populates="exam")
    corrections = relationship("Correction", uselist=False, back_populates="exam", cascade="all, delete-orphan")
    exam_associations_academia = relationship('UserExamAcademia', back_populates='exam', foreign_keys=[UserExamAcademia.exam_id])
    exam_associations_campus = relationship('UserExamCampus', back_populates='exam', foreign_keys=[UserExamCampus.exam_id])

# Modelo de Tutor
class Tutor(Base):
    __tablename__ = 'tutors'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    oposicion_id = Column(Integer, ForeignKey('opos.id'), nullable=False)
    photo = Column(LongBlob, nullable=False)
   
    user_academia = relationship('UserAcademia', back_populates='tutor')
    opos = relationship("Oposicion", primaryjoin="Tutor.oposicion_id == Oposicion.id")

# Modelo de Examinator
class Examinator(Base):
    __tablename__ = 'examinators'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    oposicion_id = Column(Integer, ForeignKey('opos.id'), nullable=False)
    json_partes = Column(JSON, nullable=False)
    photo = Column(LongBlob, nullable=False)
    
    user_academia = relationship('UserAcademia', back_populates='examinator')
    user_campus = relationship('UserCampus', back_populates='examinator')
    opos = relationship("Oposicion", primaryjoin="Examinator.oposicion_id == Oposicion.id")
    
# Modelo de Consultas Guardadas
class ConsultasGuardadas(Base):
    __tablename__ = 'consultas_guardadas'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users_academia.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    query = Column(Text, nullable=False)
    acciones = Column(Text, nullable=True)

    user_academia = relationship('UserAcademia', back_populates='consultas_guardadas')

# Tabla con notas medias de los usuarios a nivel mensual por parte
class NotasMediaMensualParteAcademia(Base):
    __tablename__= 'notas_media_mensual_parte_academia'

    id = Column(Integer, primary_key=True, index=True)
    id_usuario = Column(Integer, ForeignKey('users_academia.id',ondelete="CASCADE"), nullable=False)
    parte = Column(String(255), nullable=False)
    date = Column(DateTime,default=datetime.utcnow)
    nota_media = Column(Float, nullable=False)

    user_academia = relationship('UserAcademia', back_populates='nota_media_mensual_parte_academia')

# Tabla con notas medias de los usuarios a nivel mensual por parte
class NotasMediaMensualParteCampus(Base):
    __tablename__= 'notas_media_mensual_parte_campus'

    id = Column(Integer, primary_key=True, index=True)
    id_usuario = Column(Integer, ForeignKey('users_campus.id',ondelete="CASCADE"), nullable=False)
    parte = Column(String(255), nullable=False)
    date = Column(DateTime,default=datetime.utcnow)
    nota_media = Column(Float, nullable=False)

    user_campus = relationship('UserCampus', back_populates='nota_media_mensual_parte_campus')

# Tabla de academias y oposiciones
class AcademiaOposiciones(Base):
    __tablename__ = 'academia_oposiciones'

    academia_id = Column(Integer, ForeignKey('academias.id', ondelete="CASCADE"), primary_key=True)
    oposicion_id = Column(Integer, ForeignKey('opos.id', ondelete="CASCADE"), primary_key=True)
    preguntas_test = Column(Integer)
    preguntas_casos = Column(Integer)

    academia = relationship("Academia", back_populates="oposiciones_rel")
    oposicion = relationship("Oposicion", back_populates="academias_rel")

# Tabla para guardar las IPs de los usuarios de las academias
class UserIPAcademia(Base):
    __tablename__ = 'user_ip_academia'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users_academia.id', ondelete="CASCADE"), nullable=False)
    ip = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_academia = relationship('UserAcademia', back_populates='user_ip_academia')

# Tabla para guardar las IPs de los usuarios del campus
class UserIPCampus(Base):
    __tablename__ = 'user_ip_campus'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users_campus.id', ondelete="CASCADE"), nullable=False)
    ip = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_campus = relationship('UserCampus', back_populates='user_ip_campus')