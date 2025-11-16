from database import *
from tablas import *
from sqlalchemy import asc, extract, or_, text, func
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import SQLAlchemyError
from typing import Optional, List, Dict
from parse_to_html import ExamHTMLParser
import random, json, logging
import re, os
from datetime import datetime

logger = logging.getLogger(__name__)

max_retries = 3

# Servicio para gestionar la base de datos
class BaseDBService:
    def __init__(self):
        self.db = SessionLocal()
        
    def close(self):
        """Cierra la conexión a la base de datos."""
        if self.db:
            self.db.close()

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        if exc_type is not None:
            logger.error(f"Error en contexto de servicio: {str(exc_val)}")
            return False
        return True
    
# Servicio para gestionar usuarios
class UserDBService(BaseDBService):

    def get_user(self, session, user_id: int) -> UserCampus:
        retries = 0
        while retries < max_retries:
            try:
                return session.query(UserCampus).filter(UserCampus.id == user_id).first()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise 
            except Exception as e:
                logger.error(f"Error inesperado al obtener el usuario: {str(e)}")
                raise
    
    def get_all_users(self, session):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(UserCampus).outerjoin(Tutor, UserCampus.tutor_id == Tutor.id) \
                                    .outerjoin(Examinator, UserCampus.examinator_id == Examinator.id) \
                                    .options(joinedload(UserCampus.tutor), joinedload(UserCampus.examinator)) \
                                    .all()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise 
            except Exception as e:
                logger.error(f"Error inesperado al obtener usuarios: {str(e)}")
                raise
        
    def get_user_by_login_id(self, session, login_id: int):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(UserCampus).filter(UserCampus.login_id == login_id).first()
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener el usuario por login_id: {str(e)}")
                raise

    def get_login_by_login_id(self, session, login_id: int):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Login).filter(Login.id == login_id).first()
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener el login: {str(e)}")
                raise

    def get_user_by_email(self, email: str):
        retries = 0
        while retries < max_retries:
            try:
                return self.db.query(UserCampus).filter(UserCampus.email == email).first()
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener el login: {str(e)}")
                raise
    
    def get_next_id(self):
        """Obtiene el siguiente ID disponible"""
        retries = 0
        while retries < max_retries:
            try:
                last_user = self.db.query(UserCampus).order_by(UserCampus.id.desc()).first()
                if last_user is None:
                    return 1  # No hay registros, empezamos desde 1
                next_id = last_user.id + 1
                print(next_id)
                return next_id
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente luego de {max_retries} intentos: {str(e)}")
                    raise
                # Cerrar y recrear la sesión
                self.close()
                self.db = SessionLocal()
            except Exception as e:
                logger.error(f"Error inesperado al obtener el siguiente ID: {str(e)}")
                raise

    def create_user(self, name: str, first_surname: str, second_surname: str, email: str, phone: str, province: str, city: str, login_id: int, examinator_id: int = None):
        try:
            existing_user = self.db.query(UserCampus).filter(UserCampus.email == email).first()
            if existing_user:
                return existing_user
            else:
                user = UserCampus(name=name, first_surname=first_surname, second_surname=second_surname, email=email, phone=phone, province=province, city=city, login_id=login_id, examinator_id=examinator_id)
                self.db.add(user)
                self.db.commit()
                self.db.refresh(user)
                return user
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"Error al crear el usuario: {str(e)}")
        except Exception as e: 
            logger.error(f"Error inesperado al crear el usuario: {str(e)}")

    def set_user_trial_status(self, session, user_id, trial):
        try:
            user = session.query(UserCampus).filter(UserCampus.id == user_id).first()
            if user:
                user.is_trial = trial
                session.commit()
                return user
            else:
                logger.warning(f"Usuario con ID {user_id} no encontrado.")
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error al actualizar is_trial del usuario: {str(e)}")
        except Exception as e:
            logger.error(f"Error inesperado al actualizar is_trial: {str(e)}")

    # Servicio de cambio de contraseñas
    def change_password(self, session, id_login: int, hashed_password: str):
        retries = 0
        while retries < max_retries:
            try:
                """
                Cambia la contraseña de un usuario dado su id_login.

                :param id_login: ID del login
                :param hashed_password: Nueva contraseña hasheada
                """
                # Obtener el login directamente por su ID
                login = session.query(Login).filter(Login.id == id_login).first()
                
                if not login:
                    logger.error(f"Login no encontrado con ID {id_login}")
                    raise ValueError(f"Login con ID {id_login} no encontrado")

                # Actualizar la contraseña
                login.password = hashed_password
                session.commit()
                logger.info(f"Contraseña actualizada para login_id={id_login}")
                return True
            
            except SQLAlchemyError as e:
                session.rollback()
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                session.rollback()
                logger.error(f"Error inesperado al cambiar contraseña: {str(e)}")
                raise

    def get_user_by_username(self, session, username):
        retries = 0
        while retries < max_retries:
            try:
                login = session.query(Login).filter(Login.username == username).first()
                if login:
                    return session.query(UserCampus).filter(UserCampus.login_id == login.id).first()
                return None
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise 
            except Exception as e:
                logger.error(f"Error inesperado al obtener usuario por username: {str(e)}")
                raise

    def get_email_by_username(self, session, username):
        retries = 0
        while retries < max_retries:
            try:
                login = session.query(Login).filter(Login.username == username).first()
                if login:
                    return login.email
                return None
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise 
            except Exception as e:
                logger.error(f"Error inesperado al obtener el email del usuario: {str(e)}")
                raise
    
    def disable_user(self, session, user_id: int):
        retries = 0
        while retries < max_retries:
            try:
                user = session.query(UserCampus).filter(UserCampus.id == user_id).first()
                user.is_active = False
                session.add(user)
                session.commit()
                logger.info(f"Usuario con ID {user_id} desactivado exitosamente")
                return True
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                session.rollback()
                logger.error(f"Error inesperado al eliminar el usuario: {str(e)}")
                raise

    def is_trial_user(self, session, user_id: int):
        retries = 0
        while retries < max_retries:
            try:
                user = session.query(UserCampus).filter(UserCampus.id == user_id).first()
                return user.is_trial
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al verificar si el usuario es un usuario de prueba: {str(e)}")
                raise

# Servicio para gestionar exámenes
class ExamDBService(BaseDBService):
    
    def get_exam(self, session, exam_id: int) -> Optional[Exam]:
        """Obtener un examen por su ID"""
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Exam).filter(Exam.id == exam_id).first()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise 
            except Exception as e:
                logger.error(f"Error inesperado al obtener examen: {str(e)}")
                raise

    def get_all_exams(self, session) -> List[Exam]:
        """Obtener todos los exámenes"""
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Exam).order_by(Exam.created_at.desc()).all()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise 
            except Exception as e:
                logger.error(f"Error inesperado al obtener todos los exámenes: {str(e)}")
                raise

    def get_content_by_id_exam(self, session, id_exam: int):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Exam).filter(Exam.id == id_exam).first().content
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise 
            except Exception as e:
                logger.error(f"Error inesperado al obtener contenido del examen: {str(e)}")
                raise

    def get_random_exam_by_data(self, session, oposicion_id: int, part: str, id_user: int) -> Exam:
        retries = 0
        while retries < max_retries:
            try:
                # Obtener todos los exámenes del examinador
                exams_by_examinator = session.query(Exam).filter(
                Exam.oposicion_id == oposicion_id, Exam.part == part).all()

                undone_exams = []

                # Buscar exámenes que el usuario no haya hecho
                for exam in exams_by_examinator:
                    undone_exam = session.query(UserExamCampus).filter(
                            UserExamCampus.exam_id == exam.id,
                            UserExamCampus.user_id == id_user).first()
                    
                    if not undone_exam:  # Si no hay registro, el usuario no lo ha hecho
                        undone_exams.append(exam)

                # Seleccionar un examen aleatorio
                if undone_exams:
                    return random.choice(undone_exams)
                elif exams_by_examinator:  # Si no hay exámenes sin hacer, elegir cualquiera disponible
                    return random.choice(exams_by_examinator)
                else:
                    print("No hay exámenes disponibles")
                    return None
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener examen aleatorio: {str(e)}")
                raise
    
    def get_random_exam_for_sofia(self, session, oposicion_id: int, part: str, id_user: int) -> Exam:
        retries = 0
        while retries < max_retries:
            try:
                # Mapeo directo entre el nombre del bloque y los posibles nombres en la base de datos
                direct_mapping = {
                    "case_allblocks": ["case_all", "case_general", "case_allblocks"],
                    "case_block4admin": ["case_admin", "case_d_admin", "case_derecho", "case_block4", "case_block4admin"],
                    "case_block5rrhh": ["case_rh", "case_r_humanos", "case_recursos", "case_block5", "case_block5rrhh"],
                    "case_block6gfinanciera": ["case_g_financiera", "case_financiera", "case_gestion", "case_block6", "case_block6gfinanciera"],
                    "case_blockcontratos": ["case_contratos", "case_contrato", "case_blockcontratos"]
                }
                
                # Obtener nombres posibles para el bloque actual
                possible_names = direct_mapping.get(part, [part])
                
                # Consulta para encontrar exámenes con correcciones válidas
                valid_exams = []
                undone_exams = []
                
                for name in possible_names:
                    # Buscar exámenes exactos de este bloque
                    exams = session.query(Exam).filter(
                        Exam.oposicion_id == oposicion_id,
                        Exam.part == name
                    ).all()
                    
                    if not exams:
                        # Si no hay coincidencias exactas, buscar con comodines
                        exams = session.query(Exam).filter(
                            Exam.oposicion_id == oposicion_id,
                            Exam.part.like(f"{name}%")
                        ).all()
                    
                    # Para cada examen, verificar si tiene corrección válida
                    for exam in exams:
                        # Verificar si hay corrección mediante consulta directa o nombre específico
                        has_correction = False
                        
                        # 1. Buscar en la tabla Correction directamente
                        correction = session.query(Correction).filter(
                            Correction.exam_id == exam.id
                        ).first()
                        
                        if correction:
                            has_correction = True
                        else:
                            # 2. Buscar examen de corrección específico
                            correction_name = f"{exam.part.replace('.txt', '')}_correction.txt"
                            correction_exam = session.query(Exam).filter(
                                Exam.oposicion_id == oposicion_id,
                                Exam.part == correction_name
                            ).first()
                            
                            if correction_exam:
                                correction = session.query(Correction).filter(
                                    Correction.exam_id == correction_exam.id
                                ).first()
                                
                                if correction:
                                    has_correction = True
                        
                        # Si tiene corrección, agregarlo a la lista de exámenes válidos
                        if has_correction:
                            valid_exams.append(exam)
                            
                            # Verificar si el usuario ya ha realizado este examen
                            user_exam = session.query(UserExamCampus).filter(
                                UserExamCampus.exam_id == exam.id,
                                UserExamCampus.user_id == id_user
                            ).first()
                            
                            if not user_exam:
                                undone_exams.append(exam)
                
                # Elegir un examen no realizado si está disponible
                if undone_exams:
                    selected_exam = random.choice(undone_exams)
                    logger.debug(f"Seleccionado examen sin realizar: {selected_exam.part}")
                    return selected_exam
                
                # Si todos los exámenes ya fueron realizados, elegir cualquiera con corrección
                if valid_exams:
                    selected_exam = random.choice(valid_exams)
                    logger.debug(f"Seleccionado examen con corrección: {selected_exam.part}")
                    return selected_exam
                
                # Si no hay exámenes con corrección para este bloque específico
                logger.warning(f"No se encontraron exámenes con corrección para el bloque {part}")
                return None
                
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al buscar examen para Sofia: {str(e)}")
                raise

    def get_filtered_exams(self, session, part: Optional[str] = None, date_from: Optional[str] = None) -> List[Exam]:
        """Obtener exámenes filtrados por criterios"""
        retries = 0
        while retries < max_retries:
            try:
                query = session.query(Exam)
                if part:
                    query = query.filter(Exam.part == part)
                if date_from:
                    query = query.filter(Exam.created_at >= date_from)
                return query.order_by(Exam.created_at.desc()).all()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al filtrar exámenes: {str(e)}")
                raise

    def get_correction(self, session, exam_id):
        """Ejecuta una operación con reintentos en caso de error.""" 
        retries = 0 
        while retries < max_retries:
            try:
                correction = session.query(Correction).filter(Correction.exam_id == exam_id).first()
                return ExamHTMLParser.format_correction(correction.correction_content)
            except Exception as e:
                logger.error(f"Error inesperado al obtener corrección: {str(e)}")
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener corrección: {str(e)}")
                raise

    def get_correction_sofia(self, session, exam_id):
        """
        Obtiene la corrección asociada a un examen de Sofia con búsqueda simplificada.
        """
        retries = 0 
        while retries < max_retries:
            try:
                # 1. Primero, buscar corrección directa en la tabla de Correction
                correction = session.query(Correction).filter(Correction.exam_id == exam_id).first()
                
                if correction:
                    return correction
                
                # 2. Si no se encuentra, intentar localizar el examen
                exam = session.query(Exam).filter(Exam.id == exam_id).first()
                if not exam:
                    logger.error(f"No se encontró el examen {exam_id}")
                    return None
                
                # 3. Buscar corrección específica para este examen
                correction_name = f"{exam.part.replace('.txt', '')}_correction.txt"
                correction_exam = session.query(Exam).filter(
                    Exam.oposicion_id == exam.oposicion_id,
                    Exam.part == correction_name
                ).first()
                
                if correction_exam:
                    # Buscar el contenido de la corrección
                    exact_correction = session.query(Correction).filter(
                        Correction.exam_id == correction_exam.id
                    ).first()
                    
                    if exact_correction:
                        return exact_correction
                    else:
                        # Si no hay contenido en Correction pero existe el examen de corrección
                        return {"exam_id": correction_exam.id, "correction_content": correction_exam.content, "texto": correction_exam.content}
                
                # Si llegamos aquí, no se encontró corrección
                logger.error(f"No se encontró corrección para el examen {exam_id}")
                return None
                    
            except Exception as e:
                logger.error(f"Error buscando corrección de Sofia: {str(e)}")
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise

    def get_exam_correction_and_points(self, session, exam_id, examinator_id):
        retries = 0
        while retries < max_retries:
            try:
                correction = self.get_correction(session, exam_id)
                examinator = session.query(Examinator).filter(Examinator.id == examinator_id).first()
                opos = session.query(Oposicion).filter(Oposicion.id == examinator.oposicion_id).first()
                return correction, opos.punto_correctas, opos.punto_incorrectas
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener corrección y puntos: {str(e)}")
                raise

    def calculate_score(self, corrections: Dict[str, str], answers: dict, correct_points: float, incorrect_points: float) -> Dict:
        """Ejecuta una operación con reintentos en caso de error.""" 
        retries = 0
        while retries < max_retries:
            """
            Calcula la puntuación del examen basándose en las respuestas del usuario
            y la configuración de scoring
            
            Args:
                session_id: ID de la sesión actual
                answers: Diccionario con las respuestas del usuario
                scoring_config: Configuración de puntuación para este examen
            
            Returns:
                Dict con los resultados del examen incluyendo puntuación total y estadísticas
            """
            try:
                # Inicializar contadores
                stats = {
                    'correct': 0,
                    'incorrect': 0,
                    'blank': 0
                }
                total_score = 0
                
                # Procesar cada pregunta
                for question_id, correction_text in corrections.items():
                    # Extraer la opción correcta del texto de corrección usando regex
                    match = re.search(r'\[\d+\]\[([a-zA-Z])\]', correction_text)
                    if not match:
                        continue
                    correct_option = match.group(1).lower()
                    
                    # Manejo más robusto de respuestas en blanco
                    question_data = answers.get(f"q_{question_id}", {})
                    if isinstance(question_data, str):
                        question_data = json.loads(question_data)
                    user_answer = question_data.get('option', '').strip()
                    
                    # Calcular puntuación y actualizar estadísticas
                    if not user_answer or user_answer == '' or user_answer.lower() == 'blank':  # <- Cambio aquí
                        stats['blank'] += 1
                        total_score += 0
                    elif user_answer.lower() == correct_option:
                        stats['correct'] += 1
                        total_score += correct_points
                    else:
                        stats['incorrect'] += 1
                        total_score -= incorrect_points
                
                # Asegurar que la puntuación no sea negativa
                total_score = max(0, total_score)
        
                return {
                    'corrections': corrections,
                    'score': {
                        'total': total_score,
                        'stats': stats,
                        'scoring_config': {
                            'correct': correct_points,
                            'incorrect': incorrect_points,
                            'blank': 0
                        }
                    }
                }
            
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al calcular puntuación: {str(e)}")
                raise

    def asociar_examen_usuario(self, session, user_id: int, exam_id: int, nota: float, time_spend: int, part: str):
        try:
            nueva_relacion = UserExamCampus(user_id=user_id, exam_id=exam_id, nota=nota, time_spend=time_spend, part=part)
            session.add(nueva_relacion)
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Error al asociar examen con usuario: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error inesperado al asociar examen con usuario: {str(e)}")
            raise

# Servicio para gestionar tutores
class TutorDBService(BaseDBService):

    def get_tutor(self, session, tutor_id: int):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Tutor).filter(Tutor.id == tutor_id).first()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener tutor: {str(e)}")
                raise

    def get_all_tutors(self, session):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Tutor).all()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener todos los tutores: {str(e)}")
                raise

    def get_tutor_por_oposición(self, session, oposicion_id: int):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Tutor).filter(Tutor.oposicion_id==oposicion_id).first()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener tutor por oposición: {str(e)}")
                raise

# Servicio para gestionar examinadores
class ExaminatorDBService(BaseDBService):

    def get_examinator(self, session, examinator_id: int):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Examinator).filter(Examinator.id == examinator_id).first()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener examinador: {str(e)}")
                raise

    def get_exams_by_oposicion(self, session, oposicion_id: int):
        """Obtiene todos los exámenes asociados a un examinador."""
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Exam).filter(Exam.oposicion_id == oposicion_id).all()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener exámenes por examinador: {str(e)}")
                raise

    def get_all_examinators_by_user(self, session, examinator_id: int, admin: bool):
        retries = 0
        while retries < max_retries:
            try:
                if admin:
                    # Si el usuario es admin, obtener todos los examinadores
                    examinators = session.query(Examinator).all()
                    return examinators
                else:
                    # Si no es admin, obtener solo el examinator asignado
                    examinator = session.query(Examinator).filter(Examinator.id == examinator_id).first()
                    return [examinator] if examinator else []

            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener examinadores por usuario: {str(e)}")
                raise

    
    def get_json_by_id(self, session, examinator_id: int):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Examinator.json_partes).filter(Examinator.id == examinator_id).first()
            except SQLAlchemyError as e: 
                    retries += 1 
                    logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                    if retries >= max_retries: 
                        logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                        raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener JSON por ID: {str(e)}")
                raise

    def get_examinator_by_oposicion_id(self, session, oposicion_id):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Examinator).filter(Examinator.oposicion_id == oposicion_id).first()
            except SQLAlchemyError as e: 
                retries += 1 
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                if retries >= max_retries: 
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener JSON por ID: {str(e)}")
                raise  
            
# Servicio para gestionar el historial de interacciones
class ConsultasDbService(BaseDBService):

    def create_instancia_historial(self, session, id_usuario: int):
        retries = 0
        while retries < max_retries:
            try:
                instancia = ConsultasGuardadas(id_usuario = id_usuario)
                session.add(instancia)
                session.commit()
                session.refresh(instancia)
            except SQLAlchemyError as e: 
                    retries += 1 
                    logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                    if retries >= max_retries: 
                        logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                        raise
            except Exception as e:
                logger.error(f"Error inesperado al crear instancia de historial: {str(e)}")
                raise

# Servicio de Login
class LoginDBService(BaseDBService):

    def get_user_login_by_username(self, session, username: str) -> Login:
        """Busca un usuario por su username con reintentos en caso de error en la BD."""
        retries = 0

        while retries < max_retries:
            try:
                # Consulta dentro del contexto de la sesión
                return session.query(Login).filter(Login.username == username).first()
            
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")

                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            
            except Exception as e:
                logger.error(f"Error inesperado al buscar el usuario por username: {str(e)}")
                raise

    def get_user_login_by_email(self, session, email: str) -> Login:
        retries = 0
        while retries < max_retries:
            try:
                user = session.query(UserCampus).filter(UserCampus.email == email).first()
                if user:
                    return user.login
                return None
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")

                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al buscar el usuario por email: {str(e)}")
                raise

    def get_user_login_by_id(self, session, id_login) -> Login:
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Login).filter(Login.id==id_login).first()
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")

                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            
            except Exception as e:
                logger.error(f"Error inesperado al buscar el usuario por ID: {str(e)}")
                raise
    
    def save_user_ip(self, session, user_id: int, client_ip: str):
        retries = 0
        while retries < max_retries:
            try:
                user_ip = UserIPCampus(user_id=user_id, ip=client_ip)
                session.add(user_ip)
                session.commit()
                session.refresh(user_ip)
                return
            except SQLAlchemyError as e:
                session.rollback()  # IMPORTANTE: Deshacer cambios en caso de error
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                session.rollback()  # IMPORTANTE: Deshacer cambios en caso de error inesperado
                logger.error(f"Error inesperado al guardar la IP del usuario: {str(e)}")
                raise
    
    def maximo_ips(self, session, user_id: int) -> bool:
        retries = 0
        while retries < max_retries:
            try:
                contador = session.query(UserIPCampus).filter(UserIPCampus.user_id == user_id).count()
                return contador >= 3
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al comprobar la cantidad de IPs del usuario: {str(e)}")
                raise

    def check_ip(self, session, user_id: int, client_ip: str) -> bool:
        retries = 0
        while retries < max_retries:
            try:
                return session.query(UserIPCampus).filter_by(user_id=user_id, ip=client_ip).first() is not None
            except SQLAlchemyError as e:
                session.rollback()
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                session.rollback()
                logger.error(f"Error inesperado al comprobar la IP del usuario: {str(e)}")
                raise
    
    # Funciones sin la sesión debido a que todavia no se a iniciado
    def create_login(self, username: str, email: str, password: str, admin: bool) -> Login:
        try:
            existing_user = self.db.query(Login).filter(Login.username == username).first()
            if existing_user:
                return existing_user
            else:
                user_login = Login(username=username, email=email, password=password, admin=admin)
                self.db.add(user_login)
                self.db.commit()
                return user_login
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"Error al crear el user password: {str(e)}")
        except Exception as e:
            logger.error(f"Error inesperado al crear el user password: {str(e)}")
    
    def get_user_login_id(self, user_name: str):
        """Obtiene el ID de un user login por username"""
        retries = 0
        while retries <= max_retries:
            try: 
                login = self.db.query(Login).filter(Login.username == user_name).first()
                return login.id
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente luego de {max_retries} intentos: {str(e)}")
                    raise
                # Cerrar y recrear la sesión
                self.close()
                self.db = SessionLocal()
            except Exception as e:
                logger.error(f"Error inesperado al obtener el ID del user login: {str(e)}")
                raise

# Servicios NotasMediaMensualParte
class NotasMediasDbService(BaseDBService):
    
    def get_notas_by_id(self, session, id_usuario: int):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(NotasMediaMensualParteCampus).filter(NotasMediaMensualParteCampus.id_usuario==id_usuario).order_by(asc(NotasMediaMensualParteAcademia.date)).all()
            except SQLAlchemyError as e: 
                    retries += 1 
                    logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                    if retries >= max_retries: 
                        logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                        raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener notas por ID: {str(e)}")
                raise
    
    def get_notas_by_id_y_parte(self, session, id_usuario,parte):
        retries = 0
        while retries < max_retries:
            try:
                return session.query(NotasMediaMensualParteCampus).filter(NotasMediaMensualParteCampus.id_usuario==id_usuario,NotasMediaMensualParteCampus.parte==parte).order_by(asc(NotasMediaMensualParteCampus.date)).all()
            except SQLAlchemyError as e: 
                    retries += 1 
                    logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}") 
                    if retries >= max_retries: 
                        logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}") 
                        raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener notas por ID y parte: {str(e)}")
                raise

class SubscriptionBDService(BaseDBService):
    def is_subscription_active(self, session, user_id: int):
        retries = 0
        while retries < max_retries:
            try:
                subscription = session.query(Subscripcion).filter(Subscripcion.user_id == user_id).first()
                return subscription is not None and subscription.active
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al comprobar la suscripción: {str(e)}")
                raise

    def get_subscription(self, session, user_id: int):
        retries = 0
        while retries < max_retries:
            try:    
                return session.query(Subscripcion).filter(Subscripcion.user_id == user_id).first()
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener la suscripción: {str(e)}")
                raise

    def create_subscription(self, user_id: int, stripe_subscription_id: str, cancel_at_period_end: bool):
        retries = 0
        while retries < max_retries:
            try:
                subscription = Subscripcion(stripe_subscription_id=stripe_subscription_id, user_id=user_id, cancel_at_period_end=cancel_at_period_end)
                self.db.add(subscription)
                self.db.commit()
                self.db.refresh(subscription)
                return subscription
            except SQLAlchemyError as e:
                self.db.rollback()
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                session.rollback()
                logger.error(f"Error inesperado al crear la suscripción: {str(e)}")
                raise

    def delete_subscription(self, session, user_id: int):
        retries = 0
        while retries < max_retries:
            try:
                subscription = session.query(Subscripcion).filter(Subscripcion.user_id == user_id).first()
                if subscription:
                    session.delete(subscription)
                    session.commit()
                    return True
                return False
            except SQLAlchemyError as e:
                session.rollback()
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                session.rollback()
                logger.error(f"Error inesperado al eliminar la suscripción: {str(e)}")
                raise

    def get_subscription_by_stripe_id(self, session, stripe_id: int) -> Subscripcion:
            retries = 0
            while retries < max_retries:
                try:    
                    return session.query(Subscripcion).filter(Subscripcion.stripe_subscription_id == stripe_id).first()
                except SQLAlchemyError as e:
                    retries += 1
                    logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                    if retries >= max_retries:
                        logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                        raise
                except Exception as e:
                    logger.error(f"Error inesperado al obtener la suscripción: {str(e)}")
                    raise

    def modify_subscription(self, session, stripe_id: int, active: bool, cancel_at_period_end: bool):
        retries = 0
        while retries < max_retries:
            try:
                subscription = session.query(Subscripcion).filter(Subscripcion.stripe_subscription_id == stripe_id).first()
                if subscription:
                    subscription.active = active
                    subscription.cancel_at_period_end = cancel_at_period_end
                    session.add(subscription)
                    session.commit()
                    return True
                return False
            except SQLAlchemyError as e:
                session.rollback()
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                session.rollback()
                logger.error(f"Error inesperado al eliminar la suscripción: {str(e)}")
                raise

class HistorialPagosDBService(BaseDBService):
    def get_historial_pagos(self, session, user_id: int):
        retries = 0
        while retries < max_retries:
            try:    
                return session.query(HistorialPagos).filter(HistorialPagos.user_id == user_id).all()
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener el historial de pagos: {str(e)}")
                raise

    def increase_months_subscribed(self, session, user_id: int):
        retries = 0
        while retries < max_retries:
            try:
                historial_pagos = session.query(HistorialPagos).filter(HistorialPagos.user_id == user_id).first()
                if historial_pagos:
                    historial_pagos.months_subscribed += 1
                    session.add(historial_pagos)
                    session.commit()
                    return True
                return False
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener el historial de pagos: {str(e)}")
                raise

    def create_pago(self, user_id: int):
        retries = 0
        while retries < max_retries:
            try:
                historial_pagos = HistorialPagos(user_id=user_id)
                self.db.add(historial_pagos)
                self.db.commit()
                return historial_pagos
            except SQLAlchemyError as e:
                self.db.rollback()
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                session.rollback()
                logger.error(f"Error inesperado al crear el pago: {str(e)}")
                raise

class OposicionDBService(BaseDBService):
    def get_oposicion_by_name(self, session, oposicion: str) -> Oposicion:
        retries = 0
        while retries < max_retries:
            try:
                return session.query(Oposicion).filter(Oposicion.name == oposicion).first()
            except SQLAlchemyError as e:
                retries += 1
                logger.warning(f"Reintento {retries}/{max_retries} debido a: {str(e)}")
                if retries >= max_retries:
                    logger.error(f"Error persistente después de {max_retries} intentos: {str(e)}")
                    raise
            except Exception as e:
                logger.error(f"Error inesperado al obtener oposición: {str(e)}")
                raise