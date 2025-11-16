from database import *
from tablas import *
from werkzeug.security import generate_password_hash, check_password_hash
import json

# Inicializar la base de datos
def init_db():
    Base.metadata.create_all(bind=engine)

SessionLocal = sessionmaker(bind=engine)

# Función principal para pruebas
def main():
    """ Función para poblar la base de datos con datos de prueba """
    with SessionLocal() as session:
        try:
            # Crear corrección
            
            # Crear instancias de las correcciones
            cor1 = Correction(exam_id=10, correction_content="Corrección del examen 1")
            cor2 = Correction(exam_id=11, correction_content="Corrección del examen 2")
            cor3 = Correction(exam_id=12, correction_content="Corrección del examen 3")

            # Crear instancias de los exámenes
            test1 = Exam(part="part", content="content", context="context", examinator_id=1, total_preguntas=50)
            test2 = Exam(part="part", content="content", context="context", examinator_id=1, total_preguntas=50)
            test3 = Exam(part="part", content="content", context="context", examinator_id=1, total_preguntas=50)

            # Añadir a la sesión
            session.add_all([test1, test2, test3])
            session.add_all([cor1, cor2, cor3])

            # Confirmar los cambios en la base de datos
            session.commit()

            print("Base de datos poblada correctamente.")


            print("Base de datos poblada correctamente.")

        except Exception as e:
            session.rollback()
            print(f"Error al poblar la base de datos: {e}")
    
if __name__ == "__main__":
    init_db()
    main()

