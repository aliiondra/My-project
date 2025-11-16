import re
import logging
from typing import List, Dict, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ExamHTMLParser:
    # PROBAR A LIMITAR LAS PREGUNTAS QUE SALEN
    @staticmethod
    def parse_test_to_html(content: str) -> str:
        questions = []
        current_question = []
        question_count = 0
        
        lines = [line.strip() for line in content.strip().split('\n')]
        i = 0
        while i < len(lines):
            # Aquí es donde se limitan el numero de preguntas
            line = lines[i]
            if not line:
                i += 1
                continue
                
            # Si es una nueva pregunta (empieza con número y punto)
            if re.match(r'^\d+\.', line):
                if current_question:
                    html_question = ExamHTMLParser._format_question_html(current_question)
                    if html_question:
                        questions.append(html_question)
                        question_count += 1
                    current_question = []
                current_question.append(line)
            # Si es una opción (a, b, c, d)
            elif re.match(r'^[a-d]\)', line):
                current_question.append(line)
            i += 1
        
        if current_question:
            html_question = ExamHTMLParser._format_question_html(current_question)
            if html_question:
                questions.append(html_question)
                question_count += 1
        
        html = '<div class="questions-section">'
        html += '\n'.join(questions)
        html += '</div>'
        
        logger.info(f"Test parseado con {question_count} preguntas")
        return html

    @staticmethod
    def parse_case_to_html(content: str) -> Tuple[str, str]:
        """
        Convierte el contenido del caso práctico a formato HTML
        Retorna una tupla (caso_html, preguntas_html)
        Más robusto para diferentes formatos de casos prácticos
        """
        try:
            # Primero intentamos con el formato esperado (etiquetas explícitas)
            case_pattern = r'<caso_practico>\s*\[INICIO_CASO\](.*?)\[FIN_CASO\]\s*</caso_practico>'
            case_match = re.search(case_pattern, content, re.DOTALL)
            
            if not case_match:
                # Formato alternativo: solo etiquetas caso_practico sin INICIO/FIN
                alt_pattern = r'<caso_practico>(.*?)</caso_practico>'
                case_match = re.search(alt_pattern, content, re.DOTALL)
                
            # Extraemos las preguntas
            questions_pattern = r'<preguntas>(.*?)</preguntas>'
            questions_match = re.search(questions_pattern, content, re.DOTALL)
            
            # Si no encontramos el formato esperado para preguntas
            if not questions_match:
                # Intentar dividir el contenido en caso y preguntas automáticamente
                # Buscamos patrones como "1." que indican inicio de preguntas
                question_start_pattern = r'\n\s*1\.\s+'
                question_start_match = re.search(question_start_pattern, content)
                
                if question_start_match:
                    # Posición donde comienzan las preguntas
                    q_start_pos = question_start_match.start()
                    
                    # Si no tenemos caso definido, todo lo anterior a las preguntas es el caso
                    if not case_match:
                        case_content = content[:q_start_pos].strip()
                    else:
                        case_content = case_match.group(1).strip()
                        
                    # Las preguntas son todo lo que sigue
                    questions_text = content[q_start_pos:].strip()
                else:
                    # Si no podemos identificar automáticamente, mostrar error
                    if not case_match:
                        raise ValueError("No se encontró el caso práctico en el formato esperado")
                    if not questions_match:
                        raise ValueError("No se encontraron las preguntas en el formato esperado")
            else:
                # Si encontramos el formato estándar de preguntas
                questions_text = questions_match.group(1).strip()
                
                # Y si tenemos caso definido, lo usamos
                if case_match:
                    case_content = case_match.group(1).strip()
                else:
                    # Si tenemos preguntas pero no caso, el caso es todo lo anterior
                    q_start_pos = content.find('<preguntas>')
                    case_content = content[:q_start_pos].strip()
            
            # Verificación final
            if not case_content or not questions_text:
                raise ValueError("El caso práctico o las preguntas están vacías")
            
            # Eliminar etiquetas [INICIO_CASO] y [FIN_CASO] si existen
            case_content = re.sub(r'\[INICIO_CASO\]', '', case_content)
            case_content = re.sub(r'\[FIN_CASO\]', '', case_content)
            
            # Generamos HTML del caso preservando mejor el formato original
            case_html = '<div class="case-section">'
            
            # Preservar saltos de línea originales y formato de párrafos
            # Dividir por líneas y procesar manteniendo el formato original
            lines = case_content.split('\n')
            current_paragraph = []
            paragraphs = []
            
            for line in lines:
                line = line.rstrip()
                if not line.strip():  # Línea vacía indica nuevo párrafo
                    if current_paragraph:
                        paragraphs.append(' '.join(current_paragraph))
                        current_paragraph = []
                else:
                    current_paragraph.append(line)
            
            # No olvidar el último párrafo
            if current_paragraph:
                paragraphs.append(' '.join(current_paragraph))
            
            # Generar HTML con los párrafos
            for paragraph in paragraphs:
                paragraph = paragraph.strip()
                if paragraph:
                    case_html += f'<p class="case-paragraph">{paragraph}</p>'
            
            case_html += '</div>'
            
            # Parseamos las preguntas
            questions_html = ExamHTMLParser.parse_test_to_html(questions_text)
            
            logger.info("Caso práctico parseado correctamente")
            return case_html, questions_html
                
        except Exception as e:
            logger.error(f"Error al parsear caso práctico: {str(e)}")
            raise
        
    @staticmethod
    def _format_question_html(question_lines: List[str]) -> str:
        """
        Formatea una pregunta individual a HTML, asegurando que las opciones estén en orden alfabético
        """
        if not question_lines:
            return ""

        question_match = re.match(r'(\d+)\.\s*(.+)', question_lines[0])
        if not question_match:
            logger.warning(f"Formato de pregunta inválido: {question_lines[0]}")
            return ""

        number = question_match.group(1)
        text = question_match.group(2)
        question_id = f"q_{number}"

        html = f'<div class="question" data-question-id="{question_id}">'
        html += f'<div class="question-text">{number}. {text}</div>'
        html += '<div class="options-container">'

        # Recolectar todas las opciones primero
        options = {}
        for line in question_lines[1:]:
            option_match = re.match(r'([a-d])\)\s*(.+)', line)
            if option_match:
                letter = option_match.group(1)
                option_text = option_match.group(2)
                options[letter] = option_text
        
        # Generar el HTML para cada opción en orden alfabético
        for letter in ['a', 'b', 'c', 'd']:
            if letter in options:
                html += f'''
                    <div class="option" 
                         data-question-id="{question_id}" 
                         data-option="{letter}"
                         onclick="selectOption('{question_id}', '{letter}')">
                        <span class="option-letter">{letter})</span>
                        <span class="option-text">{options[letter]}</span>
                    </div>'''

        html += f'''
                <div class="option blank" 
                     data-question-id="{question_id}"
                     data-option="blank"
                     onclick="selectOption('{question_id}', 'blank')">
                    <span class="option-text">Marcar "en blanco"</span>
                </div>
                <div class="correction-text" id="correction_{question_id}"></div>
            </div>
        </div>'''
        
        return html

    @staticmethod
    def format_correction(correction_content: str) -> Dict[str, str]:
        """
        Formatea el contenido de la corrección
        
        Args:
            correction_content: Contenido de la corrección en formato texto
            
        Returns:
            Diccionario con las correcciones formateadas por número de pregunta
        """
        corrections = {}
        current_question = None
        correction_text = []
        
        for line in correction_content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            question_match = re.match(r'\[(\d+)\]\[([a-d])\]', line)
            if question_match:
                if current_question and correction_text:
                    corrections[current_question] = '\n'.join(correction_text)
                
                current_question = question_match.group(1)
                correction_text = [line]
                continue
            
            correction_text.append(line)
        
        if current_question and correction_text:
            corrections[current_question] = '\n'.join(correction_text)
        
        return corrections