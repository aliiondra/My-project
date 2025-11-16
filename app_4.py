from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g, send_file
from services_usuarios import * 
from werkzeug.security import generate_password_hash, check_password_hash
from database import SessionLocal, check_database_connection, engine
from datetime import timedelta, datetime
from parse_to_html import ExamHTMLParser
from io import BytesIO
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func, text
from tablas import Exam, Correction, Base
from flask_mail import Mail, Message
from functools import wraps

import stripe, uuid
import logging, traceback, os, json, time, sys, string, unicodedata, random,secrets
import jwt as pyjwt
from pathlib import Path

# Set your Stripe API key
stripe.api_key = "sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Replace with your actual Stripe secret key
STRIPE_WEBHOOK_SECRET = "whsec_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Replace with your webhook secret

PLAN_PRICES = {
    "mensual_gestion": "price_test_xxxxxxx_GESTION_MONTHLY",
    "trimestral_gestion": "price_test_xxxxxxx_GESTION_TRIMESTRAL",
    "mensual_admin": "price_test_xxxxxxx_ADMIN_MONTHLY",
    "trimestral_admin": "price_test_xxxxxxx_ADMIN_TRIMESTRAL",
}

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Activado para desarrollo local
app.secret_key = os.environ.get('SECRET_KEY', "SJVIF645hhr65876lh")  # Usa variable de entorno en producción
app.permanent_session_lifetime = timedelta(days=7)
app.config['TIMEOUT'] = 3600  # 1hora

# Configuración de logging para entorno local
log_directory = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(log_directory, "app.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Para módulos específicos, mantener nivel de log restrictivo
logging.getLogger('services_usuarios').setLevel(logging.INFO)

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.hostinger.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'noreply@my-project-domain.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'MAIL_PASSWORD_HERE')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@my-project-domain.com')

mail = Mail(app)

# Decorador para registro de tiempo de ejecución
def log_execution_time(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        try:
            result = f(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.info(f"[TIEMPO] {f.__name__} completado en {execution_time:.4f}s")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"[ERROR] {f.__name__} falló después de {execution_time:.4f}s: {str(e)}")
            raise
    return decorated_function

# Decorador para verificar que el usuario está autenticado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'id_login' not in session:
            flash('Inicie sesión para acceder a esta página', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_active(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('is_active') == False:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Inicialización de los servicios de forma lazy
def get_user_service(): 
    if not hasattr(g, 'user_service'): 
        g.user_service = UserDBService() 
    return g.user_service

def get_tutor_service(): 
    if not hasattr(g, 'tutor_service'): 
        g.tutor_service = TutorDBService() 
    return g.tutor_service

def get_examinator_service(): 
    if not hasattr(g, 'examinator_service'): 
        g.examinator_service = ExaminatorDBService() 
    return g.examinator_service

def get_exam_service(): 
    if not hasattr(g, 'exam_service'): 
        g.exam_service = ExamDBService() 
    return g.exam_service

def get_login_service(): 
    if not hasattr(g, 'login_service'): 
        g.login_service = LoginDBService() 
    return g.login_service

def get_notas_service(): 
    if not hasattr(g, 'notas_service'): 
        g.notas_service = NotasMediasDbService() 
    return g.notas_service

def get_oposicion_service(): 
    if not hasattr(g, 'oposicion_service'): 
        g.oposicion_service = OposicionDBService() 
    return g.oposicion_service

def get_subscription_service():
    if not hasattr(g, 'subscription_service'):
        g.subscription_service = SubscriptionBDService()
    return g.subscription_service

def get_historial_pagos_service():
    if not hasattr(g, 'historial_pago_service'):
        g.historial_pago_service = HistorialPagosDBService()
    return g.historial_pago_service

def get_db_session(): 
    if not hasattr(g, 'db_session'): 
        g.db_session = SessionLocal() 
    return g.db_session

#Función decorativa que comprueba si el usuario tiene acceso o no a la página
def check_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        sub = session.get('subscription')
        trial = session.get('trial')
        if sub == 1:
            return f(*args, **kwargs)
        if trial == 1:
            return f(*args, **kwargs)
        return redirect(url_for('subscripcion_caducada'))
    return decorated_function

#Función decorativa que comprueba si la subscripción del usuario está activa
def check_sub(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        sub = session.get('subscription')
        if sub == 1:
            return f(*args, **kwargs)
        return redirect(url_for('subscripcion_caducada'))
    return decorated_function

def get_client_ip():
    """Obtiene la IP real del cliente considerando proxies"""
    if request.headers.getlist("X-Forwarded-For"):
        # Lista de IPs en caso de proxy, usamos la primera (cliente original)
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    return ip

# Configuración de la base de datos
def init_db():
    """Inicializa la base de datos con manejo de errores mejorado para AWS RDS."""
    try:
        # Verificar conexión a la base de datos RDS
        logger.info("Verificando conexión a AWS RDS...")
        if not check_database_connection(max_retries=3, delay=2):
            logger.critical("No se pudo conectar a la base de datos RDS después de varios intentos")
            print("\n" + "="*80)
            print("ERROR DE CONEXIÓN A AWS RDS")
            print("="*80)
            print("Asegúrate de tener acceso a la instancia RDS:")
            print("1. Verifica que puedas acceder al punto de enlace: your-generic-rds-endpoint.com")
            print("2. Comprueba que el grupo de seguridad de RDS permite tu IP")
            print("3. Verifica que las credenciales son correctas")
            print("="*80 + "\n")
            return False
            
        # Intentar crear las tablas
        logger.info("Iniciando creación de tablas en AWS RDS...")
        Base.metadata.create_all(bind=engine)
        
        # Verificar si la columna multidominio existe en la tabla users
        try:
            with engine.connect() as conn:
                # Comprobar si la columna multidominio existe
                result = conn.execute(text("SHOW COLUMNS FROM users LIKE 'multidominio'"))
                column_exists = result.fetchone() is not None
                
                # Si la columna no existe, crearla
                if not column_exists:
                    logger.info("La columna 'multidominio' no existe en la tabla users. Creándola...")
                    conn.execute(text("ALTER TABLE users ADD COLUMN multidominio SMALLINT DEFAULT 0"))
                    logger.info("Columna 'multidominio' creada correctamente.")
        except Exception as e:
            logger.error(f"Error al verificar/crear la columna multidominio: {str(e)}")
            
        logger.info("Tablas creadas o verificadas correctamente en AWS RDS")
        return True
    except Exception as e:
        logger.critical(f"Error al inicializar la base de datos RDS: {str(e)}")
        print(f"\nERROR: No se pudo inicializar la base de datos: {str(e)}\n")
        return False

# Inicializar la base de datos durante el arranque 
with app.app_context(): 
    db_initialized = init_db()
    if not db_initialized:
        logger.warning("La aplicación continuará ejecutándose, pero podrían ocurrir errores de base de datos")

# Ruta de inicio
@app.route('/home')
def home():
    return render_template('opo345.html')

# Ruta de login
@app.route("/")
def index():
    if 'id_login' in session:
        return redirect(url_for('get_examinadoras_by_user'))
    return redirect(url_for("home"))

# Función para normalizar texto
def normalizar_texto(texto):
    texto = unicodedata.normalize('NFD', texto)  # Descompone caracteres especiales y tildes
    texto = ''.join(c for c in texto if unicodedata.category(c) != 'Mn')  # Elimina marcas diacríticas
    texto = texto.encode('ascii', 'ignore').decode('utf-8')  # Convierte a ASCII, eliminando caracteres no estándar
    return texto

# Función para generar un username
def generar_username(user_id, temp_user=None):
    if temp_user:
        user = temp_user
    else:
        user = get_user_service().get_user(user_id)
    print(user.name)
    print(user.first_surname)
    print(user.second_surname)
    print(user.id)
    
    name = normalizar_texto(user.name[:2])
    first_surname = normalizar_texto(user.first_surname[:2])
    second_surname = normalizar_texto(user.second_surname[:2])
    
    return (name + first_surname + second_surname + "_" + str(user.id)).lower()

# Keep track of pending registrations
pending_registrations = {}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Collect form data
        name = request.form.get('register-name')
        surnames = request.form.get('register-surname')
        email = request.form.get('register-email')
        phone = request.form.get('register-phone')
        oposicion_value = request.form.get('register-oposicion')
        password = request.form.get('register-password')
        province = request.form.get('register-province')
        city = request.form.get('register-city')
        first_surname, second_surname = (surnames.split() + [""])[:2]

        # Map oposicion
        oposicion_map = {
            "gestion": "Cuerpo de Gestión de la Administración Civil del Estado",
            "administrativo": "Cuerpo General Administrativo de la Administración del Estado"
        }
        oposicion_name = oposicion_map.get(oposicion_value)

        registration_id = str(uuid.uuid4())
        session['registration_id'] = registration_id

        selected_plan = request.form.get('selected-plan')
        price_id = PLAN_PRICES.get(selected_plan)

        existing_user = get_user_service().get_user_by_email(email=email)
        try:
            if existing_user:
                stripe_customer_id = existing_user.stripe_customer_id
                if not stripe_customer_id:
                    flash("El usuario ya existe pero no tiene cliente de Stripe asignado.", "warning")
                    return redirect(url_for("register"))

                checkout_session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=[{'price': price_id, 'quantity': 1}],
                    mode='subscription',
                    success_url=url_for('payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
                    cancel_url=url_for('payment_cancel', _external=True),
                    client_reference_id=registration_id,
                    customer=stripe_customer_id
                )
            else:
                pending_registrations[registration_id] = {
                    'name': name,
                    'first_surname': first_surname,
                    'second_surname': second_surname,
                    'email': email,
                    'phone': phone,
                    'oposicion_value': oposicion_value,
                    'oposicion_name': oposicion_name,
                    'password': password,
                    'province': province,
                    'city': city,
                    'created_at': datetime.now()
                }

                checkout_session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=[{'price': price_id, 'quantity': 1}],
                    mode='subscription',
                    success_url=url_for('payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
                    cancel_url=url_for('payment_cancel', _external=True),
                    client_reference_id=registration_id,
                    customer_email=email
                )

            return redirect(checkout_session.url)

        except Exception as e:
            flash(f"❌ Error al procesar el pago: {str(e)}", "danger")
            return redirect(url_for("register"))

    # Si no es POST
    return redirect(url_for("register"))


# Ruta de éxito del pago
@app.route('/payment/success')
def payment_success():
    session_id = request.args.get('session_id')
    
    # Verify the payment was successful
    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        
        # Get the registration data using the stored ID
        registration_id = session.get('registration_id')
        if not registration_id or registration_id not in pending_registrations:
            flash("❌ No se encontró información de registro", "danger")
            return redirect(url_for("register"))
        
        registration_data = pending_registrations[registration_id]
        
        # Process the successful registration
        with session_scope() as db_session:
            # Get next user ID
            next_id = get_user_service().get_next_id()
            temp_user = UserCampus(
                id=next_id, 
                name=registration_data['name'], 
                first_surname=registration_data['first_surname'], 
                second_surname=registration_data['second_surname']
            )

            # Generate username
            username = generar_username(next_id, temp_user)

            # Encrypt password
            hashed_password = generate_password_hash(registration_data['password'])

            # Create login
            get_login_service().create_login(username, registration_data['email'], hashed_password, False)
            id_login = get_login_service().get_user_login_id(username)

            if id_login is None:
                flash("❌ Error al crear el usuario", "danger")
                return redirect(url_for("register"))

            # Get oposicion and examinator
            oposicion = get_oposicion_service().get_oposicion_by_name(db_session, registration_data['oposicion_name'])
            examinador = get_examinator_service().get_examinator_by_oposicion_id(db_session, oposicion.id)
            
            # Create user
            user = get_user_service().create_user(
                name=registration_data['name'],
                first_surname=registration_data['first_surname'],
                second_surname=registration_data['second_surname'],
                email=registration_data['email'],
                phone=registration_data['phone'],
                province=registration_data['province'],
                city=registration_data['city'],
                examinator_id=examinador.id,
                login_id=id_login
            )

            # Create subscription with Stripe subscription ID
            get_subscription_service().create_subscription(
                user_id=user.id, 
                stripe_subscription_id=checkout_session.subscription, 
                active=True, 
                cancel_at_period_end=False
            )

            # Create payment record
            get_historial_pagos_service().create_pago(
                user_id=user.id
            )

            # Send welcome email
            send_welcome_email(
                name=registration_data['name'],
                email=registration_data['email'],
                username=username
            )
            
            # Clear the registration data
            del pending_registrations[registration_id]
            session.pop('registration_id', None)
            
            flash("¡Registro completado con éxito! Se ha enviado un correo con tus datos de acceso.", "success")
            return render_template('success.html', name=registration_data['name'])
    
    except Exception as e:
        flash(f"❌ Error al verificar el pago: {str(e)}", "danger")
        return redirect(url_for('home') + '#pricing')

# Ruta de cancelación del pago
@app.route('/payment/cancel')
def payment_cancel():
    flash("El proceso de pago ha sido cancelado.", "warning")
    return redirect(url_for('home') + '#pricing')

#Ruta de webhooks de Stripe
@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        # Invalid payload
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return "Invalid signature", 400

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        handle_checkout_session_completed(session)
    elif event['type'] == 'invoice.paid':
        invoice = event['data']['object']
        handle_invoice_paid(invoice)
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        handle_subscription_deleted(subscription)

    return "", 200

# Función para manejar el pago
def handle_checkout_session_completed(session):
    # This function can be used as a backup in case the user 
    # doesn't return to your site after payment
    client_reference_id = session.get('client_reference_id')
    if client_reference_id and client_reference_id in pending_registrations:
        # Process registration in background
        # This is optional as we already handle it in payment_success
        pass

# Función para manejar el pago recurrente
def handle_invoice_paid(invoice):
    # Update subscription status for recurring payments
    subscription_id = invoice.get('subscription')
    if subscription_id:
        with session_scope() as db_session:
            subscription = get_subscription_service().get_subscription_by_stripe_id(db_session, subscription_id)
            if subscription:
                get_subscription_service().modify_subscription(session=db_session,stripe_id=subscription.id,active= True, cancel_at_period_end=False)
                user_id = get_subscription_service().get_subscription_by_stripe_id(session=db_session,stripe_id=subscription.id).user_id
                get_historial_pagos_service().increase_months_subscribed(session=db_session,user_id=user_id)
            return

# Función para manejar la cancelación de la suscripción
def handle_subscription_deleted(subscription):
    # Handle when a subscription is canceled
    subscription_id = subscription.get('id')
    if subscription_id:
        with session_scope() as db_session:
            subscription = get_subscription_service().get_subscription_by_stripe_id(db_session, subscription_id)
            if subscription:
                get_subscription_service().modify_subscription(db_session, subscription.id, active= False, cancel_at_period_end=True)
            return

# Función para enviar el correo de bienvenida
def send_welcome_email(name, email, username):
    msg = Message('¡Bienvenido a MY-PROJECT! Tu cuenta ha sido creada con éxito', recipients=[email])
    msg.body = f"""
    Hola {name},

    ¡Bienvenido a MY-PROJECT! Tu cuenta ha sido creada con éxito.

    Datos de acceso:
    • Usuario: {username}
    • Contraseña: La que estableciste durante el registro

    Puedes acceder directamente al Campus Virtual en: my-project-domain.com/login

    Recuerda que en MY-PROJECT encontrarás simulacros interactivos actualizados en menos de 48h tras cada publicación en el BOE, con retroalimentación jurídica detallada para cada respuesta.

    Si necesitas ayuda, no dudes en contactar con nuestro equipo de soporte en comunicaciones@my-project.com

    ¡Te deseamos mucho éxito en tu preparación!

    El equipo de MY-PROJECT
    """

    msg.html = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bienvenido a MY-PROJECT</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700;800&family=Inter:wght@300;400;500;600&display=swap');
            
            body {{
                font-family: 'Inter', sans-serif;
                line-height: 1.65;
                color: #374151;
                margin: 0;
                padding: 0;
                background-color: #F9FAFB;
            }}
            
            .email-container {{
                max-width: 600px;
                margin: 0 auto;
                background-color: #FFFFFF;
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
            }}
            
            .email-header {{
                background: linear-gradient(135deg, #4979C0 0%, #2A5898 100%);
                color: white;
                padding: 30px 20px;
                text-align: center;
            }}
            
            .email-header h1 {{
                font-family: 'Montserrat', sans-serif;
                font-weight: 800;
                font-size: 24px;
                margin: 0;
                letter-spacing: -0.02em;
            }}
            
            .email-body {{
                padding: 30px 25px;
            }}
            
            .welcome-text {{
                font-size: 18px;
                margin-bottom: 25px;
                color: #1F2937;
            }}
            
            .credentials-box {{
                background-color: #EBF2FF;
                border-left: 4px solid #4979C0;
                padding: 20px 25px;
                border-radius: 8px;
                margin-bottom: 25px;
            }}
            
            .credentials-box h3 {{
                font-family: 'Montserrat', sans-serif;
                color: #2A5898;
                margin-top: 0;
                margin-bottom: 15px;
                font-weight: 600;
                font-size: 16px;
            }}
            
            .credentials-item {{
                margin-bottom: 10px;
                display: flex;
            }}
            
            .credentials-item strong {{
                width: 100px;
                font-weight: 600;
                color: #4B5563;
            }}
            
            .access-button {{
                display: block;
                background: linear-gradient(135deg, #F0A830, #D98C23);
                color: white;
                text-decoration: none;
                text-align: center;
                padding: 16px 20px;
                border-radius: 8px;
                font-weight: 600;
                font-size: 16px;
                margin: 30px 0;
                transition: all 0.3s ease;
            }}
            
            .feature-box {{
                background-color: #F3F4F6;
                border-radius: 8px;
                padding: 20px;
                margin-top: 25px;
            }}
            
            .feature-box h3 {{
                font-family: 'Montserrat', sans-serif;
                color: #122550;
                margin-top: 0;
                font-size: 16px;
                font-weight: 600;
            }}
            
            .feature-item {{
                display: flex;
                margin-bottom: 12px;
            }}
            
            .feature-item i {{
                color: #4979C0;
                margin-right: 10px;
                flex-shrink: 0;
            }}
            
            .support-text {{
                margin-top: 25px;
                font-size: 15px;
                color: #6B7280;
            }}
            
            .email-footer {{
                background-color: #F3F4F6;
                padding: 20px;
                text-align: center;
                font-size: 14px;
                color: #6B7280;
                border-top: 1px solid #E5E7EB;
            }}
        </style>
    </head>
    <body>
        <div class="email-container">
            <div class="email-header">
                <h1>¡Tu cuenta ha sido creada con éxito!</h1>
            </div>
            
            <div class="email-body">
                <p class="welcome-text">¡Hola <strong>{name}</strong>!</p>
                <p>Gracias por registrarte en MY-PROJECT. Tu cuenta ha sido creada correctamente y ya puedes comenzar tu preparación para las oposiciones a la Administración General del Estado.</p>
                
                <div class="credentials-box">
                    <h3>DATOS DE ACCESO</h3>
                    <div class="credentials-item">
                        <strong>Usuario:</strong> <span>{username}</span>
                    </div>
                    <div class="credentials-item">
                        <strong>Contraseña:</strong> <span>La que estableciste durante el registro</span>
                    </div>
                </div>
                
                <a href="https://my-project-domain.com/login" class="access-button">ACCEDER AL CAMPUS VIRTUAL</a>
                
                <div class="feature-box">
                    <h3>TU PREPARACIÓN INCLUYE:</h3>
                    <div class="feature-item">
                        <i>✓</i>
                        <span>Simulacros interactivos actualizados en menos de 48h tras publicación en BOE</span>
                    </div>
                    <div class="feature-item">
                        <i>✓</i>
                        <span>Retroalimentación jurídica detallada para cada respuesta</span>
                    </div>
                    <div class="feature-item">
                        <i>✓</i>
                        <span>Miles de tests por bloques temáticos y temas específicos</span>
                    </div>
                    <div class="feature-item">
                        <i>✓</i>
                        <span>Análisis de progreso con estadísticas de evaluación</span>
                    </div>
                </div>
                
                <p class="support-text">Si tienes cualquier duda o necesitas ayuda, no dudes en contactar con nuestro equipo de soporte en <a href="mailto:comunicaciones@my-project.com">comunicaciones@my-project.com</a>.</p>
                
                <p>¡Te deseamos mucho éxito en tu preparación!</p>
                
                <p><strong>El equipo de MY-PROJECT</strong></p>
            </div>
            
            <div class="email-footer">
                <p>© 2025 MY-PROJECT. Todos los derechos reservados.</p>
            </div>
        </div>
    </body>
    </html>
    """
    mail.send(msg)

# Ruta para la cancelación de la subscripción
@app.route('/payment/cancelar_sub', methods=['POST'])
def cancelar_subscripcion():
    if request.method == 'POST':
        with session_scope() as db_session:
            try:
                user_id = get_user_service().get_user(session=db_session,user_id=session.get('id_user')).user_id
                sub_stripe_id = get_subscription_service().get_subscription(session=db_session,user_id=user_id).stripe_subscription_id
                stripe.Subscription.modify(sub_stripe_id,cancel_at_period_end=True)
                #TODO Introducir un mensaje a modo de feedback para que se confirme la cancelación de la subscripción
                return redirect(url_for('perfil'))
            except:
                flash('Problema al cancelar la subscripción porfavor contacte con servicio al cliente')
                return redirect(url_for('perfil'))

# Ruta para que un nuevo usuario se registre 
@app.route('/registro_prueba_gratuita', methods=['GET', 'POST'])
def registro_prueba_gratuita():
    if request.method == 'POST':
        name = request.form.get('register-name')
        surnames = request.form.get('register-surname')
        email = request.form.get('register-email')
        phone = request.form.get('register-phone')
        oposicion_value = request.form.get('register-oposicion')
        password = request.form.get('register-password')
        province = request.form.get('register-province')
        city = request.form.get('register-city')
        first_surname, second_surname = (surnames.split() + [""])[:2]

        oposicion_map = {
            "gestion": "Cuerpo de Gestión de la Administración Civil del Estado",
            "administrativo": "Cuerpo General Administrativo de la Administración del Estado"
        }
        oposicion_name = oposicion_map.get(oposicion_value)
        print(str(oposicion_name))

        with session_scope() as db_session:
            next_id = get_user_service().get_next_id()
            temp_user = UserCampus(id=next_id, name=name, first_surname=first_surname, second_surname=second_surname)

            # Generar username
            username = generar_username(next_id, temp_user)

            #Encriptar contraseña
            hashed_password = generate_password_hash(password)

            # Crear login
            get_login_service().create_login(username, email, hashed_password, False)
            id_login = get_login_service().get_user_login_id(username)

            if id_login is None:
                flash("❌ Error al crear el usuario", "danger")
                return redirect(url_for("agregar_usuario"))

            oposicion = get_oposicion_service().get_oposicion_by_name(db_session, oposicion_name)
            print(str(oposicion))
            examinador = get_examinator_service().get_examinator_by_oposicion_id(db_session, oposicion.id)
            
            # Crear usuario
            user = get_user_service().create_user(
                name=name,
                first_surname=first_surname,
                second_surname=second_surname,
                email=email,
                phone=phone,
                province=province,
                city=city,
                examinator_id=examinador.id,
                login_id=id_login
            )

            # Crear la suscripcion
            get_subscription_service().create_subscription(user_id=user.id, stripe_subscription_id="aaa", cancel_at_period_end=False)

            msg = Message('¡Bienvenido a MY-PROJECT! Tu cuenta ha sido creada con éxito', recipients=[email])
            msg.body = f"""
            Hola {name},

            ¡Bienvenido a MY-PROJECT! Tu cuenta ha sido creada con éxito.

            Datos de acceso:
            • Usuario: {username}
            • Contraseña: La que estableciste durante el registro

            Puedes acceder directamente al Campus Virtual en: my-project-domain.com/login

            Recuerda que en MY-PROJECT encontrarás simulacros interactivos actualizados en menos de 48h tras cada publicación en el BOE, con retroalimentación jurídica detallada para cada respuesta.

            Si necesitas ayuda, no dudes en contactar con nuestro equipo de soporte en comunicaciones@my-project.com

            ¡Te deseamos mucho éxito en tu preparación!

            El equipo de MY-PROJECT
            """

            msg.html = f"""
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Bienvenido a MY-PROJECT</title>
                <style>
                    @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700;800&family=Inter:wght@300;400;500;600&display=swap');
                    
                    body {{
                        font-family: 'Inter', sans-serif;
                        line-height: 1.65;
                        color: #374151;
                        margin: 0;
                        padding: 0;
                        background-color: #F9FAFB;
                    }}
                    
                    .email-container {{
                        max-width: 600px;
                        margin: 0 auto;
                        background-color: #FFFFFF;
                        border-radius: 10px;
                        overflow: hidden;
                        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                    }}
                    
                    .email-header {{
                        background: linear-gradient(135deg, #4979C0 0%, #2A5898 100%);
                        color: white;
                        padding: 30px 20px;
                        text-align: center;
                    }}
                    
                    .email-header h1 {{
                        font-family: 'Montserrat', sans-serif;
                        font-weight: 800;
                        font-size: 24px;
                        margin: 0;
                        letter-spacing: -0.02em;
                    }}
                    
                    .email-body {{
                        padding: 30px 25px;
                    }}
                    
                    .welcome-text {{
                        font-size: 18px;
                        margin-bottom: 25px;
                        color: #1F2937;
                    }}
                    
                    .credentials-box {{
                        background-color: #EBF2FF;
                        border-left: 4px solid #4979C0;
                        padding: 20px 25px;
                        border-radius: 8px;
                        margin-bottom: 25px;
                    }}
                    
                    .credentials-box h3 {{
                        font-family: 'Montserrat', sans-serif;
                        color: #2A5898;
                        margin-top: 0;
                        margin-bottom: 15px;
                        font-weight: 600;
                        font-size: 16px;
                    }}
                    
                    .credentials-item {{
                        margin-bottom: 10px;
                        display: flex;
                    }}
                    
                    .credentials-item strong {{
                        width: 100px;
                        font-weight: 600;
                        color: #4B5563;
                    }}
                    
                    .access-button {{
                        display: block;
                        background: linear-gradient(135deg, #F0A830, #D98C23);
                        color: white;
                        text-decoration: none;
                        text-align: center;
                        padding: 16px 20px;
                        border-radius: 8px;
                        font-weight: 600;
                        font-size: 16px;
                        margin: 30px 0;
                        transition: all 0.3s ease;
                    }}
                    
                    .feature-box {{
                        background-color: #F3F4F6;
                        border-radius: 8px;
                        padding: 20px;
                        margin-top: 25px;
                    }}
                    
                    .feature-box h3 {{
                        font-family: 'Montserrat', sans-serif;
                        color: #122550;
                        margin-top: 0;
                        font-size: 16px;
                        font-weight: 600;
                    }}
                    
                    .feature-item {{
                        display: flex;
                        margin-bottom: 12px;
                    }}
                    
                    .feature-item i {{
                        color: #4979C0;
                        margin-right: 10px;
                        flex-shrink: 0;
                    }}
                    
                    .support-text {{
                        margin-top: 25px;
                        font-size: 15px;
                        color: #6B7280;
                    }}
                    
                    .email-footer {{
                        background-color: #F3F4F6;
                        padding: 20px;
                        text-align: center;
                        font-size: 14px;
                        color: #6B7280;
                        border-top: 1px solid #E5E7EB;
                    }}
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="email-header">
                        <h1>¡Tu cuenta ha sido creada con éxito!</h1>
                    </div>
                    
                    <div class="email-body">
                        <p class="welcome-text">¡Hola <strong>{name}</strong>!</p>
                        <p>Gracias por registrarte en MY-PROJECT. Tu cuenta ha sido creada correctamente y ya puedes comenzar tu preparación para las oposiciones a la Administración General del Estado.</p>
                        
                        <div class="credentials-box">
                            <h3>DATOS DE ACCESO</h3>
                            <div class="credentials-item">
                                <strong>Usuario:</strong> <span>{username}</span>
                            </div>
                            <div class="credentials-item">
                                <strong>Contraseña:</strong> <span>La que estableciste durante el registro</span>
                            </div>
                        </div>
                        
                        <a href="https://my-project-domain.com/login" class="access-button">ACCEDER AL CAMPUS VIRTUAL</a>
                        
                        <div class="feature-box">
                            <h3>TU PREPARACIÓN INCLUYE:</h3>
                            <div class="feature-item">
                                <i>✓</i>
                                <span>Simulacros interactivos actualizados en menos de 48h tras publicación en BOE</span>
                            </div>
                            <div class="feature-item">
                                <i>✓</i>
                                <span>Retroalimentación jurídica detallada para cada respuesta</span>
                            </div>
                            <div class="feature-item">
                                <i>✓</i>
                                <span>Miles de tests por bloques temáticos y temas específicos</span>
                            </div>
                            <div class="feature-item">
                                <i>✓</i>
                                <span>Análisis de progreso con estadísticas de evaluación</span>
                            </div>
                        </div>
                        
                        <p class="support-text">Si tienes cualquier duda o necesitas ayuda, no dudes en contactar con nuestro equipo de soporte en <a href="mailto:comunicaciones@my-project.com">comunicaciones@my-project.com</a>.</p>
                        
                        <p>¡Te deseamos mucho éxito en tu preparación!</p>
                        
                        <p><strong>El equipo de MY-PROJECT</strong></p>
                    </div>
                    
                    <div class="email-footer">
                        <p>© 2025 MY-PROJECT. Todos los derechos reservados.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            mail.send(msg)

        flash("Usuario registrado correctamente.")
        return redirect(url_for('login'))

    return render_template('home.html')

# Ruta para mostrar la página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Limpiar la sesión
        session.clear()
        session.modified = True
        # Obtener los datos del formulario
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = request.remote_addr
  
        # Usar session_scope para interactuar con la base de datos
        with session_scope() as db_session:
            try:
                # Obtener el login de la base de datos
                login = get_login_service().get_user_login_by_username(db_session, username)
                
                if not login:
                    # Login no encontrado
                    logger.warning(f"Usuario no encontrado: {username}")
                    flash("Usuario no encontrado", 'error')
                    return redirect(url_for('login'))
                # Verificar la contraseña
                if not check_password_hash(login.password, password):
                    # Contraseña incorrecta
                    logger.warning(f"Contraseña incorrecta para usuario: {username}")
                    flash("Contraseña incorrecta", 'error')
                    return redirect(url_for('login'))
                # Obtener el usuario asociado al login
                user = get_user_service().get_user_by_login_id(db_session, login.id)

                # Si no hay usuario asociado, mostrar un mensaje específico
                if not user:
                    logger.error(f"Usuario no encontrado para login_id: {login.id}")
                    flash("Credenciales válidas, pero la cuenta de usuario no está configurada. Contacte al administrador.", 'error')
                    return redirect(url_for('login'))
                
                if get_login_service().maximo_ips(session=db_session, user_id=user.id):
                
                    # Verificar si la IP ya está registrada
                    if not get_login_service().check_ip(session=db_session, user_id=user.id, client_ip=client_ip):
                        flash("IP no válida o no registrada", 'error')
                        return redirect(url_for('login'))
                    else:
                        session['id_login'] = login.id
                        session['id_user'] = user.id
                        subscription = get_subscription_service().get_subscription(db_session, user.id)
                        session['subscription'] = subscription.active
                        session['trial'] = user.is_trial
                        session['is_active'] = bool(user.is_active)
                        session['first_exam'] = True
                        if user.examinator_id:
                            session['examinator_id'] = user.examinator_id
                        return redirect(url_for('get_examinadoras_by_user'))
                else:
                    if not get_login_service().check_ip(session=db_session, user_id=user.id, client_ip=client_ip):
                        get_login_service().save_user_ip(session=db_session, user_id=user.id, client_ip=client_ip)
                    session['id_login'] = login.id
                    session['id_user'] = user.id
                    subscription = get_subscription_service().get_subscription(db_session, user.id)
                    session['subscription'] = subscription.active
                    session['trial'] = user.is_trial
                    session['is_active'] = bool(user.is_active)
                    session['first_exam'] = True
                    if user.examinator_id:
                        session['examinator_id'] = user.examinator_id
                    return redirect(url_for('get_examinadoras_by_user'))
                    
            except Exception as e:
                logger.error(f"Error en el proceso de login: {str(e)}")
                print(f"Error en el proceso de login: {str(e)}")
                flash("Error en el sistema. Por favor, inténtelo más tarde.", 'error')
                return redirect(url_for('login'))

    # Si no es una solicitud POST, mostrar el formulario de login
    return render_template('login.html')

# Ruta para mostrar la página de examinadoras
@app.route('/examinadoras')
@login_required
@is_active
@check_access
@log_execution_time
def get_examinadoras_by_user():
    try:
        login_id = session.get('id_login')
        if not login_id:
            logger.warning("Usuario no autenticado, redirigiendo al login.")
            return redirect(url_for('login'))
        
        with session_scope() as db_session:
            user_id = session.get('id_user')

            user = None
            if user_id:
                user = get_user_service().get_user(db_session, user_id)
            if not user:
                user = get_user_service().get_user_by_login_id(db_session, login_id)

            if not user:
                logger.error(f"No se encontró usuario con login_id={login_id} o user_id={user_id}")
                session.clear()
                flash("Usuario no encontrado", 'error')
                return redirect(url_for('login'))

            session['id_user'] = user.id
            if user.examinator_id:
                session['examinator_id'] = user.examinator_id

            examinators = get_examinator_service().get_all_examinators_by_user(
                db_session,
                examinator_id=user.examinator_id,
                admin=session.get('admin', False)
            )

            if not examinators:
                logger.warning(f"No se encontraron examinadores para user_id={user.id}")
                flash("No se encontraron examinadores disponibles", 'warning')
            
            if session.get('subscription') == True:
                return render_template('examinadoras_usuarios.html', examinators=examinators)
            elif user.is_trial == True:
                return render_template('examinadoras_usuarios_trial.html',examinators=examinators)
            else:
                return redirect(url_for('subscripcion_caducada'))

    except SQLAlchemyError as e:
        logger.error(f"Error en la base de datos: {str(e)}")
        flash("Error en la base de datos", 'error')
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error inesperado: {str(e)}")
        flash("Error inesperado al obtener examinadores", 'error')
        return redirect(url_for('login'))
        
@app.route('/examinadora/photo/<int:id>')
def get_examinadora_photo(id):
    with session_scope() as db_session:
        # Obtén la examinadora por ID
        examinadora = get_examinator_service().get_examinator(session=db_session,examinator_id=id)
        
        if examinadora.photo:
            # Convierte los datos binarios a un objeto en memoria que Flask pueda manejar
            return send_file(BytesIO(examinadora.photo), mimetype='image/jpeg')
        else:
            # Si no hay foto, devuelve una imagen predeterminada o un error
            return send_file('path/to/default-image.jpg', mimetype='image/jpeg')
    
# Ruta para mostrar el frame del test o el caso dependiendo de la selección anterior
@app.route('/examinadoras/<int:id>/examen/<string:part>', methods=['GET'])
@login_required
@is_active
@check_access
@log_execution_time
def get_exams_by_examinator(id, part):
    try:
        id_user = session.get('id_user')
        session['examinator_id'] = id
        session['part'] = part
        logger.info(f"Ruta get_exams_by_examinator con id={id}, part={part}")
        
        with session_scope() as db_session:
            examinador = get_examinator_service().get_examinator(db_session, id)
            if not examinador:
                logger.error(f"No se encontró el examinador con ID {id}")
                flash('Examinador no encontrado', 'danger')
                return redirect(url_for('get_examinadoras_by_user'))

            if "sofia" in examinador.name.lower():
                if "test" in part:
                    json_partes = examinador.json_partes
                    titulo_parte = None
                    
                    if "20" in part:
                        titulo_parte = json_partes['partes_examen'].get("tests_rapidos",{}).get("partes",{}).get(part,{}).get('nombre')
                    elif "50" in part or "100" in part:
                        titulo_parte = json_partes['partes_examen'].get("tests",{}).get("partes",{}).get(part,{}).get('nombre')

                    exam = get_exam_service().get_random_exam_for_sofia(db_session, oposicion_id=examinador.oposicion_id, part=part, id_user=id_user)
                    user = get_user_service().get_user(session=db_session,user_id = id_user)
                    if not exam:
                        logger.error(f"No se encontró un examen para Sofia con part={part}")
                        flash("No hay exámenes disponibles para esta parte", 'warning')
                        return redirect(url_for('get_examinadoras_by_user'))
                    
                    if session.get('subscription') == True:
                        return render_template('examenes.html', examinador=examinador, exam=exam, titulo_parte=titulo_parte)
                    elif user.is_trial == True and "test_bloque1" in part:
                        return render_template('examenes.html', examinador=examinador, exam=exam, titulo_parte=titulo_parte)
                    else:
                        return redirect(url_for('subscripcion_caducada'))
                    
                else:
                    examinator_json = examinador.json_partes
                    user = get_user_service().get_user(session=db_session,user_id = id_user)
                    # Extraer los casos prácticos
                    casos_practicos = examinator_json["partes_examen"]["casos_practicos"]["partes"]

                    # Construir el diccionario template_map
                    template_map = {key: "casos_sofia.html" for key in casos_practicos}

                    if session.get('subscription') == True:
                        return render_template('casos.html', examinador=examinador, exam=exam, titulo_parte=titulo_parte)
                    else:
                        return redirect(url_for('subscripcion_caducada'))
            else:
                # Código para las otras examinadoras (Alicia, Gloria, Julia)
                try:
                    user = get_user_service().get_user(session=db_session,user_id = id_user)
                    json_partes = examinador.json_partes
                    titulo_parte = json_partes['partes_examen'].get(part,{}).get('nombre') if json_partes and 'partes_examen' in json_partes else part.capitalize()
                    
                    # Intentar obtener un examen aleatorio para esta examinadora
                    try:
                        exam = get_exam_service().get_random_exam_by_data(
                            db_session, 
                            oposicion_id=examinador.oposicion_id, 
                            part=part, 
                            id_user=id_user
                        )
                    except Exception as e:
                        logger.error(f"Error obteniendo examen aleatorio: {str(e)}")
                        exam = None
                    
                    # Si no se encontró examen (por excepción o porque retornó None)
                    if not exam:
                        logger.warning(f"No se encontró examen con filtro de preguntas, intentando sin filtrar")
                        # Obtener todos los exámenes de esta examinadora para esta parte
                        exams_by_part = db_session.query(Exam).filter(
                            Exam.oposicion_id == examinador.oposicion_id,
                            Exam.part == part
                        ).all()
                        
                        if exams_by_part:
                            # Seleccionar uno aleatorio
                            exam = random.choice(exams_by_part)
                            logger.info(f"Seleccionado examen aleatorio sin filtrar por preguntas: ID={exam.id}, preguntas={exam.total_preguntas}")
                    
                    if not exam:
                        flash('No hay exámenes disponibles para esta parte', 'warning')
                        return redirect(url_for('get_examinadoras_by_user'))
                    
                    session['exam_id'] = exam.id
                    
                    # Renderizar la plantilla adecuada
                    
                    if "test" in part:
                        if session.get('subscription') == True:
                            return render_template('examenes.html', examinador=examinador, exam=exam, titulo_parte=titulo_parte)
                        elif user.is_trial == True and "test_bloque1" in part:
                            return render_template('examenes.html', examinador=examinador, exam=exam, titulo_parte=titulo_parte)
                        else:
                            return redirect(url_for('subscripcion_caducada'))
                    else:
                        if session.get('subscription') == True:
                            return render_template('casos.html', examinador=examinador, exam=exam, titulo_parte=titulo_parte)
                        else:
                            return redirect(url_for('subscripcion_caducada'))
                except Exception as e:
                    logger.error(f"Error al obtener examen para {examinador.name}: {str(e)}")
                    flash(f"Error al obtener examen: {str(e)}", 'error')
                    return redirect(url_for('get_examinadoras_by_user'))
                    
    except KeyError as e:
        logger.error(f"KeyError en get_exams_by_examinator: {str(e)}")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error inesperado en get_exams_by_examinator: {str(e)}")
        return redirect(url_for('login'))
                    
    except KeyError as e:
        logger.error(f"KeyError en get_exams_by_examinator: {str(e)}")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error inesperado en get_exams_by_examinator: {str(e)}")
        return redirect(url_for('login'))

# Ruta para obtener un examen parseado aleatorio
@app.route('/get_new_exam')
@login_required
@log_execution_time
def get_new_exam():
    try:
        id_examinadora = session.get('examinator_id')
        part = session.get('part')
        id_user = session.get('id_user')
        
        logger.info(f"Obteniendo nuevo examen. Examinadora={id_examinadora}, part={part}, user={id_user}")

        if not id_examinadora or not part or not id_user:
            return jsonify({
                "error": "Faltan parámetros de sesión necesarios"
            }), 400

        with session_scope() as db_session:
            examinador = get_examinator_service().get_examinator(db_session, id_examinadora)
            if not examinador:
                logger.error(f"No se encontró el examinador con ID {id_examinadora}")
                return jsonify({"error": "Examinador no encontrado"}), 404

            if "sofia" in examinador.name.lower():
                # Código para Sofia - solo tests
                logger.info(f"Buscando examen para Sofia con part={part}")
                
                # Obtener un examen usando el servicio actualizado
                exam = get_exam_service().get_random_exam_for_sofia(db_session, oposicion_id=examinador.oposicion_id, part=part, id_user=id_user)
                
                if not exam:
                    logger.error(f"No se encontraron exámenes con corrección para {part}")
                    return jsonify({
                        "error": "No hay exámenes disponibles para esta parte",
                        "message": f"No se encontraron exámenes con correcciones para {part}. Por favor, póngase en contacto con el administrador."
                    }), 500
                
                session['exam_id'] = exam.id
                logger.info(f"Examen encontrado: ID={exam.id}, part={exam.part}, contexto={len(exam.context or '') > 0}")

                #TODO comprobar y quitar el modo de trial del usuario
                user = get_user_service().get_user(session=db_session,user_id=id_user)
                first_ex = session.get('first_exam')
                sub = session.get('subscription')
                if user.is_trial == True and session.get('first_exam') == True:
                    get_user_service().set_user_trial_status(session=db_session, user_id=id_user, trial=False)
                    session['first_exam'] = False
                elif user.is_trial == False and first_ex == False and sub == False:
                    session.clear()
                
                if "test" in exam.part:
                    content = ExamHTMLParser.parse_test_to_html(exam.content)
                    return jsonify({"content": content,
                                     "id_examen": exam.id,
                                     "is_trial": user.is_trial,
                                     "first_exam":first_ex,
                                     "sub":sub})
                else:
                    return jsonify({
                        "block_name": session.get('block_name'),
                        "id_examen": exam.id,
                        "content": exam.content,
                        "is_trial": user.is_trial,
                        "first_exam":first_ex,
                        "sub":sub
                    })
            else:
                # Código para otras examinadoras
                try:
                    oposicion_id = examinador.oposicion_id

                    # Intentar obtener un examen aleatorio
                    try:
                        exam = get_exam_service().get_random_exam_by_data(
                            db_session, 
                            oposicion_id=oposicion_id, 
                            part=part, 
                            id_user=id_user
                        )
                    except Exception as e:
                        logger.error(f"Error obteniendo examen aleatorio: {str(e)}")
                        exam = None
                    
                    # Si no se encontró examen (por excepción o porque retornó None)
                    if not exam:
                        logger.warning(f"No se encontró examen con filtro de preguntas, intentando sin filtrar")
                        # Obtener todos los exámenes de esta examinadora para esta parte
                        exams_by_part = db_session.query(Exam).filter(
                            Exam.oposicion_id == oposicion_id,
                            Exam.part == part
                        ).all()
                        
                        if exams_by_part:
                            # Seleccionar uno aleatorio
                            exam = random.choice(exams_by_part)
                            logger.info(f"Seleccionado examen aleatorio sin filtrar por preguntas: ID={exam.id}, preguntas={exam.total_preguntas}")
                    
                    if not exam:
                        return jsonify({
                            "error": "No hay exámenes disponibles para esta parte"
                        }), 404
                        
                    session['exam_id'] = exam.id
                    
                    #TODO comprobar y quitar el modo de trial del usuario
                    user = get_user_service().get_user(session=db_session,user_id=id_user)
                    first_ex = session.get('first_exam')
                    sub = session.get('subscription')

                    if user.is_trial == True and session.get('first_exam') == True:
                        get_user_service().set_user_trial_status(session=db_session, user_id=id_user, trial=False)
                        session['first_exam'] = False
                    elif user.is_trial == False and first_ex == False and sub == False:
                        session.clear()
                        
                    # Procesar el examen según su tipo
                    if "test" in exam.part:
                        content = ExamHTMLParser.parse_test_to_html(exam.content)
                        return jsonify({"content": content,
                                        "id_examen": exam.id,
                                        "is_trial": user.is_trial,
                                        "first_exam":first_ex,
                                        "sub":sub
                                        })
                    else:
                        case_html, questions_html = ExamHTMLParser.parse_case_to_html(exam.content)
                        return jsonify({
                            "case_html": case_html,
                            "questions_html": questions_html,
                            "id_examen": exam.id,
                            "is_trial": user.is_trial,
                            "first_exam":first_ex,
                            "sub":sub
                        })
                        
                except Exception as e:
                    logger.error(f"Error obteniendo examen para {examinador.name}: {str(e)}")
                    return jsonify({"error": f"Error al obtener el examen: {str(e)}"}), 500
                
    except KeyError as e:
        logger.error(f"KeyError en get_new_exam: {str(e)}")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error en get_new_exam: {str(e)}")
        traceback.print_exc()
        return jsonify({
            "error": "Error al obtener el examen",
            "message": str(e)
        }), 500

# Ruta para mostrar la página de prueba finalizada
@app.route('/prueba_finalizada')
def prueba_finalizada():
    return render_template('prueba_finalizada.html')

# Ruta para obtener los resultados a partir de las respuestas del html
@app.route('/get_puntuaciones', methods=['GET', 'POST'])
@login_required
@log_execution_time
def get_puntuaciones():
    try:
        examinator_id = session.get('examinator_id')
        exam_id = session.get('exam_id')
        part = session.get('part')
        
        logger.info(f"Procesando puntuaciones. Examinadora={examinator_id}, exam={exam_id}, part={part}")

        with session_scope() as db_session:
            examinator = get_examinator_service().get_examinator(db_session, examinator_id)
            if not examinator:
                logger.error(f"No se encontró el examinador con ID {examinator_id}")
                return jsonify({"error": "Examinador no encontrado"}), 404

            # Para casos prácticos de Sofía, mostrar mensaje de función no disponible
            if examinator.name.lower() == "sofia" and "test" not in part:
                return jsonify({
                    "error": "Los casos prácticos no están disponibles en esta versión"
                }), 400

            # Solo procesar puntuaciones para tests (común para Sofía y otras examinadoras)
            answers = request.form.to_dict()
            
            # Intentar obtener corrección y puntos
            try:
                correction_content, correct_points, incorrect_points = get_exam_service().get_exam_correction_and_points(
                    db_session, 
                    exam_id=exam_id, 
                    examinator_id=examinator_id
                )
            except Exception as e:
                logger.error(f"Error al obtener corrección y puntos: {str(e)}")
                # Valores por defecto
                correction_content = None
                oposicion = examinator.opos
                correct_points = 1.0 if oposicion and oposicion.punto_correctas else 1.0
                incorrect_points = 0.25 if oposicion and oposicion.punto_incorrectas else 0.25
                
                # Intentar obtener la corrección directamente
                correction = db_session.query(Correction).filter(Correction.exam_id == exam_id).first()
                if correction:
                    correction_content = ExamHTMLParser.format_correction(correction.correction_content)
            
            if not correction_content:
                logger.error(f"No se encontró corrección para examen {exam_id}")
                return jsonify({"error": "No se encontró la corrección para este examen"}), 404
            
            # Calcular puntuación
            results = get_exam_service().calculate_score(
                corrections=correction_content, 
                answers=answers,
                correct_points=correct_points, 
                incorrect_points=incorrect_points
            )

            # Guardar relación usuario-examen
            get_exam_service().asociar_examen_usuario(
                db_session, 
                user_id=session['id_user'], 
                exam_id=exam_id, 
                nota=results['score']['total'], 
                time_spend=30, 
                part=part
            )
            
            return jsonify({
                'status': 'success',
                **results
            })
    
    except KeyError as e:
        logger.error(f"KeyError en get_puntuaciones: {str(e)}")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error en get_puntuaciones: {str(e)}")
        traceback.print_exc()
        return jsonify({
            "error": "Error al procesar la puntuación",
            "message": str(e)
        }), 500

# Ruta para obtener la correccion
@app.route('/get_correccion', methods=['GET'])
@login_required
@log_execution_time
def get_correccion():
    try:
        exam_id = session.get('exam_id')
        logger.info(f"Obteniendo corrección para examen {exam_id}")
        
        with session_scope() as db_session:
            try:
                # Primero obtenemos el examen actual
                exam = db_session.query(Exam).filter(Exam.id == exam_id).first()
                if not exam:
                    logger.error(f"No se encontró el examen con ID {exam_id}")
                    return jsonify({"error": "Examen no encontrado"}), 404
                
                logger.info(f"Examen encontrado: ID={exam.id}, part={exam.part}")
                
                # Buscamos la corrección exacta para este examen
                # Construir el nombre de la corrección basado en el nombre del examen
                correction_pattern = f"{exam.part.replace('.txt', '')}_correction.txt"
                logger.info(f"Buscando corrección con patrón exacto: {correction_pattern}")
                
                correction_exam = db_session.query(Exam).filter(
                    Exam.oposicion_id == exam.oposicion_id,
                    Exam.part == correction_pattern
                ).first()
                
                if correction_exam:
                    logger.info(f"Corrección exacta encontrada: ID={correction_exam.id}, part={correction_exam.part}")
                    # Buscar el contenido de la corrección
                    correction = db_session.query(Correction).filter(
                        Correction.exam_id == correction_exam.id
                    ).first()
                    
                    if correction:
                        logger.info(f"Contenido de corrección encontrado para ID={correction_exam.id}")
                        return jsonify({
                            "id": correction.id,
                            "exam_id": correction_exam.id,
                            "content": correction.texto if hasattr(correction, 'texto') else correction.correction_content,
                            "part": correction_exam.part
                        })
                    else:
                        # Si no hay contenido de corrección específico, retornamos el examen de corrección
                        logger.warning(f"No se encontró contenido de corrección para {correction_exam.part}")
                        return jsonify({
                            "id": correction_exam.id,
                            "exam_id": correction_exam.id,
                            "content": correction_exam.content,
                            "part": correction_exam.part
                        })
                
                # Si no encontramos una corrección exacta, intentamos buscar directamente en la tabla Correction
                correction = db_session.query(Correction).filter(
                    Correction.exam_id == exam_id
                ).first()
                
                if correction:
                    logger.info(f"Corrección encontrada directamente para examen {exam_id}")
                    return jsonify({
                        "id": correction.id,
                        "exam_id": exam_id,
                        "content": correction.texto if hasattr(correction, 'texto') else correction.correction_content,
                        "part": exam.part
                    })
                
                logger.error(f"No se encontró corrección para el examen {exam_id}")
                return jsonify({"error": "No se encontró corrección para este examen"}), 404
                    
            except Exception as e:
                logger.error(f"Error buscando corrección: {str(e)}")
                return jsonify({"error": f"Error al obtener la corrección: {str(e)}"}), 500
            
    except KeyError as e:
        logger.error(f"KeyError en get_correccion: {str(e)}")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error en get_correccion: {str(e)}")
        return jsonify({"error": f"Error al obtener la corrección: {str(e)}"}), 500

# Ruta para obtener las partes de una examinadora
@app.route("/examinadoras/<int:id>/examen", methods=["GET"])
@login_required
@is_active
@check_access
@log_execution_time
def ver_examen_examinadora(id):
    try:
        with session_scope() as db_session:
            id_user = session.get('id_user')
            user = get_user_service().get_user(session=db_session, user_id=id_user)
            examinadora = get_examinator_service().get_examinator(db_session, id)
            if session.get('subscription') == True:
                return render_template("ver_examen_examinadora.html", examinadora=examinadora)
            elif user.is_trial == True:
                return render_template("ver_examen_examinadora_trial.html", examinadora=examinadora)
            else:
                return redirect(url_for('subscripcion_caducada'))
    except KeyError:
        return redirect(url_for('login'))
    
# Ruta para mostrar el perfil del usuario
@app.route("/perfil")
@login_required
@is_active
@check_sub
@log_execution_time
def perfil():
    try:
        login_id = session.get('id_login')
        user_id = session.get('id_user')
        
        if not login_id or not user_id:
            logger.warning("Usuario no autenticado, redirigiendo al login.")
            return redirect(url_for('login'))
            
        with session_scope() as db_session:
            # Usar get_user directamente con el user_id
            user = get_user_service().get_user(db_session, user_id)
            
            if not user:
                logger.error(f"No se encontró usuario con ID {user_id}")
                flash("Usuario no encontrado", 'error')
                return redirect(url_for('login'))
            
            # Obtener tutor y examinator de manera segura
            tutor = user.tutor if hasattr(user, 'tutor') else None
            examinator = user.examinator if hasattr(user, 'examinator') else None
                
            return render_template("ver_perfil.html", user=user, tutor=tutor, examinator=examinator)
            
    except Exception as e:
        logger.error(f"Error en perfil: {str(e)}")
        flash("Error al cargar el perfil", 'error')
        return redirect(url_for('login'))

# Ruta que muestra, la nota maedia por parte de forma odenada
@app.route("/perfil/bloques", methods=["GET"])
@login_required
@is_active
@check_sub
@log_execution_time
def ver_partes():
    try:
        login_id = session.get('id_login')
        user_id = session.get('id_user')
        
        if not login_id or not user_id:
            logger.warning("Usuario no autenticado, redirigiendo al login.")
            return redirect(url_for('login'))
            
        with session_scope() as db_session:
            # Usar get_user directamente con el user_id
            user = get_user_service().get_user(db_session, user_id)
            
            if not user:
                logger.error(f"No se encontró usuario con ID {user_id}")
                flash("Usuario no encontrado", 'error')
                return redirect(url_for('login'))
                
            # Verificar que el usuario tenga una examinadora asignada
            if not user.examinator_id:
                logger.error(f"Usuario {user_id} no tiene examinadora asignada")
                flash("No tienes examinadora asignada", 'error')
                return redirect(url_for('get_examinadoras_by_user'))
                
            examinator = get_examinator_service().get_examinator(db_session, examinator_id=user.examinator_id)
            
            if not examinator:
                logger.error(f"No se encontró la examinadora con ID {user.examinator_id}")
                flash("No se pudo encontrar la examinadora asignada", 'error')
                return redirect(url_for('get_examinadoras_by_user'))
                
            json_examinadora = examinator.json_partes
            titulo_oposicion = json_examinadora['titulo_oposicion']
            titulo_parte = json_examinadora['partes_examen']
            
            return render_template("seleccionar_parte_mostrar_nota.html", 
                                  titulo_oposicion=titulo_oposicion, 
                                  titulo_parte=titulo_parte, 
                                  nombre_examinadora=examinator.name)
                                  
    except KeyError as e:
        logger.error(f"KeyError en ver_partes: {str(e)}")
        flash("Error al cargar las partes", 'error')
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error en ver_partes: {str(e)}")
        flash("Error al cargar las partes", 'error')
        return redirect(url_for('login'))
    
# Ruta que muestra, la nota maedia por parte de forma odenada
@app.route("/perfil/bloques/<string:parte>", methods=["GET"])
@login_required
@is_active
@check_sub
@log_execution_time
def ver_historico_notas_por_parte(parte):
    try:
        with session_scope() as db_session: 
            user_id = session.get('id_user')
            user = get_user_service().get_user(db_session, user_id)
            json_examinadora = get_examinator_service().get_examinator(db_session,examinator_id=user.examinator_id).json_partes
            
            titulo_oposicion = json_examinadora['titulo_oposicion']

            if "Sofía" in json_examinadora['nombre']:
                if "20" in parte:
                    tipo_examen = 'tests_rapidos'
                elif "case" in parte:
                    tipo_examen = 'casos_practicos'
                else:
                    tipo_examen = 'tests'
            
                titulo_parte = json_examinadora['partes_examen'].get(tipo_examen, {}).get('partes', {}).get(parte, {}).get('nombre')
            else: 
                titulo_parte = json_examinadora['partes_examen'].get(parte, {}).get('nombre')

            notas_parte = get_notas_service().get_notas_by_id_y_parte(session=db_session,id_usuario=user_id,parte=parte)
            notas_usuario_parte = []

            for nota in notas_parte:
                notas_usuario_parte.append({
                    "nota_media": nota.nota_media,
                    "mes": nota.date.strftime("%m"),
                    "año": nota.date.strftime("%Y")
                })

            jsonfinal = {"oposicion":titulo_oposicion,
                         "titulo_parte":titulo_parte,
                         "notas_usuario":notas_usuario_parte,
                         "parte":parte}
                         
            return render_template("mostrar_nota_media_parte.html", jsonfinal = jsonfinal)
    except KeyError:
        return redirect(url_for('login'))

def verificar_token(token):
    try:
        secret_key = "h5AV37h9gjke"
        payload = pyjwt.decode(token, secret_key, algorithms=["HS256"])
        return payload['user_name']
    except pyjwt.ExpiredSignatureError:
        flash("❌ El enlace ha expirado", "danger")
        return None
    except pyjwt.InvalidTokenError:
        flash("❌ Token inválido", "danger")
        return None

# Función para generar un token
def generar_token(user_name):
    payload = {
        'user_name': user_name,
        'exp': datetime.utcnow() + timedelta(hours=24)  # Expiración de 24 horas
    }
    secret_key = "h5AV37h9gjke"
    token = pyjwt.encode(payload, secret_key, algorithm="HS256")
    return token

# Ruta para el cambio de contraseña
@app.route('/cambiar_password', methods=['GET', 'POST'])
def cambiar_password():
    token = request.args.get('token') if request.method == 'GET' else request.form.get('token')
    user_name = verificar_token(token)

    if not user_name:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        try:
            with session_scope() as db_session:
                user = get_user_service().get_user_by_username(db_session, username=user_name)

                if not user:
                    print("❌ Usuario no encontrado")
                    return redirect(url_for('login'))

                id_login = user.login_id
                user_login = get_user_service().get_login_by_login_id(session=db_session, login_id=id_login)

                if not check_password_hash(user_login.password, old_password):
                    print("❌ La contraseña actual es incorrecta")
                    return redirect(url_for('cambiar_password'))

                if check_password_hash(user_login.password, new_password):
                    print("❌ La nueva contraseña no puede ser igual a la anterior")
                    return redirect(url_for('cambiar_password'))

                hashed_password = generate_password_hash(new_password)
                if get_user_service().change_password(db_session, id_login=id_login, hashed_password=hashed_password):

                    msg = Message("Contraseña actualizada", recipients=[user.email])
                    msg.body = f"""
                    Tu contraseña ha sido actualizada correctamente.
                    Puedes iniciar sesión con tu nueva contraseña.
                    
                    Accede al Campus: {url_for('login', _external=True)}

                    Saludos, 
                    El equipo de soporte.
                    """
                    msg.html = f"""
                    <p>Tu contraseña ha sido actualizada correctamente.</p>
                    <p>Puedes iniciar sesión con tu nueva contraseña.</p>
                    <a href="{url_for('login', _external=True)}" style="background-color:#8A2BE2;color:white;padding:10px 15px;border-radius:5px;text-decoration:none;">Acceder al Campus</a>
                    <p>Saludos, El equipo de soporte.</p>
                    """
                    mail.send(msg)

                    print("✅ Contraseña actualizada correctamente")
                    return redirect(url_for('login'))
                else:
                    print("❌ Error al cambiar la contraseña")
                    return redirect(url_for('cambiar_password'))
        except Exception as e:
            print(f"❌ Error al cambiar la contraseña: {str(e)}")
            return redirect(url_for('login'))

    return render_template("cambiar_password.html", token=token)

# Función para generar una contraseña aleatoria
def generar_password(longitud=12):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(caracteres) for _ in range(longitud))

# Ruta para recuperar la contraseña
@app.route('/recuperar_password', methods=['GET', 'POST'])
def recuperar_password():
    if request.method == 'POST':
        user_name = request.form.get('username')
        password_temp = generar_password()
        
        try:
            with session_scope() as db_session:
                # Obtener el correo electrónico del usuario
                email = get_user_service().get_email_by_username(db_session, username=user_name)
                
                if not email:
                    flash("Usuario no encontrado. Verifica el nombre de usuario.", "error")
                    return redirect(url_for('recuperar_password'))

                # Obtener el usuario para actualizar la contraseña
                user = get_user_service().get_user_by_username(db_session, username=user_name)
                
                if not user:
                    flash("Usuario no encontrado", "error")
                    return redirect(url_for('recuperar_password'))

                # Hashear la contraseña temporal y actualizarla en la base de datos
                hashed_temporal_password = generate_password_hash(password_temp)
                if not get_user_service().change_password(db_session, id_login=user.login_id, hashed_password=hashed_temporal_password):
                    flash("Hubo un error al actualizar la contraseña temporal. Inténtalo de nuevo.", "error")
                    return redirect(url_for('recuperar_password'))

                # Generar el enlace de restablecimiento con el dominio actual
                token = generar_token(user_name)
                reset_link = f"127.0.0.1:5000/cambiar_password?token={token}"

                # Enviar correo
                msg = Message('Recuperar Contraseña', recipients=[email])
                msg.body = f"""Hola, has solicitado recuperar tu contraseña.

                Tu contraseña temporal es: {password_temp}

                Por favor, visita el siguiente enlace para cambiarla: {reset_link}

                Saludos,
                El equipo de soporte.
                """
                msg.html = f"""
                <p>Hola, has solicitado recuperar tu contraseña.</p>
                <p>Tu contraseña temporal es: <strong>{password_temp}</strong></p>
                <p><a href="{reset_link}" style="background-color:#8A2BE2;color:white;padding:10px 15px;border-radius:5px;text-decoration:none;">Cambiar Contraseña</a></p>
                <p>Saludos,<br>El equipo de soporte.</p>
                """
                mail.send(msg)
                flash("Correo de recuperación enviado", "success")
                return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error al recuperar la contraseña: {str(e)}")
            flash("Hubo un error al procesar la solicitud de recuperación. Inténtalo de nuevo.", "error")
            return redirect(url_for('recuperar_password'))

    return render_template("recuperar_password.html")

#Ruta que desactiva un usuario
@app.route('/desactivar_usuario')
def desactivar_suaurio():
    id_user = session.get('id_user')
    with session_scope as db_session:
        get_user_service().disable_user(session=db_session,user_id=id_user)
        session['is_active'] = False
        return redirect(url_for('cancelar_subscripcion'))

# Ruta para mostrar la página de prueba finalizada
@app.route('/subscripcion_caducada')
def subscripcion_caduda():
    return render_template('not_subscribed.html')

# Cierre de todos los servicios abiertos 
@app.teardown_request 
def teardown_request(exception=None): 
    # Cerrar todas las conexiones de servicios 
    for attr in ['user_service', 'tutor_service', 'examinator_service', 'exam_service', 'login_service', 'notas_service', 'dominio_service']: 
        service = getattr(g, attr, None) 
        if service: 
            try: 
                service.close() 
            except Exception as e: 
                logger.error(f"Error al cerrar {attr}: {str(e)}") 

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Verificar si podemos conectarnos a la base de datos
    if not check_database_connection():
        logger.critical("No se pudo conectar a la base de datos. Verifica tu configuración de MySQL.")
        print("\n" + "="*80)
        print("ERROR DE CONEXIÓN A LA BASE DE DATOS")
        print("="*80)
        print("Para conectar a la base de datos, asegúrate de:")
        print("1. Tener acceso al servidor MySQL")
        print("2. Que el puerto 3306 esté accesible")
        print("3. Que las credenciales sean correctas")
        print("="*80 + "\n")
        
    # Inicializar la base de datos y crear tablas
    db_ok = init_db()
    if not db_ok:
        logger.warning("La aplicación continuará ejecutándose, pero podrían ocurrir errores de base de datos")
        
    # En producción, no ejecutar directamente Flask sino utilizar Gunicorn
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(host='localhost', port=5000, debug=True)
    else:
        # En producción, Gunicorn maneja la ejecución
        app.run(host='0.0.0.0', port=5000, debug=False)