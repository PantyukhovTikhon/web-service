from flask import Flask, request, render_template, redirect, session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from models import Base, Subject, Customer, Order, Audit
import requests
from config import Config
from datetime import timedelta
import datetime
import jwt
import time
from functools import wraps


app = Flask(__name__)
app.config.from_object(Config)
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI, echo=True)
Base.metadata.bind = engine
db_session = scoped_session(sessionmaker(bind=engine))
Base.metadata.create_all(bind=engine)
context = ('server.crt', 'server.key')
auth_service_url = Config.AUTH_SERVICE_URL

endpoint_limits = {}

window_size = Config.WINDOW_SIZE
max_requests = Config.MAX_REQUESTS


def generate_token(username, password):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        'username': username,
        'password': password,
        'exp': expiration
    }
    token = jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')
    return token


def decode_token(token):
    try:
        decoded_token = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
        return decoded_token
    except jwt.ExpiredSignatureError:
        return render_template("message.html", message=f"Срок действия токена истек!")
    except jwt.InvalidTokenError:
        return render_template("message.html", message=f"Недействительный токен")


def role_check():
    try:
        role = decode_token(session.get('token')).get('role')
    except:
        role = ""
    return role


def username_check():
    try:
        username = decode_token(session.get('token')).get('username')
    except:
        username = ""
    return username


def limit_requests(endpoint):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            request_count = endpoint_limits.get(endpoint, {'count': 0, 'last_time': 0})
            current_time = time.time()
            if current_time - request_count['last_time'] > window_size:
                request_count['count'] = 0
                request_count['last_time'] = current_time
            request_count['count'] += 1
            if request_count['count'] > max_requests:
                return render_template("message.html",message=f"Был превышен отведённый предел количества запросов в минуту. Попробуйте позже!")
            endpoint_limits[endpoint] = request_count
            return func(*args, **kwargs)
        return wrapper
    return decorator


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)
    try:
        db_session.add(Audit(action=request.url, username=username_check()))
    except:
        db_session.add(Audit(action=request.url, username="unauthorized"))
    db_session.commit()


@app.route('/logout')
@limit_requests('/logout')
def logout():
    session.pop('token', None)
    return redirect("/login")


@app.route("/login", methods=['GET', 'POST'])
@limit_requests('/login')
def login():
    if session.get('token'):
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"Вы уже авторизованы!")
    else:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            auth_token = generate_token(username, password)
            try:
                response = requests.post(f"{auth_service_url}/login", json={'token': auth_token}, verify=False)
                if response.status_code == 200:
                    token = response.json().get("token")
                    session['token'] = token
                    decoded_token = decode_token(token)
                    username = decoded_token.get('username')
                    role = decoded_token.get('role')
                    return render_template("message.html", current_user=username, current_user_role=role, message=f"Добро пожаловать в веб-сервис складского учёта предприятия, {username}!")
                else:
                    return render_template('login.html', message=response.json().get("message"))
            except:
                return render_template("message.html", message=f"Сервис аутентификации не отвечает!")
        else:
            return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
@limit_requests('/register')
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        auth_token = generate_token(username, password)
        try:
            response = requests.post(f"{auth_service_url}/register", json={'token': auth_token}, verify=False)
            if response.status_code == 200:
                return render_template('login.html', message=response.json().get("message"))
            else:
                return render_template('register.html', message=response.json().get("message"))
        except:
            return render_template("message.html", message=f"Сервис аутентификации не отвечает!")
    else:
        session.pop('token', None)
        return render_template('register.html')


@app.route('/administration_panel', methods=['GET'])
@limit_requests('/administration_panel')
def administration_panel():
    if role_check() == "Admin":
        return render_template('administration_panel.html', current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/administration_panel/change_role', methods=['POST', 'GET'])
@limit_requests('/administration_panel/change_role')
def change_role():
    if request.method == 'POST':
        username = request.form.get('username')
        role = request.form.get('role')
        auth_token = generate_token(username, role)
        try:
            response = requests.post(f"{auth_service_url}/administration_panel", json={'token': auth_token}, verify=False)
            return render_template('change_role.html', current_user=username_check(), current_user_role=role_check(), message=response.json().get("message"))
        except:
            return render_template("message.html", message=f"Сервис аутентификации не отвечает!")
    else:
        if role_check() == "Admin":
            return render_template('change_role.html', current_user=username_check(), current_user_role=role_check())
        else:
            return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/administration_panel/logs', methods=['GET', 'POST'])
@limit_requests('/administration_panel/logs')
def logs():
    if role_check() == "Admin":
        if request.method == 'POST':
            username_filter = request.form.get('username_filter')
            action_filter = request.form.get('action_filter')
            created_at_filter = request.form.get('created_at_filter')
            query = db_session.query(Audit)
            if username_filter:
                query = query.filter(Audit.username.like(f'%{username_filter}%'))
            if action_filter:
                query = query.filter(Audit.action.like(f'%{action_filter}%'))
            if created_at_filter:
                query = query.filter(Audit.created_at.like(f'%{created_at_filter}%'))
            logs = query.all()
        else:
            logs = db_session.query(Audit).all()
        return render_template('logs.html', logs=logs, current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/administration_panel/logs/delete_logs', methods=['POST'])
@limit_requests('/administration_panel/logs/delete_logs')
def delete_logs():
    if role_check() == "Admin":
        db_session.query(Audit).delete()
        db_session.commit()
        return redirect('/administration_panel/logs')
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/')
@limit_requests('/')
def index():
    if session.get('token'):
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"Веб-сервис складского учёта предприятия")
    else:
        return render_template("message.html", message=f"Веб-сервис складского учёта предприятия")


@app.route('/subjects', methods=['GET', 'POST'])
@limit_requests('/subjects')
def subjects():
    if session.get('token'):
        if request.method == 'POST':
            name_filter = request.form.get('name_filter')
            quantity_filter = request.form.get('quantity_filter')
            query = db_session.query(Subject)
            if name_filter:
                query = query.filter(Subject.name.like(f'%{name_filter}%'))
            if quantity_filter:
                query = query.filter(Subject.quantity == quantity_filter)
            subjects = query.all()
        else:
            subjects = db_session.query(Subject).all()
        return render_template('subjects.html', subjects=subjects, current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/add_subject', methods=['POST', 'GET'])
@limit_requests('/add_subject')
def add_subject():
    if role_check() == "Admin" or role_check() == "Creator":
        if request.method == 'POST':
            name = request.form.get('name')
            quantity = request.form.get('quantity')
            subject = db_session.query(Subject).filter_by(name=name).first()
            if subject:
                return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"Предмет с таким именем уже добавлен!")
            new_subject = Subject(name=name, quantity=quantity)
            db_session.add(new_subject)
            db_session.commit()
            return redirect("/subjects")
        else:
            return render_template('add_subject.html', current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/delete_subject/<int:id>', methods=['POST'])
@limit_requests('/delete_subject/<int:id>')
def delete_subject(id):
    if role_check() == "Admin" or role_check() == "Creator":
        subject = db_session.query(Subject).get(id)
        db_session.delete(subject)
        db_session.commit()
        return redirect('/subjects')
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/edit_subject/<int:id>', methods=['GET', 'POST'])
@limit_requests('/edit_subject/<int:id>')
def edit_subject(id):
    if role_check() == "Admin" or role_check() == "Creator":
        subject = db_session.query(Subject).get(id)
        if request.method == 'POST':
            name = request.form.get('name')
            quantity = request.form.get('quantity')
            if not name or not quantity:
                return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"Поля должны быть заполнены!")
            subject.name = name
            subject.quantity = quantity
            db_session.commit()
            return redirect('/subjects')
        else:
            return render_template('edit_subject.html', subject=subject, current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/customers', methods=['GET', 'POST'])
@limit_requests('/customers')
def customers():
    if role_check() == "Admin" or role_check() == "Creator":
        if request.method == 'POST':
            id_filter = request.form.get('id_filter')
            name_filter = request.form.get('name_filter')
            address_filter = request.form.get('address_filter')
            passport_details_filter = request.form.get('passport_details_filter')
            phone_number_filter = request.form.get('phone_number_filter')
            query = db_session.query(Customer)
            if id_filter:
                query = query.filter(Customer.id == id_filter)
            if name_filter:
                query = query.filter(Customer.name.like(f'%{name_filter}%'))
            if address_filter:
                query = query.filter(Customer.address.like(f'%{address_filter}%'))
            if passport_details_filter:
                query = query.filter(Customer.passport_details.like(f'%{passport_details_filter}%'))
            if phone_number_filter:
                query = query.filter(Customer.phone_number.like(f'%{phone_number_filter}%'))
            customers = query.all()
        else:
            customers = db_session.query(Customer).all()
        return render_template('customers.html', customers=customers, current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/add_customer', methods=['POST', 'GET'])
@limit_requests('/add_customer')
def add_customer():
    if role_check() == "Admin" or role_check() == "Creator":
        if request.method == 'POST':
            name = request.form.get('name')
            address = request.form.get('address')
            passport_details = request.form.get('passport_details')
            phone_number = request.form.get('phone_number')
            customer = db_session.query(Customer).filter_by(passport_details=passport_details).first()
            if customer:
                return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"Такой заказчик уже добавлен")
            db_session.add(Customer(name=name, address=address, passport_details=passport_details, phone_number=phone_number))
            db_session.commit()
            return redirect("/customers")
        else:
            return render_template('add_customer.html', current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/delete_customer/<int:id>', methods=['POST'])
@limit_requests('/delete_customer/<int:id>')
def delete_customer(id):
    if role_check() == "Admin" or role_check() == "Creator":
        customer = db_session.query(Customer).get(id)
        db_session.delete(customer)
        db_session.query(Order).filter_by(customer_id=id).delete()
        db_session.commit()
        return redirect('/customers')
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/edit_customer/<int:id>', methods=['GET', 'POST'])
@limit_requests('/edit_customer/<int:id>')
def edit_customer(id):
    if role_check() == "Admin" or role_check() == "Creator":
        customer = db_session.query(Customer).get(id)
        if request.method == 'POST':
            customer.name = request.form.get('name')
            customer.address = request.form.get('address')
            customer.passport_details = request.form.get('passport_details')
            customer.phone_number = request.form.get('phone_number')
            db_session.commit()
            return redirect('/customers')
        else:
            return render_template('edit_customer.html', customer=customer, current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/orders', methods=['GET', 'POST'])
@limit_requests('/orders')
def orders():
    if session.get('token'):
        if request.method == 'POST':
            customer_id_filter = request.form.get('customer_id_filter')
            subject_name_filter = request.form.get('subject_name_filter')
            quantity_filter = request.form.get('quantity_filter')
            created_at_filter = request.form.get('created_at_filter')
            query = db_session.query(Order)
            if customer_id_filter:
                query = query.filter(Order.customer_id == customer_id_filter)
            if subject_name_filter:
                query = query.filter(Order.subject_name.like(f'%{subject_name_filter}%'))
            if quantity_filter:
                query = query.filter(Order.quantity == quantity_filter)
            if created_at_filter:
                query = query.filter(Order.created_at.like(f'%{created_at_filter}%'))
            orders = query.all()
        else:
            orders = db_session.query(Order).all()
        return render_template('orders.html', orders=orders, current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/add_order', methods=['POST', 'GET'])
@limit_requests('/add_order')
def add_order():
    if role_check() == "Admin" or role_check() == "Creator":
        if request.method == 'POST':
            customer_id = request.form.get('customer_id')
            subject_name = request.form.get('subject_name')
            quantity = request.form.get('quantity')
            db_session.add(Order(customer_id=customer_id, subject_name=subject_name, quantity=quantity))
            db_session.commit()
            return redirect("/orders")
        else:
            customers_ids = [customer.id for customer in db_session.query(Customer).all()]
            subjects_names = [subject.name for subject in db_session.query(Subject).all()]
            return render_template('add_order.html', customers_ids=customers_ids, subjects_names=subjects_names, current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/delete_order/<int:id>', methods=['POST'])
@limit_requests('/delete_order/<int:id>')
def delete_order(id):
    if role_check() == "Admin" or role_check() == "Creator":
        order = db_session.query(Order).get(id)
        db_session.delete(order)
        db_session.commit()
        return redirect('/orders')
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


@app.route('/edit_order/<int:id>', methods=['GET', 'POST'])
@limit_requests('/edit_order/<int:id>')
def edit_order(id):
    if role_check() == "Admin" or role_check() == "Creator":
        customers_ids = [customer.id for customer in db_session.query(Customer).all()]
        subjects_names = [subject.name for subject in db_session.query(Subject).all()]
        order = db_session.query(Order).get(id)
        if request.method == 'POST':
            order.customer_id = request.form.get('customer_id')
            order.subject_name = request.form.get('subject_name')
            order.quantity = request.form.get('quantity')
            db_session.commit()
            return redirect('/orders')
        else:
            return render_template('edit_order.html', order=order, customers_ids=customers_ids, subjects_names=subjects_names, current_user=username_check(), current_user_role=role_check())
    else:
        return render_template("message.html", current_user=username_check(), current_user_role=role_check(), message=f"У вас недостаточно прав!")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context=context)