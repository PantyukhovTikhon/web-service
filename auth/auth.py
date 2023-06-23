from flask import Flask, request, jsonify, render_template, abort
from models import Base, User
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import create_engine
from config import Config
import time
import datetime
import jwt
from functools import wraps


app = Flask(__name__)
app.config.from_object(Config)
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI, echo=True)
Base.metadata.bind = engine
db_session = scoped_session(sessionmaker(bind=engine))
context = ('server.crt', 'server.key')
main_service_url = Config.MAIN_SERVICE_URL

failed_logins = {}
endpoint_limits = {}

window_size = Config.WINDOW_SIZE
max_requests = Config.MAX_REQUESTS


def generate_token(username, role):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        'username': username,
        'role': role,
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
                abort(429)
            endpoint_limits[endpoint] = request_count
            return func(*args, **kwargs)
        return wrapper
    return decorator


def is_password_strong(password):
    if len(password) < 8:
        return False
    if not any(char.islower() for char in password) or not any(char.isupper() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char in '!@#$%^&*()-_=+[]{}|:;,.<>?/~`"\'\\' for char in password):
        return False
    return True


@app.route('/register', methods=['POST'])
@limit_requests('/register')
def register():
    token = request.json.get("token")
    decoded_token = decode_token(token)
    username = decoded_token.get('username')
    password = decoded_token.get('password')
    if db_session.query(User).filter_by(username=username).first():
        return jsonify({"message": "Пользователь с таким именем уже существует."}), 401
    if not is_password_strong(password):
        return jsonify({"message": "Пароль не соответствует требованиям безопасности. Пароль должен: быть длинной не менее 8 символов, содержать как минимум одну строчную, одну заглавную букву и одну цифру, а также как минимум один специальный символ."}), 401
    db_session.add(User(username=username, role="Viewer", password=password))
    db_session.commit()
    return jsonify({"message": "Регистрация прошла успешно. Авторизируйтесь для входа в систему."}), 200


@app.route("/login", methods=["POST"])
@limit_requests('/login')
def login():
    token = request.json.get("token")
    decoded_token = decode_token(token)
    username = decoded_token.get('username')
    password = decoded_token.get('password')
    user = db_session.query(User).filter_by(username=username).first()
    if username in failed_logins and time.time() - failed_logins[username]['time'] < 300 and failed_logins[username]['attempts'] >= 3:
        return jsonify({"message": "Вы превысили лимит попыток авторизации для этого пользователя, попробуйте еще раз через 5 минут"}), 401
    if not user or not user.check_password(password):
        if username not in failed_logins:
            failed_logins[username] = {'attempts': 1, 'time': time.time()}
        else:
            failed_logins[username]['attempts'] += 1
        return jsonify({"message": "Неверное имя пользователя или пароль"}), 401
    failed_logins.pop(username, None)
    auth_token = generate_token(user.username, user.role)
    return jsonify({"token": auth_token}), 200


@app.route('/administration_panel', methods=['POST'])
@limit_requests('/administration_panel')
def administration_panel():
    token = request.json.get("token")
    decoded_token = decode_token(token)
    username = decoded_token.get('username')
    role = decoded_token.get('password')
    user = db_session.query(User).filter_by(username=username).first()
    if not user:
        return jsonify({"message": "Пользователь с таким именем не найден"}), 401
    user.role = role
    db_session.commit()
    return jsonify({"message": "Роль пользователя успешно изменена"}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, ssl_context=context)