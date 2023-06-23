import os
from cryptography.fernet import Fernet


class Config:
    try:
        MAIN_SERVICE_URL = os.environ.get('MAIN_SERVICE_URL')
        SECRET_KEY = os.environ.get('SECRET_KEY')
        SQLALCHEMY_DATABASE_URI = Fernet(SECRET_KEY).decrypt(os.environ.get('SQLALCHEMY_DATABASE_URI')).decode('UTF-8')
        WINDOW_SIZE = int(os.environ.get('WINDOW_SIZE'))
        MAX_REQUESTS = int(os.environ.get('MAX_REQUESTS'))
    except:
        MAIN_SERVICE_URL = "https://localhost:443"
        SECRET_KEY = 'h8jb8YRt4nCw8PnSMNHPVOXgZ3kZzn6-zlQZoKscgzE='
        SQLALCHEMY_DATABASE_URI = Fernet(SECRET_KEY).decrypt('gAAAAABkSDIXxForUE_obMCmLDazxYKjm6sM9e37lq91Fv5AUlWxnxAUStXhMof7cXeFiq3u0wuYSm_wBf4fSC2YguZVjBP4t2wSerliFwNwaGS5k0hbPxtVx3A6P3xH_sy4wR3LOXVcna3yW9qahmzW7myfoHY6_Q==').decode('UTF-8')
        WINDOW_SIZE = 60
        MAX_REQUESTS = 10