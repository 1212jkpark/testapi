from flask_mysqldb import MySQL
import MySQLdb.cursors

from app001.routes import app

import bcrypt
import jwt
#### JWT ####
app.config['JWT_SECRET_KEY'] = 'your_secret_key_for_jwt'
algorithm = 'HS256'

app.config['MYSQL_HOST'] = '10.10.10.136'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'imsi00.!'
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['MYSQL_PORT'] = 3306

# Intialize MySQL
mysql = MySQL(app)

class User():
    def login(email, input_password):
        # bcrypt hash transfer
        password_bytes = input_password.encode('utf-8')
        # MySQL DB에 해당 계정 정보가 있는지 확인
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', [email])
        # 값이 유무 확인 결과값 account 변수로 넣기
        account = cursor.fetchone()
        if account:
            db_password_bytes = account['hashed_password'].encode('utf-8')
            check_password = bcrypt.checkpw(password_bytes, db_password_bytes)
            payload = {
                'email': account['email'],
                'hashed_password': account['hashed_password']
            }
            jwt_token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm)
            return check_password, jwt_token.decode('utf-8')
        return False, False
    
    def login_check(input_username, input_password):
        # bcrypt hash transfer
        input_password = input_password.encode('utf-8')
        # MySQL DB에 해당 계정 정보가 있는지 확인
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', [input_username])
        # 값이 유무 확인 결과값 account 변수로 넣기
        account = cursor.fetchone()
        check_password = bcrypt.checkpw(input_password, account['password'].encode('utf-8'))
        print(check_password)
        return account, check_password
    
    def get_information(id):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', id)
        account = cursor.fetchone()
        return account
    
    def update_fromip(fromip, id):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('UPDATE `pythonlogin`.`accounts` SET `fromip`=%s WHERE `id`=%s', (fromip, str(id)))
        mysql.connection.commit()
        
    def check_username_exist(username):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        username_already_exist = cursor.fetchone()
        return username_already_exist
    
    def check_email_exist(email):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        email_already_exist = cursor.fetchone()
        return email_already_exist
    
    def useradd(username, password, email):
        password = (bcrypt.hashpw(password.encode('UTF-8'), bcrypt.gensalt())).decode('utf-8')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("INSERT INTO `accounts` (`username`, `password`, `email`) VALUES (%s, %s, %s)", (username, password, email))
        mysql.connection.commit()
    