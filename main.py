from http.server import HTTPServer, SimpleHTTPRequestHandler
import webbrowser
import threading
import time
import json
import smtplib
import random
import hashlib
import secrets
from datetime import datetime, timezone
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
import os
import re
import html

SUPABASE_URL = "https://eiltqlkhufxllkcftxbv.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVpbHRxbGtodWZ4bGxrY2Z0eGJ2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjA1OTM2MjMsImV4cCI6MjA3NjE2OTYyM30.qbDR6aDJD3ZEpeRTEbUHA7KBmr6zBsX1igSWLN0V_qI"

EMAIL_ACCOUNTS = {
    'miranovseverov@gmail.com': 'kdbc vmdb djxf pmiq',
    'alenaveterov@gmail.com': 'hmiq xwmr yfmw prsa', 
    'linadurov@gmail.com': 'gsbp xyts brbu dlpw',
    'Sckykatwo@gmail.com': 'dblx ajll ugku ogpx',
    'xxhowsq@gmail.com': 'fcmm adeq oato gjon',
    'Vanakrotisov@gmail.com': 'gukl qhxy uxea yhil',
    'ofag59111@gmail.com': 'xmnx ijya yxvr wamo',
    'vasyapetkin132@gmail.com': 'bflk peqq sorn gfsp',
    'annnoraleidingbr57@gmail.com': 'desnidcbrzkekuby',
    'dlyabravla655@gmail.com': 'kprn ihvr bgia vdys',
    'dlatt6677@gmail.com': 'usun ruef otzx zcrh',
    'qstkennethadams388@gmail.com': 'itpz jkrh mtwp escx',
    'usppaullewis171@gmail.com': 'lpiy xqwi apmc xzmv',
    'ftkgeorgeanderson367@gmail.com': 'okut ecjk hstl nucy',
    'nieedwardbrown533@gmail.com': 'wvig utku ovjk appd',
    'h56400139@gmail.com': 'byrl egno xguy ksvf',
    'den.kotelnikov220@gmail.com': 'xprw tftm lldy ranp',
    'trevorzxasuniga214@gmail.com': 'egnr eucw jvxg jatq',
    'dellapreston50@gmail.com': 'qoit huon rzsd eewo',
    'neilfdhioley765@gmail.com': 'rgco uwiy qrdc gvqh',
    'hhzcharlesbaker201@gmail.com': 'mcxq vzgm quxy smhh',
    'samuelmnjassey32@gmail.com': 'lgct cjiw nufr zxjg',
    'allisonikse1922@gmail.com': 'tozo xrzu qndn mwuq',
    'corysnja1996@gmail.com': 'pfjk ocbf augx cgiy',
    'maddietrdk1999@gmail.com': 'rhqb ssiz csar cvot',
    'yaitskaya.alya@mail.ru': 'CeiYHA6GNpvuCz584eCp'
}

AVATARS_DIR = "user_avatars"

class SecurityUtils:
    @staticmethod
    def sanitize_input(text):
        if not text:
            return ""
        text = html.escape(text)
        dangerous_patterns = [
            r'<script.*?>.*?</script>',
            r'<.*?javascript:.*?>',
            r'<.*?on\w+.*?=.*?>',
            r'union.*select',
            r'insert.*into',
            r'update.*set',
            r'delete.*from',
            r'drop.*table',
            r'exec.*\(.*\)',
            r'xp_cmdshell'
        ]
        for pattern in dangerous_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        return text.strip()

    @staticmethod
    def validate_email(email):
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_regex, email))

    @staticmethod
    def validate_username(username):
        username_regex = r'^[a-zA-Z0-9_-]{3,20}$'
        return bool(re.match(username_regex, username))

    @staticmethod
    def validate_password(password):
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        return True

    @staticmethod
    def generate_secure_token(length=32):
        return secrets.token_hex(length)

    @staticmethod
    def validate_file_extension(filename, allowed_extensions=None):
        if allowed_extensions is None:
            allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif'}
        file_ext = os.path.splitext(filename)[1].lower()
        return file_ext in allowed_extensions

    @staticmethod
    def validate_file_size(file_size, max_size_mb=5):
        return file_size <= max_size_mb * 1024 * 1024

class RateLimiter:
    def __init__(self, max_requests=10, window=60):
        self.max_requests = max_requests
        self.window = window
        self.requests = {}

    def is_allowed(self, ip):
        now = time.time()
        if ip not in self.requests:
            self.requests[ip] = []
        
        self.requests[ip] = [req_time for req_time in self.requests[ip] if now - req_time < self.window]
        
        if len(self.requests[ip]) < self.max_requests:
            self.requests[ip].append(now)
            return True
        return False

class SupabaseService:
    def __init__(self):
        self.url = SUPABASE_URL
        self.key = SUPABASE_KEY
        self.headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json"
        }
    
    def make_request(self, endpoint, method="GET", data=None):
        url = f"{self.url}/rest/v1/{endpoint}"
        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers, params=data, timeout=10)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, json=data, timeout=10)
            elif method == "PUT":
                response = requests.put(url, headers=self.headers, json=data, timeout=10)
            elif method == "DELETE":
                response = requests.delete(url, headers=self.headers, timeout=10)
            
            if response.status_code in [200, 201, 204]:
                return {"success": True, "data": response.json() if response.content else {}}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def create_user(self, username, email, password_hash):
        user_data = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "avatar_url": "default-avatar.jpg",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        return self.make_request("users", "POST", user_data)
    
    def get_user_by_email(self, email):
        params = {"email": f"eq.{email}"}
        result = self.make_request("users", "GET", params)
        if result["success"] and result["data"]:
            return result["data"][0]
        return None
    
    def get_user_by_username(self, username):
        params = {"username": f"eq.{username}"}
        result = self.make_request("users", "GET", params)
        if result["success"] and result["data"]:
            return result["data"][0]
        return None
    
    def update_user_avatar(self, email, avatar_url):
        update_data = {"avatar_url": avatar_url}
        url = f"{self.url}/rest/v1/users?email=eq.{email}"
        response = requests.patch(url, headers=self.headers, json=update_data, timeout=10)
        return response.status_code in [200, 204]
    
    def create_verification_code(self, email, code, username):
        expires_at = datetime.now(timezone.utc).timestamp() + 600
        code_data = {
            "email": email,
            "code": code,
            "username": username,
            "expires_at": expires_at,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        return self.make_request("verification_codes", "POST", code_data)
    
    def get_verification_code(self, email, code):
        params = {
            "email": f"eq.{email}",
            "code": f"eq.{code}"
        }
        result = self.make_request("verification_codes", "GET", params)
        if result["success"] and result["data"]:
            code_data = result["data"][0]
            if datetime.now(timezone.utc).timestamp() < code_data['expires_at']:
                return code_data
        return None
    
    def delete_verification_code(self, email):
        params = {"email": f"eq.{email}"}
        return self.make_request("verification_codes", "DELETE", params)
    
    def upload_avatar_to_storage(self, file_data, filename, user_id):
        url = f"{self.url}/storage/v1/object/avatars/{user_id}/{filename}"
        content_type = "image/jpeg" if filename.lower().endswith('.jpg') else "image/png"
        headers = {
            "Authorization": f"Bearer {self.key}",
            "Content-Type": content_type,
            "Cache-Control": "max-age=3600"
        }
        try:
            response = requests.post(url, headers=headers, data=file_data, timeout=30)
            if response.status_code == 200:
                avatar_url = f"{user_id}/{filename}"
                return {"success": True, "avatar_url": avatar_url}
            else:
                return {"success": False, "error": response.text}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_avatar_url(self, avatar_path):
        if avatar_path == "default-avatar.jpg":
            return "/photo/default-avatar.jpg"
        else:
            return f"{self.url}/storage/v1/object/public/avatars/{avatar_path}"

class AvatarService:
    def __init__(self):
        if not os.path.exists(AVATARS_DIR):
            os.makedirs(AVATARS_DIR)
    
    def save_avatar_locally(self, file_data, filename, user_id):
        try:
            if not SecurityUtils.validate_file_extension(filename):
                return {"success": False, "error": "Invalid file extension"}
            
            if not SecurityUtils.validate_file_size(len(file_data)):
                return {"success": False, "error": "File too large"}
            
            file_ext = os.path.splitext(filename)[1].lower()
            new_filename = f"{user_id}{file_ext}"
            file_path = os.path.join(AVATARS_DIR, new_filename)
            
            with open(file_path, 'wb') as f:
                f.write(file_data)
            return {"success": True, "avatar_url": new_filename}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_local_avatar_url(self, avatar_path):
        if avatar_path == "default-avatar.jpg":
            return "/photo/default-avatar.jpg"
        else:
            return f"/{AVATARS_DIR}/{avatar_path}"

class EmailService:
    def __init__(self):
        self.supabase = SupabaseService()
    
    def generate_verification_code(self):
        return ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    def send_verification_email(self, to_email, code):
        for email, password in EMAIL_ACCOUNTS.items():
            try:
                msg = MIMEMultipart()
                msg['From'] = email
                msg['To'] = to_email
                msg['Subject'] = 'Код подтверждения регистрации - OneWeb'
                
                html = f"""
                <html>
                <body style="font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; color: #333;">
                    <div style="max-width: 500px; margin: 0 auto; background: white; border-radius: 20px; padding: 40px; box-shadow: 0 20px 40px rgba(0,0,0,0.1);">
                        <h2 style="color: #8a2be2; text-align: center; margin-bottom: 30px;">OneWeb - Подтверждение регистрации</h2>
                        <p style="font-size: 16px; line-height: 1.6; margin-bottom: 25px;">Благодарим за регистрацию! Ваш код подтверждения:</p>
                        <div style="background: linear-gradient(45deg, #8a2be2, #9b30ff); color: white; padding: 25px; border-radius: 15px; text-align: center; margin: 30px 0; font-size: 36px; font-weight: bold; letter-spacing: 8px; font-family: 'Courier New', monospace;">{code}</div>
                        <p style="font-size: 14px; color: #666; text-align: center; line-height: 1.5;">Код действителен 10 минут</p>
                        <div style="border-top: 1px solid #eee; margin-top: 30px; padding-top: 20px; text-align: center;"><p style="font-size: 12px; color: #999;">Команда OneWeb</p></div>
                    </div>
                </body>
                </html>
                """
                
                msg.attach(MIMEText(html, 'html'))
                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                server.login(email, password)
                server.send_message(msg)
                server.quit()
                print(f"Письмо отправлено с {email} на {to_email}")
                return True
            except Exception as e:
                print(f"Ошибка отправки с {email}: {e}")
                continue
        return False

class AuthHandler:
    def __init__(self):
        self.supabase = SupabaseService()
        self.email_service = EmailService()
        self.rate_limiter = RateLimiter(max_requests=5, window=300)
    
    def hash_password(self, password):
        salt = secrets.token_hex(32)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() + ':' + salt
    
    def verify_password(self, stored_password, provided_password):
        try:
            password_hash, salt = stored_password.split(':')
            return secrets.compare_digest(
                password_hash,
                hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt.encode(), 100000).hex()
            )
        except:
            return False
    
    def register_user(self, username, email, password, ip_address):
        if not self.rate_limiter.is_allowed(ip_address):
            return {'success': False, 'message': 'Слишком много запросов. Попробуйте позже.'}
        
        username = SecurityUtils.sanitize_input(username)
        email = SecurityUtils.sanitize_input(email).lower()
        
        if not SecurityUtils.validate_email(email):
            return {'success': False, 'message': 'Некорректный email'}
        
        if not SecurityUtils.validate_username(username):
            return {'success': False, 'message': 'Имя пользователя должно содержать 3-20 символов (a-z, -9, _, -)'}
        
        if not SecurityUtils.validate_password(password):
            return {'success': False, 'message': 'Пароль должен содержать минимум 8 символов, включая заглавные и строчные буквы и цифры'}
        
        if self.supabase.get_user_by_email(email):
            return {'success': False, 'message': 'Email уже зарегистрирован'}
        
        if self.supabase.get_user_by_username(username):
            return {'success': False, 'message': 'Username уже занят'}
        
        password_hash = self.hash_password(password)
        result = self.supabase.create_user(username, email, password_hash)
        
        if result["success"]:
            return {'success': True, 'message': 'Пользователь успешно зарегистрирован'}
        else:
            return {'success': False, 'message': f'Ошибка базы данных: {result.get("error", "Unknown error")}'}
    
    def login_user(self, identifier, password, ip_address):
        if not self.rate_limiter.is_allowed(ip_address):
            return {'success': False, 'message': 'Слишком много попыток входа. Попробуйте позже.'}
        
        identifier = SecurityUtils.sanitize_input(identifier).lower()
        
        user = None
        if '@' in identifier:
            user = self.supabase.get_user_by_email(identifier)
        else:
            user = self.supabase.get_user_by_username(identifier)
        
        if user and self.verify_password(user['password_hash'], password):
            avatar_url = self.supabase.get_avatar_url(user['avatar_url'])
            return {
                'success': True, 
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'avatar_url': avatar_url,
                    'created_at': user['created_at']
                }
            }
        else:
            return {'success': False, 'message': 'Неверный email/username или пароль'}

class SecureHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.auth_handler = AuthHandler()
        self.email_service = EmailService()
        self.supabase = SupabaseService()
        self.avatar_service = AvatarService()
        self.rate_limiter = RateLimiter(max_requests=100, window=60)
        super().__init__(*args, **kwargs)
    
    def get_client_ip(self):
        return self.client_address[0]
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_security_headers()
        self.end_headers()
    
    def send_security_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    
    def do_GET(self):
        if not self.rate_limiter.is_allowed(self.get_client_ip()):
            self.send_error(429, "Too Many Requests")
            return
        
        if self.path == '/':
            self.path = '/onion.html'
        
        if self.path.startswith('/api/'):
            self.handle_api_request()
        elif self.path.startswith(f'/{AVATARS_DIR}/'):
            self.serve_avatar()
        else:
            super().do_GET()
    
    def do_POST(self):
        if not self.rate_limiter.is_allowed(self.get_client_ip()):
            self.send_error(429, "Too Many Requests")
            return
        
        if self.path.startswith('/api/'):
            self.handle_api_request()
        else:
            super().do_POST()
    
    def serve_avatar(self):
        try:
            avatar_path = self.path[1:]
            if not os.path.exists(avatar_path):
                self.send_error(404)
                return
            
            with open(avatar_path, 'rb') as f:
                file_data = f.read()
            
            self.send_response(200)
            if avatar_path.endswith('.png'):
                self.send_header('Content-Type', 'image/png')
            else:
                self.send_header('Content-Type', 'image/jpeg')
            self.send_header('Content-Length', str(len(file_data)))
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(file_data)
        except:
            self.send_error(404)
    
    def handle_api_request(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 10 * 1024 * 1024:
                self.send_error(413, "Payload Too Large")
                return
                
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            if self.path == '/api/send_verification':
                self.handle_send_verification(data)
            elif self.path == '/api/verify_code':
                self.handle_verify_code(data)
            elif self.path == '/api/register':
                self.handle_register(data)
            elif self.path == '/api/login':
                self.handle_login(data)
            elif self.path == '/api/upload_avatar':
                self.handle_upload_avatar(data)
            else:
                self.send_error(404)
                
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            self.send_response(500)
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'message': 'Internal server error'}).encode())
    
    def handle_send_verification(self, data):
        email = data.get('email', '').lower()
        username = data.get('username', '')
        
        if not SecurityUtils.validate_email(email):
            self.send_json_response({'success': False, 'message': 'Некорректный email'})
            return
        
        if not SecurityUtils.validate_username(username):
            self.send_json_response({'success': False, 'message': 'Некорректное имя пользователя'})
            return
        
        if self.supabase.get_user_by_email(email):
            self.send_json_response({'success': False, 'message': 'Email уже зарегистрирован'})
            return
        
        if self.supabase.get_user_by_username(username):
            self.send_json_response({'success': False, 'message': 'Username уже занят'})
            return
        
        code = self.email_service.generate_verification_code()
        result = self.supabase.create_verification_code(email, code, username)
        if not result["success"]:
            self.send_json_response({'success': False, 'message': 'Ошибка сохранения кода'})
            return
        
        max_attempts = 3
        for attempt in range(max_attempts):
            if self.email_service.send_verification_email(email, code):
                self.send_json_response({'success': True, 'message': f'Код отправлен на {email}', 'attempt': attempt + 1})
                return
            time.sleep(2)
        
        self.send_json_response({'success': False, 'message': 'Не удалось отправить код после 3 попыток'})
    
    def handle_verify_code(self, data):
        email = data.get('email', '').lower()
        code = data.get('code', '')
        
        verification_data = self.supabase.get_verification_code(email, code)
        if verification_data:
            self.send_json_response({'success': True, 'message': 'Код подтвержден', 'username': verification_data['username']})
        else:
            self.send_json_response({'success': False, 'message': 'Неверный или устаревший код'})
    
    def handle_register(self, data):
        username = data.get('username', '')
        email = data.get('email', '').lower()
        password = data.get('password', '')
        code = data.get('code', '')
        
        verification_data = self.supabase.get_verification_code(email, code)
        if not verification_data:
            self.send_json_response({'success': False, 'message': 'Неверный код подтверждения'})
            return
        
        result = self.auth_handler.register_user(username, email, password, self.get_client_ip())
        if result['success']:
            self.supabase.delete_verification_code(email)
        
        self.send_json_response(result)
    
    def handle_login(self, data):
        identifier = data.get('identifier', '')
        password = data.get('password', '')
        
        result = self.auth_handler.login_user(identifier, password, self.get_client_ip())
        self.send_json_response(result)
    
    def handle_upload_avatar(self, data):
        try:
            file_data = base64.b64decode(data['file_data'])
            filename = SecurityUtils.sanitize_input(data['filename'])
            user_id = SecurityUtils.sanitize_input(str(data['user_id']))
            
            if not SecurityUtils.validate_file_extension(filename):
                self.send_json_response({'success': False, 'message': 'Недопустимый тип файла'})
                return
            
            if not SecurityUtils.validate_file_size(len(file_data)):
                self.send_json_response({'success': False, 'message': 'Файл слишком большой'})
                return
            
            result = self.supabase.upload_avatar_to_storage(file_data, filename, user_id)
            if result["success"]:
                if self.supabase.update_user_avatar(data['email'], result["avatar_url"]):
                    avatar_url = self.supabase.get_avatar_url(result["avatar_url"])
                    self.send_json_response({'success': True, 'avatar_url': avatar_url, 'message': 'Аватар успешно обновлен'})
                else:
                    self.send_json_response({'success': False, 'message': 'Ошибка обновления пользователя'})
            else:
                self.send_json_response({'success': False, 'message': f'Ошибка загрузки: {result["error"]}'})
                    
        except Exception as e:
            self.send_json_response({'success': False, 'message': f'Ошибка: {str(e)}'})
    
    def send_json_response(self, data):
        self.send_response(200)
        self.send_security_headers()
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

def open_browser():
    time.sleep(1)
    webbrowser.open('http://localhost:8000')

if __name__ == '__main__':
    port = 8000
    server_address = ('', port)
    httpd = HTTPServer(server_address, SecureHTTPRequestHandler)
    
    print(f'Server running at http://localhost:{port}')
    print('Security features:')
    print('- XSS Protection')
    print('- SQL Injection Prevention')
    print('- Rate Limiting')
    print('- Input Validation')
    print('- Secure Headers')
    print('- File Upload Security')
    
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nServer stopped')