import os, re, secrets, sqlite3, time
try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
try:
    import requests
except ImportError:
    requests = None

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ImportError:
    Limiter = None
    get_remote_address = None

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, region_code_for_number
except ImportError:
    phonenumbers = None

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, 'numtrack.db')
DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('HTTPS','0') == '1',
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

if Limiter:
    limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["120 per minute"], storage_uri="memory://")
else:
    limiter = None


def now(): return datetime.now(timezone.utc).isoformat()

@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    if request.is_secure or app.config.get('SESSION_COOKIE_SECURE'):
        resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return resp

def external_lookup(number):
    key = os.environ.get('ABSTRACT_API_KEY')
    if not key or requests is None:
        return None
    try:
        r = requests.get('https://phonevalidation.abstractapi.com/v1/', params={'api_key': key, 'phone': number}, timeout=6)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict): return None
        return {
            'valid': bool(data.get('valid')),
            'international': data.get('international_format') or data.get('phone') or number,
            'country': (data.get('country') or {}).get('name') or data.get('country_name') or 'Unknown',
            'region': data.get('location') or data.get('registered_location') or 'Unknown',
            'operator': data.get('carrier') or 'Unknown',
            'country_code': (data.get('country') or {}).get('code') or data.get('country_code') or 'Unknown',
            'line_type': data.get('type') or data.get('line_type') or 'Unknown',
            'risk_score': data.get('risk_score'),
            'source': 'live_api'
        }
    except Exception:
        return None

class DBConn:
    def __init__(self, conn, postgres=False):
        self.conn = conn
        self.postgres = postgres
    def execute(self, sql, params=()):
        if self.postgres:
            sql = sql.replace('?', '%s')
        return self.conn.execute(sql, params)
    def executescript(self, script):
        if self.postgres:
            with self.conn.cursor() as cur:
                for stmt in script.split(';'):
                    stmt = stmt.strip()
                    if stmt:
                        cur.execute(stmt)
        else:
            self.conn.executescript(script)
    def commit(self):
        self.conn.commit()
    def close(self):
        self.conn.close()

def db():
    if 'db' not in g:
        if DATABASE_URL:
            if psycopg is None:
                raise RuntimeError('psycopg is required when DATABASE_URL is configured')
            g.db = DBConn(psycopg.connect(DATABASE_URL, row_factory=dict_row), True)
        else:
            conn = sqlite3.connect(DB)
            conn.row_factory = sqlite3.Row
            g.db = DBConn(conn, False)
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    c = g.pop('db', None)
    if c:
        c.close()

def init_db():
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError('DATABASE_URL is set but psycopg is not installed')
        c = DBConn(psycopg.connect(DATABASE_URL, row_factory=dict_row), True)
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          is_admin BOOLEAN DEFAULT FALSE, created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports(
          id BIGSERIAL PRIMARY KEY, user_id BIGINT, number TEXT NOT NULL,
          type TEXT NOT NULL CHECK(type IN ('spam','scam')), details TEXT,
          status TEXT NOT NULL DEFAULT 'pending', created TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS lookups(
          id BIGSERIAL PRIMARY KEY, user_id BIGINT, number TEXT NOT NULL,
          country TEXT, region TEXT, operator TEXT, valid BOOLEAN, created TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_reports_number_status ON reports(number,status);
        CREATE INDEX IF NOT EXISTS idx_lookups_created ON lookups(created);
        """)
    else:
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        c = DBConn(conn, False)
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          is_admin INTEGER DEFAULT 0, created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, number TEXT NOT NULL,
          type TEXT NOT NULL CHECK(type IN ('spam','scam')), details TEXT,
          status TEXT NOT NULL DEFAULT 'pending', created TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS lookups(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, number TEXT NOT NULL,
          country TEXT, region TEXT, operator TEXT, valid INTEGER, created TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_reports_number_status ON reports(number,status);
        CREATE INDEX IF NOT EXISTS idx_lookups_created ON lookups(created);
        """)
    admin_email = os.environ.get('ADMIN_EMAIL','admin@numtrackbd.com').lower()
    if not c.execute('SELECT 1 FROM users WHERE email=?',(admin_email,)).fetchone():
        admin_password = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(18)
        c.execute('INSERT INTO users(name,email,password_hash,is_admin,created) VALUES(?,?,?,?,?)',
                  ('Administrator',admin_email,generate_password_hash(admin_password),bool(DATABASE_URL) or 1,now()))
        print(f'Initial admin password: {admin_password}')
    c.commit()
    c.close()

def csrf_token():
    if 'csrf' not in session: session['csrf'] = secrets.token_urlsafe(24)
    return session['csrf']
app.jinja_env.globals['csrf_token'] = csrf_token

@app.before_request
def csrf_check():
    if request.method == 'POST':
        token = request.form.get('_csrf') or request.headers.get('X-CSRF-Token')
        if not token or token != session.get('csrf'):
            return 'CSRF validation failed', 400

def login_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get('uid'):
            flash('Please log in first.')
            return redirect(url_for('login', next=request.path))
        return f(*a, **kw)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get('admin'):
            flash('Administrator access required.')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapped

def normalize(raw):
    s = (raw or '').strip()
    digits = re.sub(r'\D','',s)
    if s.startswith('00'): return '+' + digits[2:]
    if digits.startswith('01') and len(digits) == 11: return '+880' + digits[1:]
    if s.startswith('+'): return '+' + digits
    return '+' + digits if digits else ''

def lookup_number(raw):
    n = normalize(raw)
    out = {'input': n, 'valid': False, 'country':'Unknown', 'region':'Unknown', 'operator':'Unknown', 'international':n, 'country_code':'Unknown', 'line_type':'Unknown', 'risk_score':None, 'source':'local'}
    if not n: return out
    live = external_lookup(n)
    if live:
        live['input'] = n
        return live
    if not phonenumbers:
        out['valid'] = bool(re.fullmatch(r'\+[0-9]{7,15}', n)); return out
    try:
        x = phonenumbers.parse(n, None)
        out['valid'] = phonenumbers.is_valid_number(x)
        out['international'] = phonenumbers.format_number(x, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        out['country'] = geocoder.country_name_for_number(x,'en') or 'Unknown'
        out['region'] = geocoder.description_for_number(x,'en') or 'Unknown'
        out['operator'] = carrier.name_for_number(x,'en') or 'Unknown'
        out['country_code'] = region_code_for_number(x) or 'Unknown'
        out['line_type'] = str(phonenumbers.number_type(x)).replace('_',' ').title()
    except Exception: pass
    return out

def risk_for(number):
    rows = db().execute("SELECT type,COUNT(*) n FROM reports WHERE number=? AND status='approved' GROUP BY type",(number,)).fetchall()
    counts = {r['type']:r['n'] for r in rows}
    if counts.get('scam'): risk='High Risk'
    elif counts.get('spam'): risk='Caution'
    else: risk='No approved reports'
    return counts.get('spam',0), counts.get('scam',0), risk

@app.context_processor
def globals_ctx(): return {'current_user': session.get('name'), 'is_admin': session.get('admin',False)}

@app.get('/health')
def health():
    return jsonify(status='ok', service='numtrack-bd')

@app.route('/')
def home(): return render_template('home.html')

@app.post('/lookup')
def lookup_route():
    r = lookup_number(request.form.get('number',''))
    if not r['input']:
        flash('Enter a phone number.')
        return redirect(url_for('home'))
    spam, scam, risk = risk_for(r['input']); r.update(spam=spam, scam=scam, risk=risk)
    c=db(); c.execute('INSERT INTO lookups(user_id,number,country,region,operator,valid,created) VALUES(?,?,?,?,?,?,?)',
      (session.get('uid'),r['input'],r['country'],r['region'],r['operator'],int(r['valid']),now())); c.commit()
    return render_template('result.html', r=r)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        name=request.form.get('name','').strip(); email=request.form.get('email','').strip().lower(); pw=request.form.get('password','')
        if len(name)<2 or '@' not in email or len(pw)<8:
            flash('Use a valid name/email and a password of at least 8 characters.')
        else:
            try:
                c=db(); c.execute('INSERT INTO users(name,email,password_hash,created) VALUES(?,?,?,?)',(name,email,generate_password_hash(pw),now())); c.commit()
                flash('Registration successful. You can now log in.'); return redirect(url_for('login'))
            except sqlite3.IntegrityError: flash('That email is already registered.')
    return render_template('auth.html', mode='Register')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); pw=request.form.get('password','')
        u=db().execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        if u and check_password_hash(u['password_hash'],pw):
            session.clear(); session['csrf']=secrets.token_urlsafe(24); session.update(uid=u['id'],name=u['name'],admin=bool(u['is_admin']))
            nxt=request.args.get('next')
            return redirect(nxt if nxt and nxt.startswith('/') else (url_for('admin') if u['is_admin'] else url_for('home')))
        flash('Invalid email or password.')
    return render_template('auth.html', mode='Login')

@app.get('/logout')
def logout(): session.clear(); return redirect(url_for('home'))

@app.post('/report')
@login_required
def report():
    n=normalize(request.form.get('number','')); typ=request.form.get('type'); details=request.form.get('details','').strip()[:1000]
    if typ not in ('spam','scam') or not n: flash('Invalid report.'); return redirect(url_for('home'))
    c=db(); c.execute('INSERT INTO reports(user_id,number,type,details,created) VALUES(?,?,?,?,?)',(session['uid'],n,typ,details,now())); c.commit()
    flash('Report submitted. An administrator will review it.'); return redirect(url_for('home'))

@app.get('/account')
@login_required
def account():
    c=db(); reports=c.execute('SELECT * FROM reports WHERE user_id=? ORDER BY id DESC LIMIT 20',(session['uid'],)).fetchall(); lookups=c.execute('SELECT * FROM lookups WHERE user_id=? ORDER BY id DESC LIMIT 20',(session['uid'],)).fetchall()
    return render_template('account.html',reports=reports,lookups=lookups)

@app.get('/admin')
@admin_required
def admin():
    c=db(); stats={
      'users':c.execute('SELECT COUNT(*) FROM users').fetchone()[0],
      'lookups':c.execute('SELECT COUNT(*) FROM lookups').fetchone()[0],
      'reports':c.execute('SELECT COUNT(*) FROM reports').fetchone()[0],
      'pending':c.execute("SELECT COUNT(*) FROM reports WHERE status='pending'").fetchone()[0],
    }
    reports=c.execute('SELECT r.*,u.name user_name,u.email FROM reports r LEFT JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 100').fetchall()
    users=c.execute('SELECT id,name,email,is_admin,created FROM users ORDER BY id DESC LIMIT 100').fetchall()
    return render_template('admin.html',stats=stats,reports=reports,users=users)

@app.post('/admin/report/<int:rid>/<action>')
@admin_required
def moderate(rid,action):
    status={'approve':'approved','reject':'rejected','pending':'pending'}.get(action)
    if not status: return 'Invalid action',400
    c=db(); c.execute('UPDATE reports SET status=? WHERE id=?',(status,rid)); c.commit(); return redirect(url_for('admin'))

@app.get('/api/lookup')
def api_lookup():
    r=lookup_number(request.args.get('number','')); spam,scam,risk=risk_for(r['input']); r.update(spam_reports=spam,scam_reports=scam,risk=risk)
    return jsonify(r)

@app.errorhandler(404)
def not_found(e): return render_template('404.html'),404
    
init_db()
if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=False)
# PostgreSQL এর জন্য psycopg2 বা SQLAlchemy ব্যবহার করা থাকলে:
@app.route('/admin-users-count-9988') # /admin-users-count-9988 এটি আপনার গোপন লিংক
def admin_users_count():
    try:
        # যদি psycopg2 দিয়ে সরাসরি SQL কুয়েরি চালান:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users;") # 'users' টেবিলের নাম যা আপনার DB-তে আছে
        count = cursor.fetchone()[0]
        cursor.close()
        return f"<h2>Total Registered Users: {count}</h2>"
    except Exception as e:
        return f"Error fetching count: {str(e)}"
