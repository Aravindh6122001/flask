from flask import Flask, request, session, redirect, url_for, render_template, flash,jsonify
import psycopg2 # psycopg2 
import psycopg2.extras
import re 
from werkzeug.security import generate_password_hash, check_password_hash
 
app = Flask(__name__)
app.secret_key = 'cairo-ednalan'

# stores = [
#     {
#     'name':'name1',
#     'items':[{
#         'name':'bag',
#         'id':1
#     }]
#     },
    
#     {
#     'name':'name2',
#     'items':[{
#         'name':'phone',
#         'id':2
#     }]
#     }
# ]
 
DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASS = "Aravindh@01"
 
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

# @app.route('/store/<string:name>')
# def get_store(name):
#     for store in stores:
#        if (store['name'] == name):
#            return jsonify(store['name'])
       
#     return jsonify("{message : not found}")
  
  
# @app.route('/store/<string:name>/item')
# def get_store_item(name):
#     for store in stores:
#       if (store['name'] == name):
#         return jsonify(store['items'])
    
#     return jsonify({"message : not found"})

 
@app.route('/')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    
    return redirect(url_for('login'))
 
@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
   
   
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
 
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
 
        if account:
            password_rs = account['password']
            print(password_rs)
           
            if check_password_hash(password_rs, password):
            
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                return redirect(url_for('home'))
            else:
               
                flash('Incorrect username/password')
                
        else:
           
            flash('Incorrect username/password')
 
    return render_template('login.html')
  
@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
 
   
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
    
        _hashed_password = generate_password_hash(password)
 
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        account = cursor.fetchone()
        print(account)
    
        if account:
            flash('Account already exists!')
        if not username or not password or not email:
            flash('Please fill out the form!')
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        if not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        if not re.match(r'[A-Za-z0-9]+', password):
            flash('Password must contain only characters and numbers!')
        else:
          
            cursor.execute("INSERT INTO users (fullname, username, password, email) VALUES (%s,%s,%s,%s)", (fullname, username, _hashed_password, email))
            conn.commit()
            flash('You have successfully registered!')
            
            
    elif request.method == 'POST':
        flash('Please fill out the form!')
    return render_template('register.html')
   
   
@app.route('/logout')
def logout():
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   return redirect(url_for('login'))
  
@app.route('/profile')
def profile(): 
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
   
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM users WHERE id = %s', [session['id']])
        account = cursor.fetchone()
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))
 
if __name__ == "__main__":
    app.run(host='127.0.0.1',port=5016,debug=True)