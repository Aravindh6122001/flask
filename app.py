from flask import Flask, request, session, redirect, url_for, render_template, flash,jsonify
import psycopg2 # psycopg2 
import psycopg2.extras
from functools import wraps
import re 
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
 
app = Flask(__name__)
app.secret_key = 'cairo-ednalan'
 
DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASS = "Aravindh@01"
 
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)
cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)


def validate_access_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = request.headers.get('Authorization')

        if not access_token:
            return jsonify({'error': 'Access token is missing'}), 401
        try:
            data = jwt.decode(access_token,app.config["secret_key"]) 
        except:
            return jsonify({'error': 'Invalid Access token'}), 401

        return f(*args, **kwargs)
            
    return decorated_function

     #   auth = request.authorization
     #      if auth and auth.password == 'password':
     #       access_token = jwt.encode({'user': auth.username,'exp':datetime.datetime.utcnow() + datetime.timedelta      (second=30)})
          
     #      return jsonify({'token' : access_token.decode('UTF-8')})
     
     #    return jsonify("could not verify")


@app.route('/register',methods=['GET','POST'])
def register():
     if request.method == 'POST':
       required_data = request.get_json()
       if not required_data:
            return jsonify(message="No JSON data provided"), 400
        
       required_fields = ['fullname', 'username','email', 'password']
       for field in required_fields:
            if field not in required_data:
                return jsonify(message=f"{field} is required"), 400
      
       new_data = {
          'fullname' : required_data['fullname'],
          'username' : required_data['username'],
          'password' : required_data['password'],
          'email' : required_data['email']
       }
       
       _hashed_password = generate_password_hash(new_data['password'])
       
            
       cursor.execute("INSERT INTO users (fullname, username, password, email) VALUES (%s,%s,%s,%s)", (new_data['fullname'], new_data['username'],_hashed_password, new_data['email']))
       conn.commit()

       return jsonify(new_data)


@app.route('/login',methods=['GET','POST'])
@validate_access_token
def login():
    if request.method == 'POST':
       required_data = request.get_json()
       if not required_data:
            return jsonify(message="No JSON data provided"), 400
        
       required_fields = ['username','email', 'password']
       for field in required_fields:
            if field not in required_data:
                return jsonify(message=f"{field} is required"), 400
      
       new_data = {
          'username' : required_data['username'],
          'password' : required_data['password'],
          'email' : required_data['email']
       }       
            
       cursor.execute('SELECT password FROM users WHERE (username,email) = (%s,%s)', (new_data['username'],new_data['email'],))
       account = cursor.fetchone()
       

       if account is None:
            return jsonify(message="Login Failed,please try again"), 401
       password_rs = account['password']
 
       if check_password_hash(password_rs,new_data['password']):
            return jsonify(message = "Login successful"),200
       else:
            return jsonify(message="Wrong Password"),500
   
    elif request.method == 'GET':
         return jsonify("This is get method")      


@app.route('/login/<string:name>',methods=['GET','POST'])
def login_item(name):
 if request.method == 'GET':

   cursor.execute("SELECT fullname,email FROM users")
   
   stores = cursor.fetchall()
   for store in stores:
      if (store[0] == name):
        return jsonify(store[1] , "message created successfully!!")
    
   return jsonify("message : not found")



@app.route("/delete", methods=["DELETE"])
def delete():
    required_data = request.get_json()
    
    if request.method == "DELETE":
        new_data = {
            'username': required_data['username']
            }
    
    try:
        cursor.execute("DELETE FROM users WHERE username=%s", (new_data['username'],))
        conn.commit()
        return jsonify(message="content deleted successful")
   
    except:
         return jsonify(message= "there was a problem deleting that row")
    


@app.route("/patch", methods=["PATCH"])
def update():
    required_data = request.get_json()
    if request.method == "PATCH":
        new_data = {
            'username': required_data['username'],
            'email':required_data['email']}
        try:
            account = cursor.execute("UPDATE users SET username=%s WHERE email=%s", (new_data['username'], new_data['email']))
            conn.commit()
            return jsonify(message="Updated")
       
        except:
            return jsonify(message= "Patch error")
       
    
if __name__ == "__main__":
    app.run(host='127.0.0.1',port=5017,debug=True)