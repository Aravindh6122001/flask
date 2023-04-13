from flask import Flask, request, session, redirect, url_for, render_template, flash,jsonify
import psycopg2 # psycopg2 
import psycopg2.extras
from functools import wraps
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
import os
from dotenv import load_dotenv
import re 
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv() 
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

app = Flask(__name__)
app.secret_key = os.getenv("key")
# JWT_SECRET_KEY = 'JWT_SECRET_KEY'
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
JWTManager(app)
 
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)
cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)


@app.route('/register',methods=['POST'])
def register():
    #  if request.method == 'POST':
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
            
       cursor.execute('SELECT * FROM users WHERE (username,email) = (%s,%s)', (new_data['username'],new_data['email'],))
       account = cursor.fetchone()
       

       if account is None:
            return jsonify(message="Login Failed,please try again"), 401
       password_rs = account['password']
       
       if check_password_hash(password_rs,new_data['password']):
                  refresh = create_refresh_token(identity = account['password'])
                  access = create_access_token(identity = account['password'])
                  return ({
                        'user':{
                            'refresh' : refresh,
                            'access' : access,
                            'username' : account['username'],
                            'email' : account['email']
                        },
                        "success":"Login successful"
                    })
    return ({
            "error":"Login Unsuccessful. Please check username and password"
        })  
     
       


@app.route('/login/<string:name>',methods=['GET'])
def login_item(name):
 if request.method == 'GET':

   cursor.execute("SELECT fullname,email FROM users")
   
   stores = cursor.fetchall()
   for store in stores:
      if (store[0] == name):
        return jsonify(store[1] ,"message created successfully!!")
    
   return jsonify("message : not found")

# User.query.filter_by(id=current_user_id).first()

@app.route('/protected', methods=['GET'])

    

@app.route("/update_details", methods=["PATCH","DELETE","GET"])
@jwt_required()
def update():
    required_data = request.get_json()
    
    if request.method == "PATCH":
        new_data = {
            'username': required_data['username'],
            'email':required_data['email']
            }
        
        cursor.execute('SELECT * FROM users WHERE (username,email) = (%s,%s)', (new_data['username'],new_data['email'],))
        account = cursor.fetchall()
        if account is None:
            return jsonify(message="Invalid details")
        
        try:
            cursor.execute("UPDATE users SET username=%s WHERE email=%s",(new_data['username'], new_data['email']))
            conn.commit()
            # return jsonify({'message': f'Protected endpoint. Welcome, {account['username']}!'}), 200
            return jsonify(message="Updated")
       
        except:
            return jsonify(message= "Patch error")
      
    
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
       
    
if __name__ == "__main__":
    app.run(host='127.0.0.1',port=5017,debug=True)