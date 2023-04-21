from flask import Flask, request, session, redirect, url_for, render_template, flash,jsonify
import psycopg2 # psycopg2 
import psycopg2.extras
from functools import wraps
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
import os
from dotenv import load_dotenv
from datetime import timedelta
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
JWT_SECRET_KEY = 'JWT_SECRET_KEY'
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
JWTManager(app)
 
conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)
cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

@app.route('/login',methods=['GET','POST'])#login
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
                  access_token = create_access_token(identity=account[0], expires_delta=timedelta(hours=1))
                  refresh = create_refresh_token(identity = account['password'])
                  return ({
                        'user':{
                            'refresh' : refresh,
                            'access_token' : access_token,
                            'username' : account['username'],
                            'email' : account['email']
                        },
                        "success":"Login successful"
                    })
    return ({
            "error":"Login Unsuccessful. Please check username and password"
        })  
     
       
@app.route('/login/<string:name>',methods=['GET']) # will display email of the employee if the user knows the name 
def login_item(name):
 if request.method == 'GET':

   cursor.execute("SELECT fullname,email FROM users")
   
   stores = cursor.fetchall()
   for store in stores:
      if (store[0] == name):
        return jsonify(store[1] ,"message created successfully!!")
    
   return jsonify("message : not found")

        
@app.route('/register', methods=["POST"])#only admin can register a user
@jwt_required()
def register():
 if request.method == "POST":
     
    current_user_id = get_jwt_identity()
    required_data = request.get_json()
    
    new_data = {
          'fullname' : required_data["fullname"],  
          'username' : required_data['username'],
          'password' : required_data["password"],
          'email' : required_data['email'],
          'user_role' : required_data["user_role"],
          'manager_id' : required_data["manager_id"]       
       } 
    
    _hashed_password = generate_password_hash(new_data['password'])

    cursor.execute("SELECT role_ FROM users WHERE id=%s",(current_user_id,))
    role = cursor.fetchone()[0]
    if role != "Admin":
        return jsonify({"message": "Only an Admin can add a new employee."}), 403
    
    if new_data['user_role'] not in ['Employee', 'Manager']:
        return jsonify ({"message": "Invalid role"}), 403

    cursor.execute("INSERT INTO users (fullname,username,password,email,role_,manager_id) VALUES (%s,%s, %s, %s, %s,%s)", (new_data["fullname"],new_data["username"],_hashed_password,new_data["email"],new_data["user_role"],new_data["manager_id"]))
    conn.commit()
    
    return jsonify ({"message": "New user added successfully."})

@app.route('/users/<int:id>', methods=["GET"])
def user_details(id):
    
    if request.method == "GET":
        cursor.execute("SELECT u.id, u.username, u.email, u.role_, m.manager_id, m.username FROM users u INNER JOIN users m ON u.manager_id = m.id WHERE u.id = %s",(id,))
        user = cursor.fetchone()
        
        required_data = {
                "id": user[0], 
                "username": user[1], 
                "email": user[2], 
                "role": user[3], 
                "manager_id": user[4],
                "manager_name": user[5]
                }
        
        return jsonify(required_data)
    
    else:
        return("Invalid Request method")

            
@app.route('/display', methods=['GET']) #will display all employees under a manager and details based on the role you search eg."role" : "manager" then all managers respective details will be shown
def display():
    required_data = request.get_json()
    
    if 'id' in required_data and required_data['id']:
        new_data = {
            'id': required_data['id']
        } 
        cursor.execute("SELECT * FROM users WHERE manager_id = %s", (new_data['id'],))

    if 'role' in required_data and required_data['role']:
          new_data = {
            'role': required_data['role']
          } 
          cursor.execute("SELECT * FROM users WHERE role_ = %s", (new_data['role'],))
 
    accounts = cursor.fetchall()

    results = []
    for account in accounts:
        result = {
            "username": account['username'], 
            "email": account['email'],
            "role": account['role_'],
            "manager_id": account['manager_id']
        }
        results.append(result)

    return jsonify(results)


@app.route("/update_details", methods=["PATCH","DELETE","GET"]) #will do update,delete
@jwt_required()

def update():
   
    required_data = request.get_json()
    current_user_id = get_jwt_identity()
    
    new_data = {'username': required_data['username'],}
    
    cursor.execute("SELECT role_ FROM users WHERE id=%s",(current_user_id,))
    role = cursor.fetchone()[0]
    print(role)
    
    if role != "Admin":
         return jsonify({"message": "Only an Admin can add a new employee."}), 403 
    
    if request.method == "PATCH": # only admin can update users reporting manager and change his role
        new_data = {
            'id' : required_data['id'],
            'username': required_data['username'],
            'role':required_data['role'],
            'manager_id':required_data['manager_id']
            }
        
        cursor.execute("UPDATE users SET role_ = %s WHERE username = %s AND manager_id = %s",(new_data['role'],new_data['username'],new_data['manager_id']))
        conn.commit()
        cursor .execute("INSERT INTO manager (id,manager_name) VALUES (%s,%s)",(new_data["id"],new_data["username"]))
        conn.commit()
        return jsonify(message="Updated")
      
    
    if request.method == "DELETE":
        current_user_id = get_jwt_identity()     
    try:
        cursor.execute("DELETE FROM users WHERE username=%s", (new_data['username'],))
        conn.commit()
        return jsonify(message="content deleted successful")
   
    except:
         return jsonify(message= "there was a problem deleting that row")   

             
           
if __name__ == "__main__":
    app.run(host='127.0.0.1',port=5017,debug=True)