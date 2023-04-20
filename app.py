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
# JWT_SECRET_KEY = 'JWT_SECRET_KEY'
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


@app.route('/users/<int:user_id>', methods=["GET"]) #dispaly users data by comparing two tables
# @jwt_required()
def user(user_id):
    if request.method == "GET":
        
        cursor.execute("SELECT u.id, u.username, u.email, u.role_, a.admin_name FROM users u JOIN admin a ON u.id = a.admin_id WHERE u.id = %s;",(user_id,))
        account = cursor.fetchone()

        if account:
            required_data = {
                "id": account[0], 
                "username": account[1], 
                "email": account[2], 
                "role": account[3], 
                "admin_name": account[4]
                }
            return jsonify({"id-info": required_data})
        else:
            return jsonify({"message": "User not found"}), 404


@app.route('/display', methods=['GET']) #will display all details based on the role you search eg."role" : "manager" then all managers respective details will be shown
def display():
    required_data = request.get_json()
    
    new_data = {
        'role': required_data.get('role')
    } 

    cursor.execute("SELECT username, email, role_, manager_id FROM users WHERE role_ = %s", (new_data['role'],))
    accounts = cursor.fetchall()

    results = []
    for account in accounts:
        result = {
            "username": account[0], 
            "email": account[1],
            "role": account[2],
            "manager_id": account[3]
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
            'username': required_data['username'],
            'role':required_data['role'],
            'manager_id':required_data['manager_id']
            }
        
        cursor.execute("UPDATE users SET manager_id = %s WHERE username = %s AND role_= %s",(new_data['manager_id'],new_data['username'],new_data['role']))
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