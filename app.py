from flask import Flask, render_template, request
import mysql.connector
import bcrypt


app = Flask(__name__)

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="google"
    )

@app.route('/')
def home():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    emailid = request.form['emailid']
    mobile = request.form['mobile']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = "INSERT INTO users (username, password, emailid, mobile) VALUES (%s, %s, %s, %s)"
    val = (username, hashed_password, emailid, mobile)
    cursor.execute(sql, val)
    conn.commit()
    cursor.close() 
    return "Registration successful! <a href='/login'>Login</a>"

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['GET','POST'])
def login_post():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')
    conn = get_db_connection()
    cursor = conn.cursor()
    sql = "SELECT password FROM users WHERE username = %s"
    cursor.execute(sql, (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        stored_hashed_password = result[0]
        if bcrypt.checkpw(password, stored_hashed_password.encode('utf-8')):
            return "Login successful! <a href='/change'>Change Password</a>"
        else:
            return "Invalid credentials. <a href='/login'>Try again</a>"
    else:
        return "Invalid Username or Password. <a href='/login'>Try again</a>"
    
@app.route('/change', methods=['GET','POST'])
def change():
    if request.method == 'GET':
        return render_template('home.html')
    
    username = request.form['username']
    oldpassword = request.form['oldpassword']
    newpassword = request.form['newpassword']
    confirmpassword = request.form['changepassword']
    
    
    if newpassword != confirmpassword:
        return "New password and confirm password do not match. <a href='/change'>Try again</a>"
    
    try:
        conn=get_db_connection()
        cur = conn.cursor(buffered=True)  # ✅ Cursor defined here

        # ✅ Fetch hashed password from DB
        cur.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cur.fetchone()

        if not result:
            return "❌ Username not found. <a href='/change'>Try again</a>"

        stored_hash = result[0]
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')

        if not bcrypt.checkpw(oldpassword.encode('utf-8'), stored_hash):
            return "❌ Old password is incorrect. <a href='/change'>Try again</a>"

        # ✅ Hash and update new password
        new_hash = bcrypt.hashpw(newpassword.encode('utf-8'), bcrypt.gensalt())
        cur.execute("UPDATE users SET password=%s WHERE username=%s",
                    (new_hash.decode('utf-8'), username))
        conn.commit()

        cur.close()
        conn.close()

        return "✅ Password changed successfully! <a href='/login'>Login again</a>"

    except Exception as e:
        return f"❌ An error occurred: {str(e)} <a href='/change'>Try again</a>"
    
if __name__ == '__main__':
    app.run(debug=True)
        