from flask import Flask, render_template, redirect, request, session, flash, escape
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)

#imported the random password generator
bcrypt = Bcrypt(app)

app.secret_key = '1234qwer'
mysql = MySQLConnector(app, 'thewall')

#setting the route to index.html as soon as user reaches the page
@app.route('/')
def index():
    if 'user_id' and 'first_name' in session:
        return redirect('/sueccess')
    return render_template('index.html')
@app.route('/users', methods=['POST'])
def create():
    #giving the request.form value to the post
    post = request.form

    #checking to see if user put infomation
    if 'name' in post  and 'email' in post and 'password' in post and 'conf_password' in post:

        #used escape to insert html
        name = escape(post['name'])
        email = escape(post['email'])
        password = escape(post['password'])
        conf_password = escape(post['conf_password'])

        #setting error as 0
        error = 0
        #conditional check statement
        if not name:
            error += 1
            flash("Name cannot be empty!", "name")
        if not email:
            error += 1
            flash("Email cannot be empty!", "email")
        if not EMAIL_REGEX.match(email):
            error += 1
            flash("Invalid email address!", 'email')
        if not password:
            error += 1
            flash('password is empty!', 'password')
        if not conf_password:
            error += 1
            flash("Confirm your password!", 'conf_password')
        if  password != conf_password:
            error += 1
            flash("password not match", 'password')

        #if there were no errors
        if error < 1:
            #generate the password and take it to the database
            encrypted_password = bcrypt.generate_password_hash(password)
            #insert user into database
            query = "INSERT INTO users(name, email, password, created_at, updated_at)VALUES(:name, :email, :password, NOW(), NOW())";
            data = {
                #make sure we insert user name as lower case letters
                'name': name.lower(),
                'email': email,
                'password': encrypted_password
                }
            #set the user_id as variable
            user_id = mysql.query_db(query, data)

            #store user_id and first_name into session so can use it in the success page
            session['user_id'] = int(user_id)
            session['name'] = name
            return redirect('/success')
        #if there were error, redirect to register page
        return redirect('/')

#creating a login page
@app.route('/users/login', methods=['post'])
def login():
    #excract long -v to short -v
    post = request.form

    #test for post data
    if 'email' in post and 'password' in post:
        email = escape(post['email']).lower()
        password = escape(post['password'])

    if email and password:

        query = "SELECT * FROM users WHERE email = :email"
        data = {
            'email': email
        }
        user = mysql.query_db(query, data)

        if user:


            if bcrypt.check_password_hash(user[0]['password'], password):

                #set session and render user to success page
                                #make sure to grab one user who belongs to the email
                session['user_id'] = int(user[0]['id'])
                session['name'] = user[0]['name']
                return redirect('/success')

        flash("Email and password does not match with our records", 'log_email')

    #set errors for empty inputs
    else:
        if not post['email']:
            flash("Empty Email!", 'log_email')
        if not post['password']:
            flash("Empty password!", 'log_password')
    #if user faild to load the success page, redirect to login page
        return redirect('/')

@app.route('/success')
def success():
    #validate session
    if 'user_id' in session and 'name' in session:

        #then get the message
        query = "SELECT messages.id, text, DATE_FORMAT(messages.created_at, '%a %b %M %Y, %r') as created_at, users.id as author_id, users.name as author_name from messages join users on messages.user_id = users.id ORDER BY created_at DESC";
        message = mysql.query_db(query)

        #also comments
        query = "SELECT comments.id, message_id, text, DATE_FORMAT(comments.created_at, '%a %b %M %Y, %r') as created_at, comments.updated_at, users.id AS author_id, users.name AS author_name FROM comments JOIN users ON comments.user_id = users.id"
        comments = mysql.query_db(query)
        return render_template('success.html', messages=message, comments=comments)
    return redirect('/')

@app.route('/messages', methods=['post'])
def messages():
    post = request.form
    if 'message' in post:
        query = "INSERT INTO messages(text, user_id, created_at, updated_at) VALUES (:text, :user_id, NOW(), NOW())";
        data = {
            'text': post['message'],
            'user_id': session['user_id']
        }
        mysql.query_db(query, data)
    return redirect('/success')

@app.route('/message/delete/<id>')
def delete_message(id):
    query = "SELECT * FROM messages WHERE id = :id AND user_id = :user_id"
    data = {
        'id': id,
        'user_id': session['user_id']
    }
    messages = mysql.query_db(query, data)

    if messages:
        data = {'id': id}

        query = "DELETE FROM comments WHERE message_id = :id"
        mysql.query_db(query, data)

        query = "DELETE FROM messages WHERE id = :id"
        mysql.query_db(query, data)
    return redirect('/success')

@app.route('/comment', methods=['post'])
def comment():
    post = request.form
    print post
    if 'text' in post and 'message_id' in post:
        query = 'INSERT INTO comments (text, message_id, user_id, created_at, updated_at) VALUES (:text, :message_id, :user_id, NOW(), NOW())'
        data = {
            'text': post['text'],
            'message_id': post['message_id'],
            'user_id': session['user_id']
        }
        mysql.query_db(query, data)
    return redirect('/success')


@app.route('/comment/delete/<id>')
def delete_comment(id):
    query = "SELECT * FROM comments WHERE id = :id AND user_id = :user_id"
    data = {
        'id': id,
        'user_id': session['user_id']
    }
    mysql.query_db(query, data)
    comments = mysql.query_db(query, data)
    if comments:
        query = "DELETE FROM comments WHERE id = :id"
        data = {
            'id': id
        }
        mysql.query_db(query, data)
    return redirect('/success')

@app.route('/logout')
def logout():
    # clear our session variables
    session.pop('user_id', None)
    session.pop('name', None)

    # redirect to login
    return redirect('/')
app.run(debug=True)
