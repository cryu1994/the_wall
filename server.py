from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import MySQLConnector
import re
import md5
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
app.secret_key = '1234qwer'
mysql = MySQLConnector(app, 'wall')


@app.route('/')
def index():
    return render_template('index.html')
app.run(debug=True)
