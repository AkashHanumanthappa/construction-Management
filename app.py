from flask import Flask, render_template, request, redirect, session, url_for, flash,make_response
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, ValidationError, Length
import bcrypt, os
import pymysql
from flask_mail import Mail
from mysql.connector.errors import IntegrityError
import email_validator
from flask_mysqldb import MySQL

app = Flask(__name__)
app.config['MAIL_SERVER']="smtp.gmail.com"
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = "akashhanumanthappa.official@gmail.com"
app.config['MAIL_PASSWORD']="rfjd xgpl xyjb yajv"
app.config['MAIL_USE_SSL']=True

mail=Mail(app)

app.secret_key = os.urandom(24)
conn = pymysql.connect(host="localhost", user="root", password="akash@123", database="construction")
#conn = mysql.connector.connect(host="localhost", user="root", password="akash@123", database="construction")
cursor = conn.cursor()


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_email(self, field):
        cursor.execute("SELECT * FROM `signup` WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        if user:
            raise ValidationError('Email Already taken')


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ApplicationForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    name = StringField('name', validators=[DataRequired()])
    cust_phone = StringField('phone', validators=[DataRequired(), Length(min=10, max=10)])
    cust_add = StringField('address', validators=[DataRequired()])
    project = StringField('Project Name', validators=[DataRequired()])
    submit = SubmitField('Apply')

    def validate_email(self, field):
        cursor.execute("SELECT * FROM `customer` WHERE cust_email=%s", (field.data,))
        user = cursor.fetchone()
        if user:
            raise ValidationError('Email Already taken')

    def validation_phone(self):
        if len('phone')!=10:
           raise ValidationError('invalid phone number')


class updateForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    cust_phone = StringField('phone', validators=[DataRequired(), Length(10)])
    cust_add = StringField('address', validators=[DataRequired()])
    project = StringField('Project Name', validators=[DataRequired()])
    submit = SubmitField('update')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor.execute("SELECT * FROM `signup` WHERE email=%s", (email,))
        user = cursor.fetchone()
        if user and password  == user[3] :
            session['user_id'] = user[0]
            return redirect(url_for('home'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))
    return render_template('login.html', form=form)


@app.route('/')
def home():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor.execute("SELECT * FROM `signup` WHERE id=%s", (user_id ,))
        signup= cursor.fetchone()
        if signup:
            return render_template('index.html',signup=signup)
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('user_id',None)
    return redirect(url_for('login'))



@app.route('/adminlogin', methods=['GET', 'POST'])
def adminlogin():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor.execute("SELECT * FROM `admins` WHERE email=%s", (email,))
        user = cursor.fetchone()
        if user and password  == user[1] :
            session['email'] = user[0]
            return redirect(url_for('admin'))
        else:
            flash("Login failed. Please check your email and password",'danger')
            return redirect(url_for('adminlogin'))
    return render_template('adminLog.html', form=form)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor.execute("INSERT INTO `signup` (`name`,`email`,`password`) VALUES(%s,%s,%s)",
                       (name, email, password))
        conn.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/apply', methods=['POST', 'GET'])
def apply():
    form = ApplicationForm()
    if form.validate_on_submit():
        email = form.email.data
        name = form.name.data
        cust_phone = form.cust_phone.data
        cust_add = form.cust_add.data
        project = form.project.data
        try:

            cursor.execute(
                "INSERT INTO `customer` (`cust_email`,`name`,`cust_phone`,`address`,`project`) VALUES(%s,%s,%s,%s,%s)",
                (email, name, cust_phone, cust_add, project))
            flash("You successfully applied your application we cantact you soon, Bye! ", 'success')
            conn.commit()
            mail.send_message('New message from'+name,sender=email,recipients=['akashhanumanthappa.official@gmail.com'],body='hi '+name+' is registered '+cust_phone)
            mail.send_message('New message from APconstructions.Ltd ', sender='akashhanumanthappa.official@gmail.com',
                              recipients=[email],
                              body='Hi, ' + name + ' THANK YOU for registering to the APconstructions.Ltd')

            return redirect(url_for('home'))
        except pymysql.err.IntegrityError as e:
            if '1452' in str(e):
                flash('You should Register to apply', 'danger')

    return render_template('Apply.html', form=form)


@app.route('/dashboard')
def dashboard():
    cursor.execute("SELECT * FROM `customer`")
    data = cursor.fetchall()

    return render_template('dashboard.html', customer=data)


@app.route('/update', methods=['POST', 'GET'])
def update():
    if request.method == 'POST':
        email = request.form['email']
        name= request.form['name']
        phone = request.form['phone']
        address = request.form['address']
        project = request.form['project']
        Total = request.form['Total']
        paid = request.form['paid']
        remaining = request.form['remaining']
        try:
            cursor.execute("UPDATE customer SET  name=%s, cust_phone=%s, address=%s, project=%s ,total_amount=%s, paid=%s, remaining_amt=%sWHERE cust_email=%s",
                           (name, phone, address, project,Total,paid,remaining, email))
            flash("data updated successfully", "success")
            conn.commit()
            return redirect(url_for('dashboard'))

        except IntegrityError as e:
            if '1452' in str(e):
                flash('You should Register to apply', 'danger')
    return render_template('update.html')


@app.route('/delete/<string:email>', methods=['POST', 'GET'])
def delete(email):
    cursor.execute("DELETE FROM customer WHERE cust_email=%s", (email,))
    flash("data deleted successfully", "success")
    conn.commit()
    return redirect(url_for('dashboard'))


@app.route('/resetpass', methods=['POST', 'GET'])
def reset():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_pass = request.form['password1']

        if password == confirm_pass:

            try:
                cursor.execute("UPDATE  `signup` SET password=%s WHERE email=%s",
                               (password, email))
                flash("data updated successfully", "success")
                conn.commit()
                return redirect(url_for('login'))

            except IntegrityError as e:
                if '1452' in str(e):
                    flash('You should Register to apply', 'danger')
    return render_template('resetpass.html')


@app.route('/civil')
def civil():
    cursor.execute("SELECT * FROM `employee` WHERE dep_id=1")
    data = cursor.fetchall()

    return render_template('civil.html', employee=data)


@app.route('/architecture')
def architecture():
    cursor.execute("SELECT * FROM `employee` WHERE dep_id=2")
    data = cursor.fetchall()

    return render_template('Architecture.html', employee=data)


@app.route('/interior')
def interior():
    cursor.execute("SELECT * FROM `employee` WHERE dep_id=3")
    data = cursor.fetchall()

    return render_template('Interiar.html', employee=data)


@app.route('/material')
def material():
    cursor.execute("SELECT * FROM `employee` WHERE dep_id=4")
    data = cursor.fetchall()

    return render_template('Material.html', employee=data)


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    cursor.execute("SELECT * FROM `admins`")
    data2 = cursor.fetchall()
    return render_template('admin.html',admins=data2)


@app.route('/rate',methods=['GET', 'POST'])
def rate():
    if request.method == 'POST' and 'rating' in request.form:
        email = request.form['email']
        reviews=request.form['review']
        rating = int(request.form['rating'])
        try:
          cursor.execute('INSERT INTO reviews (r_email,review,ratings) VALUES (%s,%s,%s)', (email,reviews,rating))
          flash('your feed back sent successfully','success')
          conn.commit()
          return redirect(url_for('rate'))
        except pymysql.err.IntegrityError as e:
          if '1062' in str(e):
            flash('You already sent feedback', 'danger')
    return render_template('review.html')


@app.route('/rev_dash')
def rev_dash():
    cursor.execute("SELECT * FROM `reviews`")
    data3 = cursor.fetchall()

    return render_template('rev_dash.html', reviews=data3)


@app.route('/del/<string:email>', methods=['POST', 'GET'])
def delete_all(email):
    cursor.execute("DELETE FROM reviews WHERE r_email=%s", (email,))
    flash("data deleted successfully", "success")
    conn.commit()
    return redirect(url_for('rev_dash'))


@app.route('/cust', methods=['POST', 'GET'])
def cust_dash():
    if request.method == 'POST':
        email = request.form['email']
        cursor.execute("SELECT * FROM `customer` WHERE cust_email=%s", (email,))
        customer=cursor.fetchone()
        return render_template('cust_dash.html',customer=customer)
    return render_template('new.html')


@app.route('/project')
def project():
    cursor.execute("SELECT * FROM `project` ")
    flash("data updated successfully", "success")
    proj=cursor.fetchall()
    return render_template("proj_dash.html",project=proj)


@app.route('/del1/<string:email>', methods=['POST', 'GET'])
def delete_proj(email):
    cursor.execute("DELETE FROM project WHERE cust_name=%s", (email,))
    flash("data deleted successfully", "success")
    conn.commit()
    return redirect(url_for('project'))


@app.route('/update_proj', methods=['POST', 'GET'])
def update_proj():
     cursor.execute("SELECT * FROM `project`")
     project = cursor.fetchone()
     if request.method == 'POST':
        id=request.form['id']
        email = request.form['email']
        name= request.form['Pname']
        cursor.execute("UPDATE project SET  pid=%s,p_name=%s WHERE cust_name=%s",
                           (id,name, email))
        conn.commit()
        return redirect(url_for('project'))
     return render_template('update_proj.html', project=project)

@app.route('/project1')
def project1():
    cursor.execute("SELECT * FROM `project` ")
    flash("data updated successfully", "success")
    proj=cursor.fetchall()
    return render_template("proj1_dash.html",project=proj)

if __name__ == '__main__':
    app.run(debug=True)
