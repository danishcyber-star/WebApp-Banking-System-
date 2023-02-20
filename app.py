from flask import Flask, render_template, request, jsonify, session, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import sqlite3
import datetime

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/',methods=["GET"])
def welocme():
    return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
    return render_template('login.html', form=form)


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    return render_template('home.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route("/account_manage",methods=["GET"])
def account_management():
    return render_template('account_management.html')

@app.route("/fund_transfer",methods=["GET"])
def fund_transfer():
    return render_template('fund_transfer.html')


@app.route("/location",methods=["GET"])
def atm_locator():
    return render_template('atm_locator.html')

# @app.route('/locate', methods=['GET', 'POST'])
# def locate():
#     if request.method == 'POST':
#         location = request.form['location']
#         response = requests.get(
#             'https://maps.googleapis.com/maps/api/geocode/json?address={}&key=YOUR_API_KEY'.format(location))
#         if response.status_code == 200:
#             json_response = response.json()
#             lat = json_response['results'][0]['geometry']['location']['lat']
#             lng = json_response['results'][0]['geometry']['location']['lng']

@app.route("/open_account",methods=["GET"])
def open_account():
    return render_template('open_account.html')
@app.route("/apply", methods=["POST","GET"])
def apply():
    name = request.form.get("name")
    father_name = request.form.get("father_name")
    adhar = request.form.get("adhar")
    dob = request.form.get("dob")
    pan = request.form.get("pan")
    address = request.form.get("address")
    pincode = request.form.get("pincode")
    state = request.form.get("state")
    country = request.form.get("country")
    occupation = request.form.get("occupation")
    email = request.form.get("email")
    mobile_number = request.form.get("mobile_number")
    marital_status = request.form.get("marital_status")

    conne = sqlite3.connect("myaccount.db")
    d = conne.cursor()
    # Check if account already exists in the database
    d.execute("SELECT * FROM accounts WHERE adhar=? OR pan=? OR mobile_number=? OR email=?", (adhar, pan, mobile_number, email))
    acc = d.fetchone()
    if acc is not None:
        conne.close()
        return "Account already exists with the bank."
    # create the table
    d.execute('CREATE TABLE IF NOT EXISTS accounts \
                (name text, father_name text, adhar text unique, dob text, pan text unique, \
                address text, pincode integer, state text, country text, occupation text, \
                email text unique, mobile_number text unique, marital_status text);')

    # Insert account details into database
    d.execute("INSERT INTO accounts (name, father_name, adhar, dob, pan, address, pincode, state, country, occupation, email, mobile_number, marital_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (name, father_name, adhar, dob, pan, address, pincode, state, country, occupation, email, mobile_number, marital_status))
    conne.commit()
    # Display success message to user
    conne.close()
    return "Congratulations 🎉, your account has been created!"

@app.route("/notify",methods=["GET"])
def notification():
    return render_template('notification.html')

@app.route("/online_payment",methods=["GET"])
def online_payment():
    return render_template('online_payment.html')

@app.route('/submit', methods=['POST'])
def submit_payment():
    sender_account = request.form['senderAccount']
    receiver_account = request.form['receiverAccount']
    amount = request.form['amount']

    if not sender_account or not receiver_account or not amount:
        return 'Please fill out all fields'
    try:
        amount = float(amount)
    except ValueError:
        return 'Amount must be a number'

    # Replace the following line with actual payment processing logic
    payment_status = 'successful'

    conn = sqlite3.connect('payment.db')
    c = conn.cursor()

    # Check if both sender and receiver accounts exist in the database
    c.execute("SELECT balance FROM accounts WHERE account_number=?", (sender_account,))
    sender_balance = c.fetchone()
    c.execute("SELECT balance FROM accounts WHERE account_number=?", (receiver_account,))
    receiver_balance = c.fetchone()
    
    if sender_balance is None:
        return 'Sender and/or receiver account does not exist'
    
    sender_balance = sender_balance[0]
    receiver_balance = receiver_balance[0]
    
    # Check if the sender account balance is greater than or equal to the payment amount
    if sender_balance < amount:
        return 'Insufficient funds'
    # Update sender and receiver account balances
    sender_balance -= amount
    receiver_balance += amount
    c.execute("UPDATE accounts SET balance=? WHERE account_number=?", (sender_balance, sender_account))
    c.execute("UPDATE accounts SET balance=? WHERE account_number=?", (receiver_balance, receiver_account))

    date = datetime.date.today()
    time = datetime.datetime.now().time()
    c.execute('CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, time TEXT, sender_account TEXT, receiver_account TEXT, amount REAL, payment_status TEXT)')
    conn.commit()
    conn.close()
    payment_status_emoji = '✅' if payment_status == 'successful' else '❌'
    return render_template('payment_receipt.html', transaction_id=c.lastrowid, date=date, time=time, sender_account=sender_account, receiver_account=receiver_account, amount=amount, payment_status=payment_status, payment_status_emoji=payment_status_emoji)



if __name__ == '__main__':
    app.run(debug=True)




