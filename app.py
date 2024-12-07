from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy #usage of SQLAlchemy (Flask ORM) to manage database interactions
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, Email, Optional, NumberRange
from flask_bcrypt import Bcrypt
from flask_wtf.file import FileField, FileAllowed

app = Flask(__name__)

# Configure the Flask app to use the existing database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project_database_01.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

#-----------------------------------------------------------------------------------------------------------------Initialize the LoginManager
login_manager = LoginManager() #handles session management and user login tracking
login_manager.init_app(app)
login_manager.login_view = 'login' #Specifies the route /login to redirect users to when they try to acces proteced routes without begin logged in


#-----------------------------------------------------------------------------------------------------------------Models



# Define the user loader for Flask-Login
#Floask-Login requires a way to load a user object given their unqique identiefier
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) #retrieves user from database based on user_id whenever flask-login needs to manage user session






#mixin from Flask-Login provides default implementations for proporties and methods like is_authenticated, is_active, etc => authentication and session tracking
class User(db.Model, UserMixin): #database model which represents a table in the database #At the moment it is going in an internal database
    id = db.Column(db.Integer, primary_key=True) #unique identifier for each user
    username = db.Column(db.String(20), nullable=False, unique=True) #username must be unique
    password = db.Column(db.String(80), nullable=False) #password stores the hash_password
    age = db.Column(db.Integer, nullable=False)
    email= db.Column(db.String(120), nullable=False, unique=True)
    profile= db.Column(db.Text)
    profile_image= db.Column(db.LargeBinary)
    account_type = db.column(db.String(20))



class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})
    age = IntegerField(validators=[InputRequired()], render_kw={"placeholder": "Age"})
    email = StringField(validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"})
    profile = StringField(render_kw={"placeholder": "Profile Information"})
    profile_image = FileField('Profile Image')
    account_type = SelectField('Account Type', choices=[('user', 'User'), ('administrator', 'Administrator')], validators=[InputRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by( username=username.data).first() #checks if a username already exists in the database(to avoid duplicates)
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')
        

class LoginForm(FlaskForm): #contains field for username and password with validation requirenments #this is a form
    username = StringField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


class UpdateProfileForm(FlaskForm):
    age = IntegerField('Age', validators=[Optional(), NumberRange(min=0, max=150)])
    email = StringField('Email', validators=[Optional(), Email()])
    profile = TextAreaField('Profile', validators=[Optional()])
    profile_image = FileField('Profile Image', validators=[Optional()])
    submit = SubmitField('Update Profile')
#-----------------------------------------------------------------------------------------------------------------



# Create the table if it doesn't exist
#with app.app_context():
    #db.create_all()

#--------------------------------------------------------------------------------------------------------------------------------------Decorators
@app.route("/")#-----------------home 
def home():
    return render_template('home.html')

#Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm() #user fills in a loginForm
    if form.validate_on_submit(): #checks if all fields are valid
        user = User.query.filter_by(username=form.username.data).first()  #app queries the databse to find a user with given username
        if user and bcrypt.check_password_hash(user.password, form.password.data): #if user is found and the password matches the hashed password in database (bcrypt.check_password_hash), login_user(user) is called, loggin the user in and storing their ID in the session
            login_user(user)
            return redirect(url_for('home')) #user redirected to the home page
    return render_template('login.html', form=form) #if fails than login again


#Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            age=form.age.data,
            email=form.email.data,
            profile=form.profile.data,
            profile_image=form.profile_image.data.read() if form.profile_image.data else None,
            account_type=form.account_type.data  # Make sure to add this line
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        if form.age.data:
            current_user.age = form.age.data
        if form.email.data:
            current_user.email = form.email.data
        if form.profile.data:
            current_user.profile = form.profile.data
        if form.profile_image.data:
            current_user.profile_image = form.profile_image.data.read()
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('home'))
    # Populate form fields with existing data
    form.age.data = current_user.age
    form.email.data = current_user.email
    form.profile.data = current_user.profile
    return render_template('profile.html', form=form)



#--------------------------------------------------------------------------------------------------------------------------------------show tables
if __name__ == '__main__':
    app.run(debug=True)


app.close()

