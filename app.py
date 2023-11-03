from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from sqlalchemy import or_
from sqlalchemy import desc, func
import os



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
if os.getenv('DATABASE_URL'):
        app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://users_m6u9_user:JRQCGMGOJQwg8iaNSktxbs8NumI7hRBm@dpg-cl237ermgg9c73ebngng-a.oregon-postgres.render.com:5432/users_m6u9"
else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
db = SQLAlchemy(app)
admin = Admin()
admin.init_app(app)
bcrypt = Bcrypt(app)



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'






class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username_or_fullname = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    #email_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    organizations = db.relationship('Organization', backref='users')
    
    def __str__(self): 
        return self.organizations

class Organization(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.Integer, primary_key=True)
    org_name = db.Column(db.String(100), nullable=False)
    #user_id = db.Column(db.Integer, db.ForeignKey('email'))
    user = db.relationship('User', backref='my_organizations')

class Issue(db.Model):
    __tablename__ = 'issues'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime(), default=datetime.utcnow())
    role = db.Column(db.String(100), default="unspecified")
    username_or_fullname = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    user = db.relationship('User', backref='issues')
    organization = db.relationship('Organization', backref='issues')

class DeletedIssue(db.Model):
    __tablename__ = 'deleted_issues'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime(), default=datetime.utcnow())
    role = db.Column(db.String(100), default="unspecified")
    username_or_fullname = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    user = db.relationship('User', backref='deleted_issues')
    organization = db.relationship('Organization', backref='deleted_issues')



class RegistrationForm(FlaskForm):
    username_or_fullname = StringField('Username or Full Name', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    email = StringField('Email', validators=[DataRequired(), Email()])
    organization = StringField('Organization', validators=[Length(max=100)])
    submit = SubmitField('Register')

    #def validate_organization(self, field):
     #   organization_name = field.data
      #  organization = Organization.query.filter_by(name=organization_name).first()
       # if not organization:
        #    raise ValidationError('The organization does not exist. Leave this space blank and log in to create a new organization')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UpdateOrganizationForm(FlaskForm):
    organization = StringField('Organization', validators=[Length(max=100)])
    submit = SubmitField('Join Organization')

class OrganizationForm(FlaskForm):
    org_name = StringField('Organization', validators=[Length(max=100)])
    submit = SubmitField('Create new Organization')

class IssueForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired()])
    date_created = DateField('Date: ')
    role = StringField('Your role in the organization: ', validators=[Length(max=100)])
    organization = SelectField('Organization', validators=[DataRequired()], coerce=int)
    username_or_fullname = StringField('Username or Business Name', validators=[ Length(max=100)])
    submit = SubmitField('Submit Issue')



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if form.password.data!=form.confirm_password.data: 
            flash("Password Do Not Match. Please try again.")
        if user:
            flash('Email already exists. Please log in.')
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        organization = Organization.query.filter_by(org_name=form.organization.data).first()
        if not organization:
            organization = Organization(org_name=form.organization.data)
            db.session.add(organization)
            db.session.commit()

        new_user = User(username_or_fullname=form.username_or_fullname.data, email=form.email.data, password=hashed_password, organization_id=organization.id)
        db.session.add(new_user)
        db.session.commit()
        

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('home.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.')

    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    organization = Organization.query.filter(Organization.users.contains(current_user)).first()
    issues = organization.issues if organization else []
    return render_template('dashboard.html', title='Dashboard', issues=issues)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    my_organizations = Organization.query.all()
    
    return render_template('profile.html', my_organizations=my_organizations)

@app.route('/about')
def about():
    
    return render_template('about.html')

@app.route('/issues')
@login_required
def issues():
    
    return render_template('issues.html')

# Route for editing an issue
@app.route('/edit_issue/<int:issue_id>', methods=['GET', 'POST'])
def edit_issue(issue_id):
    # Logic to retrieve the issue by ID from the database
    issue = Issue.query.get(issue_id)

    if request.method == 'POST':
        # Update the issue with the submitted form data
        issue.title = request.form['title']
        issue.description = request.form['description']

        # Save the updated issue to the database
        db.session.commit()

        # Redirect to the issues page
        return redirect(url_for('issues'))

    # Render the edit issue template with the issue data
    return render_template('edit_issue.html', issue=issue)

@app.route('/edit_deleted_issue/<int:deleted_issue_id>', methods=['GET', 'POST'])
def edit_deleted_issue(deleted_issue_id):
    deleted_issue = DeletedIssue.query.get(deleted_issue_id)

    if request.method == 'POST':
        # Update the deleted issue with the form data
        deleted_issue.title = request.form['title']
        deleted_issue.description = request.form['description']
        deleted_issue.role = request.form['role']

        # Move the deleted issue to the regular issue list
        issue = Issue(
            title=deleted_issue.title,
            description=deleted_issue.description,
            date_created=deleted_issue.date_created,
            role=deleted_issue.role,
            username_or_fullname=deleted_issue.username_or_fullname,
            user_id=deleted_issue.user_id,
            organization_id=deleted_issue.organization_id
        )
        db.session.add(issue)
        db.session.commit()

        # Delete the deleted issue from the deleted issues list
        db.session.delete(deleted_issue)
        db.session.commit()

        # Redirect to the issues page
        return redirect(url_for('issues'))

    # Render the edit issue template with the deleted_issue object
    return render_template('edit_deleted_issue.html', deleted_issue=deleted_issue)


@app.route('/delete_issue/<int:issue_id>', methods=['POST', 'GET'])
def delete_issue(issue_id):
    if request.method == 'POST':
        # Logic to retrieve the issue by ID from the database
        issue = Issue.query.get(issue_id)

        # Save the issue to the history page instead of deleting it
        deleted_issue = DeletedIssue(
            title=issue.title,
            description=issue.description,
            date_created=issue.date_created,
            role=issue.role,
            username_or_fullname=issue.username_or_fullname,
            user_id=issue.user_id,
            organization_id=issue.organization_id
        )
        db.session.add(deleted_issue)
        db.session.commit()

        # Delete the issue from the database
        db.session.delete(issue)
        db.session.commit()

    # Redirect to the history page
    return redirect(url_for('history'))

@app.route('/restore_issue/<int:issue_id>', methods=['POST'])
def restore_issue(issue_id):
    # Logic to retrieve the deleted issue by ID from the database
    deleted_issue = DeletedIssue.query.get(issue_id)

    # Create a new issue based on the deleted issue's data
    restored_issue = Issue(
        title=deleted_issue.title,
        description=deleted_issue.description,
        date_created=deleted_issue.date_created,
        role=deleted_issue.role,
        username_or_fullname=deleted_issue.username_or_fullname,
        user_id=deleted_issue.user_id,
        organization_id=deleted_issue.organization_id
    )
    db.session.add(restored_issue)
    db.session.commit()

    # Delete the deleted issue from the history
    db.session.delete(deleted_issue)
    db.session.commit()

    # Redirect to the issues page or any other appropriate page
    return redirect(url_for('dashboard'))

@app.route('/restore_deleted_issue/<int:deleted_issue_id>', methods=['POST'])
def restore_deleted_issue(deleted_issue_id):
    # Logic to retrieve the deleted issue by ID from the database
    deleted_issue = DeletedIssue.query.get(deleted_issue_id)

    # Create a new issue based on the deleted issue's data
    restored_issue = Issue(
        title=deleted_issue.title,
        description=deleted_issue.description,
        date_created=deleted_issue.date_created,
        role=deleted_issue.role,
        username_or_fullname=deleted_issue.username_or_fullname,
        user_id=deleted_issue.user_id,
        organization_id=deleted_issue.organization_id
    )
    db.session.add(restored_issue)
    db.session.commit()

    # Delete the deleted issue from the history
    db.session.delete(deleted_issue)
    db.session.commit()

    # Redirect to the issues page or any other appropriate page
    return redirect(url_for('dashboard'))

@app.route('/edit_email/<int:user_id>', methods=['GET', 'POST'])
def edit_email(user_id):
    # Logic to retrieve the issue by ID from the database
    user = User.query.get(user_id)

    if request.method == 'POST':
        # Update the issue with the submitted form data
        user.email = request.form['email']
        
        # Save the updated issue to the database
        db.session.commit()

        # Redirect to the issues page
        return redirect(url_for('profile'))

    # Render the edit issue template with the issue data
    return render_template('edit_email.html', user=user)


@app.route('/history', methods=['GET'])
def history():
    # Logic to retrieve the deleted issues from the database
    deleted_issues = DeletedIssue.query.filter_by(organization_id=current_user.organization_id).all()

    return render_template('history.html', deleted_issues=deleted_issues)

@app.route('/issue/new', methods=['GET', 'POST'])
@login_required
def create_issue():
    form = IssueForm()
    form.organization.choices = [(organization.id, organization.org_name) for organization in Organization.query.all()]
    if form.validate_on_submit():
        user = current_user
        organization_id = form.organization.data
        new_issue = Issue(title=form.title.data, description=form.description.data, role=form.role.data, user_id=user.id, organization_id=organization_id, username_or_fullname=current_user.username_or_fullname)
        db.session.add(new_issue)
        db.session.commit()

        users = User.query.filter_by(organization_id=organization_id).all()

   
        flash('Issue created successfully.')
        return redirect(url_for('dashboard'))

    return render_template('create_issue.html', form=form)


#@app.route('/search_results', methods=['GET', 'POST'])
#def search_results():
 #   if request.method == 'POST':
  #      search_query = request.form.get('search_query')
   #     issues = Issue.query.filter(Issue.title.ilike(f'%{search_query}%')).all()
    #    return render_template('search_results.html', issues=issues)






app.app_context().push()

if __name__ == '__main__':
    app.run(debug=True)