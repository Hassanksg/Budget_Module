import os
import logging
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session, make_response
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SubmitField, BooleanField, validators, IntegerField, SelectMultipleField
from flask_login import login_required, current_user, login_user, logout_user
from pymongo.errors import PyMongoError, WriteError, DuplicateKeyError
from werkzeug.security import generate_password_hash, check_password_hash
import re
from utils import get_mongo_db, logger, is_valid_email
from models import create_user
from translations import trans

users_bp = Blueprint('users', __name__, template_folder='templates/users')

USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
PASSWORD_REGEX = re.compile(r'.{6,}')
PHONE_REGEX = re.compile(r'^\+?\d{10,15}$')

# Custom validator for the login identifier
def validate_identifier(form, field):
    identifier = field.data.strip()
    if '@' not in identifier:
        if not USERNAME_REGEX.match(identifier):
            raise validators.ValidationError(trans('general_username_format', default='Username must be alphanumeric with underscores'))

class LoginForm(FlaskForm):
    username = StringField(
        trans('general_login_identifier', default='Username or Email'),
        [
            validators.DataRequired(message=trans('general_identifier_required', default='Username or Email is required')),
            validators.Length(min=3, max=50, message=trans('general_identifier_length', default='Identifier must be between 3 and 50 characters')),
            validate_identifier
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}  # Soft Cream background, Deep Blue border
    )
    password = PasswordField(
        trans('general_password', default='Password'),
        [
            validators.DataRequired(message=trans('general_password_required', default='Password is required')),
            validators.Length(min=6, message=trans('general_password_length', default='Password must be at least 6 characters'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}  # Soft Cream background, Deep Blue border
    )
    remember = BooleanField(
        trans('general_remember_me', default='Remember me'),
        render_kw={'class': 'form-check-input'}
    )
    submit = SubmitField(
        trans('general_login', default='Sign In'),
        render_kw={'class': 'btn w-100', 'style': 'background-color: #1E3A8A; color: #FFF8F0;'}  # Deep Blue button, Soft Cream text
    )

class SignupForm(FlaskForm):
    username = StringField(
        trans('general_username', default='Username'),
        [
            validators.DataRequired(message=trans('general_username_required', default='Username is required')),
            validators.Length(min=3, max=50, message=trans('general_username_length', default='Username must be between 3 and 50 characters')),
            validators.Regexp(USERNAME_REGEX, message=trans('general_username_format', default='Username must be alphanumeric with underscores'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}  # Soft Cream background, Deep Blue border
    )
    email = StringField(
        trans('general_email', default='Email'),
        [
            validators.DataRequired(message=trans('general_email_required', default='Email is required')),
            validators.Email(message=trans('general_email_invalid', default='Invalid email address')),
            validators.Length(max=254),
            lambda form, field: is_valid_email(field.data.strip().lower()) or validators.ValidationError(trans('general_email_domain_invalid', default='Invalid email domain'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}  # Soft Cream background, Deep Blue border
    )
    password = PasswordField(
        trans('general_password', default='Password'),
        [
            validators.DataRequired(message=trans('general_password_required', default='Password is required')),
            validators.Length(min=6, message=trans('general_password_length', default='Password must be at least 6 characters')),
            validators.Regexp(PASSWORD_REGEX, message=trans('general_password_format', default='Password must be at least 6 characters'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}  # Soft Cream background, Deep Blue border
    )
    submit = SubmitField(
        trans('general_signup', default='Sign Up'),
        render_kw={'class': 'btn w-100', 'style': 'background-color: #1E3A8A; color: #FFF8F0;'}  # Deep Blue button, Soft Cream text
    )

class PersonalSetupForm(FlaskForm):
    first_name = StringField(
        trans('general_first_name', default='First Name'),
        validators=[
            validators.Optional(),
            validators.Length(max=255, message=trans('general_first_name_length', default='First name must be between 1 and 255 characters'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}  # Soft Cream background, Deep Blue border
    )
    last_name = StringField(
        trans('general_last_name', default='Last Name'),
        validators=[
            validators.Optional(),
            validators.Length(max=255, message=trans('general_last_name_length', default='Last name must be between 1 and 255 characters'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}  # Soft Cream background, Deep Blue border
    )
    financial_goals = SelectMultipleField(
        trans('setup_financial_goals', default='What are your main financial goals? (Select all that apply)'),
        choices=[
            ('emergency_fund', trans('setup_emergency_fund', default='Build an emergency fund')),
            ('debt_payoff', trans('setup_debt_payoff', default='Pay off debt')),
            ('savings_vacation', trans('setup_savings_vacation', default='Save for vacation/travel')),
            ('retirement', trans('setup_retirement', default='Plan for retirement')),
            ('home_purchase', trans('setup_home_purchase', default='Save for a home')),
            ('other', trans('setup_other', default='Other (e.g., education, investments)'))
        ],
        validators=[validators.Optional()],
        render_kw={'class': 'form-select', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;', 'multiple': True}
    )
    currency = SelectField(
        trans('setup_currency', default='Preferred Currency'),
        choices=[
            ('USD', 'USD - US Dollar'),
            ('EUR', 'EUR - Euro'),
            ('GBP', 'GBP - British Pound'),
            ('NGN', 'NGN - Nigerian Naira'),
            ('other', trans('setup_other_currency', default='Other'))
        ],
        validators=[validators.DataRequired()],
        default='USD',
        render_kw={'class': 'form-select', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}
    )
    budget_frequency = SelectField(
        trans('setup_budget_frequency', default='How often do you want to set budgets?'),
        choices=[
            ('monthly', trans('setup_monthly', default='Monthly')),
            ('weekly', trans('setup_weekly', default='Weekly')),
            ('biweekly', trans('setup_biweekly', default='Bi-weekly'))
        ],
        validators=[validators.DataRequired()],
        render_kw={'class': 'form-select', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}
    )
    notifications = SelectMultipleField(
        trans('setup_notifications', default='What notifications would you like? (Select all that apply)'),
        choices=[
            ('spending_alerts', trans('setup_spending_alerts', default='Spending limit alerts')),
            ('bill_reminders', trans('setup_bill_reminders', default='Bill due reminders')),
            ('goal_progress', trans('setup_goal_progress', default='Goal progress updates')),
            ('insights_tips', trans('setup_insights_tips', default='Personalized tips and insights'))
        ],
        validators=[validators.Optional()],
        render_kw={'class': 'form-select', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;', 'multiple': True}
    )
    language = SelectField(
        trans('general_language', default='Language'),
        choices=[
            ('en', trans('general_english', default='English')),
            ('ha', trans('general_hausa', default='Hausa'))
        ],
        validators=[validators.DataRequired(message=trans('general_language_required', default='Language is required'))],
        render_kw={'class': 'form-select', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}  # Soft Cream background, Deep Blue border
    )
    terms = BooleanField(
        trans('general_terms', default='I accept the Terms and Conditions'),
        validators=[validators.DataRequired(message=trans('general_terms_required', default='You must accept the terms'))],
        render_kw={'class': 'form-check-input'}
    )
    submit = SubmitField(
        trans('general_save_and_continue', default='Save and Continue'),
        render_kw={'class': 'btn w-100', 'style': 'background-color: #1E3A8A; color: #FFF8F0;'}  # Deep Blue button, Soft Cream text
    )

def log_audit_action(action, details=None):
    try:
        db = get_mongo_db()
        audit_details = {
            'admin_id': str(current_user.id) if current_user.is_authenticated else 'system',
            'action': action,
            'details': details or {},
            'timestamp': datetime.utcnow(),
            'session_id': session.get('session_id', 'no-session-id')
        }
        db.audit_logs.insert_one(audit_details)
        logger.debug(f"Audit log created: {audit_details}")
    except PyMongoError as e:
        logger.error(f"MongoDB error logging audit action '{action}': {str(e)}", exc_info=True)
    except Exception as e:
        logger.error(f"Unexpected error logging audit action '{action}': {str(e)}", exc_info=True)

def get_post_login_redirect(user_role):
    """Determine where to redirect user after login based on their role."""
    try:
        if user_role == 'personal':
            return url_for('general_bp.home')
        logger.warning(f"Unknown role '{user_role}' for login redirect, defaulting to home")
        return url_for('general_bp.home')
    except Exception as e:
        logger.error(f"Error determining login redirect for role '{user_role}': {str(e)}", exc_info=True)
        return url_for('general_bp.home')

@users_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        try:
            logger.info(f"Authenticated user {current_user.id} redirected from login, session_id: {session.get('session_id')}")
            return redirect(get_post_login_redirect(current_user.role))
        except Exception as e:
            logger.error(f"Error redirecting authenticated user: {str(e)}", exc_info=True)
            flash(trans('general_error', default='An error occurred. Please try again.'), 'danger')
            return redirect(url_for('users.login')), 500

    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
        logger.debug(f"Created new session_id: {session['session_id']}")

    form = LoginForm()
    if request.method == 'POST':
        logger.debug(f"Received POST request for login, form data: {request.form}, session_id: {session.get('session_id')}")
        if form.validate_on_submit():
            try:
                identifier = form.username.data.strip().lower()
                password = form.password.data
                logger.info(f"Login attempt for identifier: {identifier}, session_id: {session['session_id']}")
                
                db = get_mongo_db()
                if '@' in identifier:
                    user = db.users.find_one({'email': {'$regex': f'^{re.escape(identifier)}$', '$options': 'i'}})
                else:
                    user = db.users.find_one({'_id': {'$regex': f'^{re.escape(identifier)}$', '$options': 'i'}})
                
                if not user:
                    logger.warning(f"Login attempt failed: Identifier {identifier} not found")
                    flash(trans('general_identifier_not_found', default='Username or Email not found. Please check your signup details.'), 'danger')
                    log_audit_action('login_failed', {'identifier': identifier, 'reason': 'identifier_not_found'})
                    return render_template('users/login.html', form=form, title=trans('general_login', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 401

                username = user['_id']
                if not check_password_hash(user['password_hash'], password):
                    logger.warning(f"Login attempt failed for username: {username} (invalid password)")
                    flash(trans('general_invalid_password', default='Incorrect password'), 'danger')
                    log_audit_action('login_failed', {'user_id': username, 'reason': 'invalid_password'})
                    return render_template('users/login.html', form=form, title=trans('general_login', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 401

                logger.info(f"User found: {username}, proceeding with login")
                from app import User
                user_obj = User(user['_id'], user['email'], user.get('display_name'), user.get('role', 'personal'))
                login_result = login_user(user_obj, remember=form.remember.data)
                if not login_result:
                    logger.error(f"login_user failed for {username} without raising an exception")
                    flash(trans('general_login_failed', default='Login failed. Please try again.'), 'danger')
                    log_audit_action('login_failed', {'user_id': username, 'reason': 'login_user_failed'})
                    return render_template('users/login.html', form=form, title=trans('general_login', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 401
                
                session['lang'] = user.get('language', 'en')
                log_audit_action('login', {'user_id': username})
                logger.info(f"User {username} logged in successfully. Session: {dict(session)}")
                if not user.get('setup_complete', False):
                    return redirect(url_for('users.personal_setup_wizard'))
                return redirect(get_post_login_redirect(user.get('role', 'personal')))
            except PyMongoError as e:
                logger.error(f"MongoDB error during login for {identifier}: {str(e)}", exc_info=True)
                flash(trans('general_database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
                log_audit_action('login_failed', {'identifier': identifier, 'reason': 'mongodb_error', 'error': str(e)})
                return render_template('users/login.html', form=form, title=trans('general_login', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 500
            except Exception as e:
                logger.error(f"Unexpected error during login for {identifier}: {str(e)}", exc_info=True)
                flash(trans('general_error', default='An error occurred. Please try again.'), 'danger')
                log_audit_action('login_failed', {'identifier': identifier, 'reason': 'unexpected_error', 'error': str(e)})
                return render_template('users/login.html', form=form, title=trans('general_login', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 500
        else:
            logger.debug(f"Form validation failed: {form.errors}, session_id: {session.get('session_id')}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", 'danger')
    return render_template('users/login.html', form=form, title=trans('general_login', lang=session.get('lang', 'en')), background_color='#FFF8F0')

@users_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        try:
            logger.info(f"Authenticated user {current_user.id} redirected from signup, session_id: {session.get('session_id')}")
            return redirect(get_post_login_redirect(current_user.role))
        except Exception as e:
            logger.error(f"Error redirecting authenticated user in signup: {str(e)}", exc_info=True)
            flash(trans('general_error', default='An error occurred. Please try again.'), 'danger')
            return redirect(url_for('users.login')), 500

    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
        logger.debug(f"Created new session_id: {session['session_id']}")

    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        email = form.email.data.strip().lower()
        password = form.password.data
        logger.debug(f"Signup attempt: username={username}, email={email}, session_id: {session['session_id']}")
        try:
            db = get_mongo_db()

            if db.users.find_one({'_id': username}):
                flash(trans('general_username_exists', default='Username already exists'), 'danger')
                logger.warning(f"Signup failed: Username {username} already exists")
                log_audit_action('signup_failed', {'username': username, 'email': email, 'reason': 'username_exists'})
                return render_template('users/signup.html', form=form, title=trans('general_signup', lang=session.get('lang', 'en')), background_color='#FFF8F0')

            if db.users.find_one({'email': email}):
                flash(trans('general_email_exists', default='Email already exists'), 'danger')
                logger.warning(f"Signup failed: Email {email} already exists")
                log_audit_action('signup_failed', {'username': username, 'email': email, 'reason': 'email_exists'})
                return render_template('users/signup.html', form=form, title=trans('general_signup', lang=session.get('lang', 'en')), background_color='#FFF8F0')

            user_data = {
                '_id': username,
                'email': email,
                'password': password,  # create_user will hash this
                'role': 'personal',
                'ficore_credit_balance': 10,  # Signup bonus for Ficore Credits
                'language': 'en',
                'dark_mode': False,
                'is_admin': False,
                'setup_complete': False,
                'display_name': username,
                'created_at': datetime.utcnow()
            }

            with db.client.start_session() as mongo_session:
                with mongo_session.start_transaction():
                    user_id = create_user(db, user_data)

                    # Optionally log a signup bonus transaction
                    log_transaction = request.form.get('log_transaction', 'false').lower() == 'true'
                    if log_transaction:
                        transaction = {
                            'user_id': username,
                            'action': 'signup_bonus',
                            'amount': 10.0,
                            'timestamp': datetime.utcnow(),
                            'session_id': session['session_id'],
                            'status': 'completed'
                        }
                        db.ficore_credit_transactions.insert_one(transaction, session=mongo_session)
                    
                    mongo_session.commit_transaction()

            log_audit_action('signup', {'user_id': username, 'email': email, 'role': 'personal'})
            logger.info(f"New user created: {username}, email: {email}, role: personal")

            from app import User
            user_obj = User(username, email, username, 'personal')
            login_user(user_obj, remember=True)
            session['lang'] = 'en'
            
            logger.info(f"User {username} logged in after signup. Session: {dict(session)}")
            return redirect(url_for('users.personal_setup_wizard'))
        except WriteError as we:
            logger.error(f"Document validation error during signup for {username}: {str(we)}", exc_info=True)
            flash(trans('general_validation_error', default='Invalid data provided'), 'danger')
            log_audit_action('signup_failed', {'username': username, 'email': email, 'reason': 'validation_error', 'error': str(we)})
            return render_template('users/signup.html', form=form, title=trans('general_signup', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 400
        except DuplicateKeyError:
            logger.error(f"Duplicate key error during signup for {username}: Username or email already exists", exc_info=True)
            flash(trans('general_duplicate_user', default='Username or email already taken'), 'danger')
            log_audit_action('signup_failed', {'username': username, 'email': email, 'reason': 'duplicate_key'})
            return render_template('users/signup.html', form=form, title=trans('general_signup', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 400
        except PyMongoError as e:
            logger.error(f"MongoDB error during signup for {username}: {str(e)}", exc_info=True)
            flash(trans('general_database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
            log_audit_action('signup_failed', {'username': username, 'email': email, 'reason': 'mongodb_error', 'error': str(e)})
            return render_template('users/signup.html', form=form, title=trans('general_signup', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 500
        except Exception as e:
            logger.error(f"Unexpected error during signup for {username}: {str(e)}", exc_info=True)
            flash(trans('general_error', default='An error occurred. Please try again.'), 'danger')
            log_audit_action('signup_failed', {'username': username, 'email': email, 'reason': 'unexpected_error', 'error': str(e)})
            return render_template('users/signup.html', form=form, title=trans('general_signup', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 500
    else:
        logger.debug(f"Signup form validation failed: {form.errors}, session_id: {session.get('session_id')}")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('users/signup.html', form=form, title=trans('general_signup', lang=session.get('lang', 'en')), background_color='#FFF8F0')

@users_bp.route('/personal_setup_wizard', methods=['GET', 'POST'])
@login_required
def personal_setup_wizard():
    try:
        db = get_mongo_db()
        user_id = current_user.id
        user = db.users.find_one({'_id': user_id})
        if not user:
            flash(trans('general_user_not_found', default='User not found'), 'danger')
            logger.warning(f"Personal setup wizard failed: User {user_id} not found, session_id: {session.get('session_id')}")
            log_audit_action('personal_setup_failed', {'user_id': user_id, 'reason': 'user_not_found'})
            return redirect(url_for('users.logout'))

        if user.get('setup_complete', False):
            logger.info(f"User {user_id} already completed setup, redirecting, session_id: {session.get('session_id')}")
            return redirect(get_post_login_redirect(user.get('role', 'personal')))

        form = PersonalSetupForm()
        if form.validate_on_submit():
            first_name = form.first_name.data.strip() if form.first_name.data else None
            last_name = form.last_name.data.strip() if form.last_name.data else None
            financial_goals = list(form.financial_goals.data) if form.financial_goals.data else []
            currency = form.currency.data
            budget_frequency = form.budget_frequency.data
            notifications = list(form.notifications.data) if form.notifications.data else []
            language = form.language.data

            # Additional validation for optional fields
            if first_name and len(first_name) > 255:
                flash(trans('general_first_name_length', default='First name must be between 1 and 255 characters'), 'danger')
                logger.warning(f"Invalid first name length for user: {user_id}")
                log_audit_action('personal_setup_failed', {'user_id': user_id, 'reason': 'invalid_first_name_length'})
                return render_template('users/personal_setup.html', form=form, title=trans('general_personal_setup', lang=session.get('lang', 'en')), background_color='#FFF8F0')

            if last_name and len(last_name) > 255:
                flash(trans('general_last_name_length', default='Last name must be between 1 and 255 characters'), 'danger')
                logger.warning(f"Invalid last name length for user: {user_id}")
                log_audit_action('personal_setup_failed', {'user_id': user_id, 'reason': 'invalid_last_name_length'})
                return render_template('users/personal_setup.html', form=form, title=trans('general_personal_setup', lang=session.get('lang', 'en')), background_color='#FFF8F0')

            if language not in ['en', 'ha']:
                flash(trans('general_language_invalid', default='Invalid language selection'), 'danger')
                logger.warning(f"Invalid language selection for user: {user_id}")
                log_audit_action('personal_setup_failed', {'user_id': user_id, 'reason': 'invalid_language'})
                return render_template('users/personal_setup.html', form=form, title=trans('general_personal_setup', lang=session.get('lang', 'en')), background_color='#FFF8F0')

            update_data = {
                'language': language,
                'setup_complete': True
            }
            if first_name or last_name:
                update_data['personal_details'] = {}
                if first_name:
                    update_data['personal_details']['first_name'] = first_name
                if last_name:
                    update_data['personal_details']['last_name'] = last_name
            update_data['financial_goals'] = financial_goals
            update_data['currency'] = currency
            update_data['budget_frequency'] = budget_frequency
            update_data['notifications'] = notifications

            db.users.update_one(
                {'_id': user_id},
                {'$set': update_data}
            )
            log_audit_action('complete_personal_setup_wizard', {'user_id': user_id, 'updated_by': current_user.id})
            logger.info(f"Personal setup completed for user: {user_id}, session_id: {session.get('session_id')}")
            flash(trans('general_personal_setup_success', default='Personal setup completed'), 'success')
            return redirect(get_post_login_redirect(user.get('role', 'personal')))
        else:
            logger.debug(f"Personal setup form validation failed: {form.errors}, session_id: {session.get('session_id')}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", 'danger')
        return render_template('users/personal_setup.html', form=form, title=trans('general_personal_setup', lang=session.get('lang', 'en')), background_color='#FFF8F0')
    except PyMongoError as e:
        logger.error(f"MongoDB error during personal setup for {user_id}: {str(e)}", exc_info=True)
        flash(trans('general_database_error', default='An error occurred while accessing the database. Please try again later.'), 'danger')
        log_audit_action('personal_setup_failed', {'user_id': user_id, 'reason': 'mongodb_error', 'error': str(e)})
        return render_template('users/personal_setup.html', form=form, title=trans('general_personal_setup', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 500
    except Exception as e:
        logger.error(f"Unexpected error during personal setup for {user_id}: {str(e)}", exc_info=True)
        flash(trans('general_error', default='An error occurred. Please try again.'), 'danger')
        log_audit_action('personal_setup_failed', {'user_id': user_id, 'reason': 'unexpected_error', 'error': str(e)})
        return render_template('users/personal_setup.html', form=form, title=trans('general_personal_setup', lang=session.get('lang', 'en')), background_color='#FFF8F0'), 500

@users_bp.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    lang = session.get('lang', 'en')
    sid = session.get('session_id', 'no-session-id')
    logger.info(f"Before logout - User: {user_id}, Session: {dict(session)}, Authenticated: {current_user.is_authenticated}")
    try:
        logout_user()
        if current_app.config.get('SESSION_TYPE') == 'mongodb':
            try:
                db = get_mongo_db()
                db.sessions.delete_one({'_id': sid})
                logger.info(f"Deleted MongoDB session for user {user_id}, SID: {sid}")
            except PyMongoError as e:
                logger.error(f"Failed to delete MongoDB session for SID {sid}: {str(e)}", exc_info=True)
                log_audit_action('logout_failed', {'user_id': user_id, 'session_id': sid, 'reason': 'mongodb_error', 'error': str(e)})
        session.clear()
        session['lang'] = lang
        log_audit_action('logout', {'user_id': user_id, 'session_id': sid})
        logger.info(f"User {user_id} logged out successfully. After logout - Session: {dict(session)}, Authenticated: {current_user.is_authenticated}")
        response = make_response(redirect(url_for('general_bp.landing')))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.set_cookie(current_app.config['SESSION_COOKIE_NAME'], '', expires=0, httponly=True, secure=current_app.config.get('SESSION_COOKIE_SECURE', True))
        response.set_cookie('remember_token', '', expires=0, httponly=True, secure=True)
        flash(trans('general_logged_out', default='Logged out successfully'), 'success')
        return response
    except Exception as e:
        logger.error(f"Error during logout for user {user_id}: {str(e)}", exc_info=True)
        flash(trans('general_error', default='An error occurred during logout'), 'danger')
        log_audit_action('logout_failed', {'user_id': user_id, 'session_id': sid, 'reason': 'unexpected_error', 'error': str(e)})
        response = make_response(redirect(url_for('general_bp.landing')))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.set_cookie(current_app.config['SESSION_COOKIE_NAME'], '', expires=0, httponly=True, secure=current_app.config.get('SESSION_COOKIE_SECURE', True))
        response.set_cookie('remember_token', '', expires=0, httponly=True, secure=True)
        return response
