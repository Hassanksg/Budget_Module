from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify, send_file
from flask_login import login_required, current_user
from translations import trans
from utils import get_mongo_db, is_admin, get_user_query, logger, format_currency
from bson import ObjectId
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_wtf.file import FileAllowed
from wtforms import StringField, TextAreaField, SelectField, BooleanField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, Email, Optional
from gridfs import GridFS
from io import BytesIO
from PIL import Image
import bleach
import uuid

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')
csrf = CSRFProtect()

class ProfileForm(FlaskForm):
    full_name = StringField(
        trans('general_full_name', default='Full Name'),
        validators=[
            DataRequired(message=trans('general_full_name_required', default='Full name is required')),
            Length(min=1, max=100, message=trans('general_full_name_length', default='Full name must be between 1 and 100 characters'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}
    )
    email = StringField(
        trans('general_email', default='Email'),
        validators=[
            DataRequired(message=trans('general_email_required', default='Email is required')),
            Email(message=trans('general_email_invalid', default='Invalid email address'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}
    )
    phone = StringField(
        trans('general_phone', default='Phone'),
        validators=[
            Optional(),
            Length(max=20, message=trans('general_phone_length', default='Phone number too long'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}
    )
    profile_picture = FileField(
        trans('general_profile_picture', default='Profile Picture'),
        validators=[
            FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 
                       message=trans('general_invalid_image_format', default='Only JPG, PNG, and GIF files are allowed'))
        ],
        render_kw={'accept': 'image/*'}
    )
    first_name = StringField(
        trans('general_first_name', default='First Name'),
        validators=[
            Optional(),
            Length(max=50, message=trans('general_first_name_length', default='First name too long'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}
    )
    last_name = StringField(
        trans('general_last_name', default='Last Name'),
        validators=[
            Optional(),
            Length(max=50, message=trans('general_last_name_length', default='Last name too long'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}
    )
    personal_address = TextAreaField(
        trans('general_address', default='Address'),
        validators=[
            Optional(),
            Length(max=500, message=trans('general_address_length', default='Address too long'))
        ],
        render_kw={'class': 'form-control', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}
    )
    submit = SubmitField(
        trans('general_save_changes', default='Save Changes'),
        render_kw={'class': 'btn btn-primary w-100', 'style': 'background-color: #1E3A8A;'}
    )

class NotificationForm(FlaskForm):
    email_notifications = BooleanField(
        trans('general_email_notifications', default='Email Notifications'),
        render_kw={'class': 'form-check-input'}
    )
    sms_notifications = BooleanField(
        trans('general_sms_notifications', default='SMS Notifications'),
        render_kw={'class': 'form-check-input'}
    )
    submit = SubmitField(
        trans('general_save', default='Save'),
        render_kw={'class': 'btn btn-primary w-100', 'style': 'background-color: #1E3A8A;'}
    )

class LanguageForm(FlaskForm):
    language = SelectField(
        trans('general_language', default='Language'),
        choices=[
            ('en', trans('general_english', default='English')),
            ('ha', trans('general_hausa', default='Hausa'))
        ],
        validators=[DataRequired(message=trans('general_language_required', default='Language is required'))],
        render_kw={'class': 'form-select', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}
    )
    submit = SubmitField(
        trans('general_save', default='Save'),
        render_kw={'class': 'btn btn-primary w-100', 'style': 'background-color: #1E3A8A;'}
    )

def log_audit_action(db, user_id, action, session_id, details=None):
    """Log an audit action to the audit_logs collection."""
    try:
        db.audit_logs.insert_one({
            'user_id': user_id,
            'action': action,
            'timestamp': datetime.utcnow(),
            'session_id': session_id,
            'details': details or {}
        })
    except Exception as e:
        logger.error(f"Error logging audit action {action} for user {user_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': session_id})

@settings_bp.route('/')
@login_required
def index():
    """Display settings overview."""
    try:
        session_id = session.get('session_id', str(uuid.uuid4()))
        session['session_id'] = session_id
        user_display = {
            'id': str(current_user.id),
            'email': current_user.email,
            'display_name': current_user.personal_details.get('first_name', '') + ' ' + 
                           current_user.personal_details.get('last_name', ''),
            'phone': current_user.personal_details.get('phone_number', ''),
            'ficore_credit_balance': format_currency(
                current_user.ficore_credit_balance, 
                current_user.settings.get('currency', 'USD')
            ),
            'role': current_user.role,
            'language': current_user.language,
            'personal_details': current_user.personal_details,
            'settings': current_user.settings,
            'security_settings': current_user.security_settings,
            'profile_picture': current_user.profile_picture
        }
        return render_template(
            'settings/index.html',
            user=user_display,
            title=trans('settings_index_title', default='Settings', lang=session.get('lang', 'en')),
            background_color='#FFF8F0',
            button_color='#1E3A8A',
            text_color='#1F2937',
            success_color='#10B981',
            danger_color='#EF4444'
        )
    except Exception as e:
        logger.error(f"Error loading settings for user {current_user.id}: {str(e)}", 
                    exc_info=True, extra={'session_id': session.get('session_id', 'no-session-id')})
        flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('index'))

@settings_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Unified profile management page."""
    try:
        session_id = session.get('session_id', str(uuid.uuid4()))
        session['session_id'] = session_id
        db = get_mongo_db()
        fs = GridFS(db)
        user_id = request.args.get('user_id', current_user.id) if is_admin() else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans('general_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('index'))

        form = ProfileForm()
        if request.method == 'GET':
            form.full_name.data = user.get('display_name', user.get('_id', ''))
            form.email.data = user.get('email', '')
            form.phone.data = user.get('personal_details', {}).get('phone_number', '')
            form.first_name.data = user.get('personal_details', {}).get('first_name', '')
            form.last_name.data = user.get('personal_details', {}).get('last_name', '')
            form.personal_address.data = user.get('personal_details', {}).get('address', '')

        if form.validate_on_submit():
            try:
                # Sanitize inputs
                cleaned_data = {
                    'display_name': bleach.clean(form.full_name.data),
                    'email': bleach.clean(form.email.data.lower()),
                    'phone': bleach.clean(form.phone.data),
                    'first_name': bleach.clean(form.first_name.data),
                    'last_name': bleach.clean(form.last_name.data),
                    'personal_address': bleach.clean(form.personal_address.data)
                }

                if cleaned_data['email'] != user['email'] and db.users.find_one({'email': {'$regex': f'^{cleaned_data["email"]}$', '$options': 'i'}}):
                    flash(trans('general_email_exists', default='Email already in use'), 'danger')
                    return render_template(
                        'settings/profile.html',
                        form=form,
                        user=user,
                        title=trans('settings_profile_title', default='Profile Settings', lang=session.get('lang', 'en')),
                        background_color='#FFF8F0',
                        button_color='#1E3A8A',
                        text_color='#1F2937',
                        success_color='#10B981',
                        danger_color='#EF4444'
                    )

                update_data = {
                    'display_name': cleaned_data['display_name'],
                    'email': cleaned_data['email'],
                    'updated_at': datetime.utcnow(),
                    'setup_complete': True
                }
                if user.get('role') == 'personal':
                    update_data['personal_details'] = {
                        'first_name': cleaned_data['first_name'] or '',
                        'last_name': cleaned_data['last_name'] or '',
                        'address': cleaned_data['personal_address'] or '',
                        'phone_number': cleaned_data['phone'] or ''
                    }

                db.users.update_one(user_query, {'$set': update_data})
                log_audit_action(db, user_id, 'profile_update', session_id, {'updated_fields': list(update_data.keys())})
                flash(trans('general_profile_updated', default='Profile updated successfully'), 'success')
                logger.info(f"Profile updated for user: {user_id}", extra={'session_id': session_id})
                return redirect(url_for('settings.profile'))

            except Exception as e:
                logger.error(f"Error updating profile for user {user_id}: {str(e)}", 
                            exc_info=True, extra={'session_id': session_id})
                flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')

        user_display = {
            '_id': str(user['_id']),
            'email': user.get('email', ''),
            'display_name': user.get('display_name', ''),
            'phone': user.get('personal_details', {}).get('phone_number', ''),
            'ficore_credit_balance': format_currency(
                user.get('ficore_credit_balance', 0), 
                user.get('settings', {}).get('currency', 'USD')
            ),
            'role': user.get('role', 'personal'),
            'language': user.get('language', 'en'),
            'personal_details': user.get('personal_details', {}),
            'settings': user.get('settings', {}),
            'security_settings': user.get('security_settings', {}),
            'profile_picture': user.get('profile_picture', None)
        }
        return render_template(
            'settings/profile.html',
            form=form,
            user=user_display,
            title=trans('settings_profile_title', default='Profile Settings', lang=session.get('lang', 'en')),
            background_color='#FFF8F0',
            button_color='#1E3A8A',
            text_color='#1F2937',
            success_color='#10B981',
            danger_color='#EF4444'
        )
    except Exception as e:
        logger.error(f"Error in profile settings for user {current_user.id}: {str(e)}", 
                    exc_info=True, extra={'session_id': session.get('session_id', 'no-session-id')})
        flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('index'))

@settings_bp.route('/api/upload-profile-picture', methods=['POST'])
@login_required
@csrf.exempt
def upload_profile_picture():
    """API endpoint to handle profile picture uploads."""
    try:
        session_id = session.get('session_id', str(uuid.uuid4()))
        session['session_id'] = session_id
        db = get_mongo_db()
        fs = GridFS(db)
        user_query = get_user_query(str(current_user.id))
        user = db.users.find_one(user_query)
        if not user:
            return jsonify({"success": False, "message": trans('general_user_not_found', default='User not found.')}), 404

        if 'profile_picture' not in request.files:
            return jsonify({"success": False, "message": trans('general_no_file_uploaded', default='No file uploaded.')}), 400

        file = request.files['profile_picture']
        if file.filename == '':
            return jsonify({"success": False, "message": trans('general_no_file_selected', default='No file selected.')}), 400

        if file:
            file.seek(0, 2)
            if file.tell() > 5 * 1024 * 1024:
                return jsonify({"success": False, "message": trans('settings_image_too_large', default='Image size must be less than 5MB.')}), 400
            file.seek(0)

            try:
                file_content = file.read()
                img = Image.open(BytesIO(file_content))
                file_format = img.format.lower()
                if file_format not in ['jpeg', 'png', 'gif']:
                    return jsonify({"success": False, "message": trans('general_invalid_image_format', 
                                 default='Only JPG, PNG, and GIF files are allowed.')}), 400
            except Exception as e:
                logger.error(f"Error validating image file: {str(e)}", extra={'session_id': session_id})
                return jsonify({"success": False, "message": trans('general_invalid_image_format', 
                             default='Only JPG, PNG, and GIF files are allowed.')}), 400

            try:
                if user.get('profile_picture'):
                    fs.delete(ObjectId(user['profile_picture']))
                file_id = fs.put(file_content, filename=file.filename, content_type=file.content_type)
                db.users.update_one(user_query, {
                    '$set': {
                        'profile_picture': str(file_id),
                        'updated_at': datetime.utcnow()
                    }
                })
                log_audit_action(db, str(current_user.id), 'profile_picture_update', session_id)
                return jsonify({
                    "success": True,
                    "message": trans('settings_profile_picture_updated', default='Profile picture updated successfully.'),
                    "image_url": url_for('settings.get_profile_picture', user_id=user['_id'])
                })
            except Exception as e:
                logger.error(f"Error storing profile picture for user {current_user.id}: {str(e)}", 
                            exc_info=True, extra={'session_id': session_id})
                return jsonify({"success": False, "message": trans('general_something_went_wrong', 
                             default='An error occurred.')}), 500
    except Exception as e:
        logger.error(f"Error uploading profile picture for user {current_user.id}: {str(e)}", 
                    exc_info=True, extra={'session_id': session.get('session_id', 'no-session-id')})
        return jsonify({"success": False, "message": trans('general_something_went_wrong', 
                     default='An error occurred.')}), 500

@settings_bp.route('/profile-picture/<user_id>')
@login_required
def get_profile_picture(user_id):
    """Serve the user's profile picture."""
    try:
        session_id = session.get('session_id', str(uuid.uuid4()))
        session['session_id'] = session_id
        db = get_mongo_db()
        fs = GridFS(db)
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user or not user.get('profile_picture'):
            return redirect(url_for('static', filename='img/default_profile.png'))

        file_id = ObjectId(user['profile_picture'])
        grid_out = fs.get(file_id)
        return send_file(BytesIO(grid_out.read()), mimetype=grid_out.content_type)
    except Exception as e:
        logger.error(f"Error retrieving profile picture for user {user_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': session.get('session_id', 'no-session-id')})
        return redirect(url_for('static', filename='img/default_profile.png'))

@settings_bp.route('/notifications', methods=['GET', 'POST'])
@login_required
def notifications():
    """Update notification preferences."""
    try:
        session_id = session.get('session_id', str(uuid.uuid4()))
        session['session_id'] = session_id
        db = get_mongo_db()
        user_id = request.args.get('user_id', current_user.id) if is_admin() else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans('general_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('index'))

        form = NotificationForm(data={
            'email_notifications': user.get('settings', {}).get('email_notifications', True),
            'sms_notifications': user.get('settings', {}).get('sms_notifications', False)
        })
        if form.validate_on_submit():
            try:
                update_data = {
                    'settings.email_notifications': form.email_notifications.data,
                    'settings.sms_notifications': form.sms_notifications.data,
                    'updated_at': datetime.utcnow()
                }
                db.users.update_one(user_query, {'$set': update_data})
                log_audit_action(db, user_id, 'notification_update', session_id, 
                                {'email_notifications': form.email_notifications.data, 
                                 'sms_notifications': form.sms_notifications.data})
                flash(trans('general_notifications_updated', default='Notification preferences updated successfully'), 'success')
                return redirect(url_for('settings.index'))
            except Exception as e:
                logger.error(f"Error updating notifications for user {user_id}: {str(e)}", 
                            exc_info=True, extra={'session_id': session_id})
                flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')

        return render_template(
            'settings/notifications.html',
            form=form,
            title=trans('settings_notifications_title', default='Notification Settings', lang=session.get('lang', 'en')),
            background_color='#FFF8F0',
            button_color='#1E3A8A',
            text_color='#1F2937',
            success_color='#10B981',
            danger_color='#EF4444'
        )
    except Exception as e:
        logger.error(f"Error in notification settings for user {current_user.id}: {str(e)}", 
                    exc_info=True, extra={'session_id': session.get('session_id', 'no-session-id')})
        flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('index'))

@settings_bp.route('/language', methods=['GET', 'POST'])
@login_required
def language():
    """Update language preference."""
    try:
        session_id = session.get('session_id', str(uuid.uuid4()))
        session['session_id'] = session_id
        db = get_mongo_db()
        user_id = request.args.get('user_id', current_user.id) if is_admin() else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans('general_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('index'))

        form = LanguageForm(data={'language': user.get('language', 'en')})
        if form.validate_on_submit():
            try:
                session['lang'] = form.language.data
                db.users.update_one(
                    user_query,
                    {'$set': {'language': form.language.data, 'updated_at': datetime.utcnow()}}
                )
                log_audit_action(db, user_id, 'language_update', session_id, {'language': form.language.data})
                flash(trans('general_language_updated', default='Language updated successfully'), 'success')
                return redirect(url_for('settings.index'))
            except Exception as e:
                logger.error(f"Error updating language for user {user_id}: {str(e)}", 
                            exc_info=True, extra={'session_id': session_id})
                flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')

        return render_template(
            'settings/language.html',
            form=form,
            title=trans('settings_language_title', default='Language Settings', lang=session.get('lang', 'en')),
            background_color='#FFF8F0',
            button_color='#1E3A8A',
            text_color='#1F2937',
            success_color='#10B981',
            danger_color='#EF4444'
        )
    except Exception as e:
        logger.error(f"Error in language settings for user {current_user.id}: {str(e)}", 
                    exc_info=True, extra={'session_id': session.get('session_id', 'no-session-id')})
        flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('index'))

@settings_bp.route('/api/update-user-setting', methods=['POST'])
@login_required
@csrf.exempt
def update_user_setting():
    """API endpoint to update user settings via AJAX."""
    try:
        session_id = session.get('session_id', str(uuid.uuid4()))
        session['session_id'] = session_id
        data = request.get_json()
        setting_name = data.get('setting')
        value = data.get('value')
        valid_settings = [
            'showKoboToggle', 'incognitoModeToggle', 'appSoundsToggle',
            'fingerprintPasswordToggle', 'fingerprintPinToggle', 'hideSensitiveDataToggle'
        ]
        if setting_name not in valid_settings:
            return jsonify({"success": False, "message": trans('general_invalid_setting', 
                         default='Invalid setting name.')}), 400

        db = get_mongo_db()
        user_query = get_user_query(str(current_user.id))
        user = db.users.find_one(user_query)
        if not user:
            return jsonify({"success": False, "message": trans('general_user_not_found', 
                         default='User not found.')}), 404

        settings = user.get('settings', {})
        security_settings = user.get('security_settings', {})
        if setting_name == 'showKoboToggle':
            settings['show_kobo'] = bool(value)
        elif setting_name == 'incognitoModeToggle':
            settings['incognito_mode'] = bool(value)
        elif setting_name == 'appSoundsToggle':
            settings['app_sounds'] = bool(value)
        elif setting_name == 'fingerprintPasswordToggle':
            security_settings['fingerprint_password'] = bool(value)
        elif setting_name == 'fingerprintPinToggle':
            security_settings['fingerprint_pin'] = bool(value)
        elif setting_name == 'hideSensitiveDataToggle':
            security_settings['hide_sensitive_data'] = bool(value)

        update_data = {
            'settings': settings,
            'security_settings': security_settings,
            'updated_at': datetime.utcnow()
        }
        db.users.update_one(user_query, {'$set': update_data})
        log_audit_action(db, str(current_user.id), 'setting_update', session_id, 
                        {setting_name: value})
        return jsonify({
            "success": True,
            "message": trans('general_setting_updated', default='Setting updated successfully.')
        })
    except Exception as e:
        logger.error(f"Error updating user setting: {str(e)}", 
                    exc_info=True, extra={'session_id': session.get('session_id', 'no-session-id')})
        return jsonify({"success": False, "message": trans('general_setting_update_error', 
                     default='An error occurred while updating the setting.')}), 500
