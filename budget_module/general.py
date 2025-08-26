from flask import Blueprint, render_template, redirect, url_for, flash, session, request
from flask_login import login_required, current_user
from jinja2.exceptions import TemplateNotFound
from datetime import datetime
from models import create_feedback
from flask import current_app
from utils import get_mongo_db, logger, get_user_query
from users import get_post_login_redirect
from translations import trans

general_bp = Blueprint('general_bp', __name__, url_prefix='/general', template_folder='templates', static_folder='static')

@general_bp.route('/landing')
def landing():
    """Render the public landing page."""
    try:
        if current_user.is_authenticated:
            current_app.logger.info(f"Authenticated user {current_user.id} redirected from landing to {get_post_login_redirect(current_user.role)}")
            return redirect(get_post_login_redirect(current_user.role))

        current_app.logger.info(f"Accessing general.landing - User: Unauthenticated, Session: {dict(session)}")
        response = render_template(
            'general/landingpage.html',
            title=trans('general_welcome', lang=session.get('lang', 'en'), default='Welcome'),
            background_color='#FFF8F0'  # Soft Cream background
        )
        return response
    except TemplateNotFound:
        current_app.logger.error(f"Template 'general/landingpage.html' not found", extra={'session_id': session.get('sid', 'unknown')})
        flash(trans('general_error', default='An error occurred'), 'danger')
        return render_template(
            'general/error.html',
            error_message="Unable to load the landing page due to a missing template.",
            title=trans('general_welcome', lang=session.get('lang', 'en'), default='Welcome'),
            background_color='#FFF8F0'
        ), 500
    except Exception as e:
        current_app.logger.error(f"Error rendering landing page: {str(e)}", extra={'session_id': session.get('sid', 'unknown')})
        flash(trans('general_error', default='An error occurred'), 'danger')
        return render_template(
            'general/error.html',
            error_message="Unable to load the landing page due to an internal error.",
            title=trans('general_welcome', lang=session.get('lang', 'en'), default='Welcome'),
            background_color='#FFF8F0'
        ), 500

@general_bp.route('/home')
@login_required
def home():
    """Personal homepage."""
    if current_user.role not in ['personal', 'admin']:
        flash(trans('general_access_denied', default='You do not have permission to access this page.'), 'danger')
        return redirect(url_for('general_bp.landing'))
    
    try:
        return render_template(
            'general/home.html',
            title=trans('general_business_home', lang=session.get('lang', 'en'), default='Home'),
            background_color='#FFF8F0',  # Soft Cream background
            button_color='#1E3A8A'  # Deep Blue for buttons
        )
    except TemplateNotFound:
        current_app.logger.error(f"Template 'general/home.html' not found", extra={'session_id': session.get('sid', 'unknown')})
        return render_template(
            'general/error.html',
            error_message="Unable to load the home page due to a missing template.",
            title=trans('general_business_home', lang=session.get('lang', 'en'), default='Home'),
            background_color='#FFF8F0'
        ), 500

@general_bp.route('/access_denied')
@login_required
def access_denied():
    """Render a friendly access denied page."""
    try:
        return render_template(
            'general/access_denied.html',
            title=trans('access_denied', default='Access Denied', lang=session.get('lang', 'en')),
            message=trans('general_access_denied', default='You do not have permission to access this page.', lang=session.get('lang', 'en')),
            background_color='#FFF8F0',  # Soft Cream background
            text_color='#2E2E2E'  # Dark Gray for text
        ), 403
    except TemplateNotFound:
        current_app.logger.error(f"Template 'general/access_denied.html' not found", extra={'session_id': session.get('sid', 'unknown')})
        return render_template(
            'general/error.html',
            error_message="Unable to load the access denied page due to a missing template.",
            title=trans('access_denied', lang=session.get('lang', 'en'), default='Access Denied'),
            background_color='#FFF8F0'
        ), 500

@general_bp.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    """Feedback page for budget-related tools."""
    lang = session.get('lang', 'en')
    current_app.logger.info('Handling feedback', extra={'ip_address': request.remote_addr, 'session_id': session.get('sid', 'no-session-id')})
    tool_options = [
        ['budget', trans('budget_budget_planner', default='Budget Planner', lang=lang)],
        ['report', trans('reports_dashboard', default='Budget Reports', lang=lang)]
    ]
    if request.method == 'POST':
        try:
            tool_name = request.form.get('tool_name')
            rating = request.form.get('rating')
            comment = request.form.get('comment', '').strip()
            valid_tools = [option[0] for option in tool_options]
            if not tool_name or tool_name not in valid_tools:
                current_app.logger.error(f'Invalid feedback tool: {tool_name}', extra={'ip_address': request.remote_addr})
                flash(trans('general_invalid_input', default='Please select a valid tool'), 'danger')
                return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang), background_color='#FFF8F0', button_color='#1E3A8A')

            if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
                current_app.logger.error(f'Invalid rating: {rating}', extra={'ip_address': request.remote_addr})
                flash(trans('general_invalid_input', default='Please provide a rating between 1 and 5'), 'danger')
                return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang), background_color='#FFF8F0', button_color='#1E3A8A')

            db = get_mongo_db()
            query = get_user_query(str(current_user.id))
            result = db.users.update_one(query, {'$inc': {'ficore_credit_balance': -1}})
            if result.matched_count == 0:
                raise ValueError(f'No user found for ID {current_user.id}')

            db.ficore_credit_transactions.insert_one({
                'user_id': str(current_user.id),
                'email': current_user.email,
                'amount': -1,
                'type': 'debit',
                'description': f'Feedback submission for {tool_name}',
                'timestamp': datetime.utcnow()
            })

            feedback_entry = {
                'user_id': current_user.id,
                'session_id': session.get('sid', 'no-session-id'),
                'tool_name': tool_name,
                'rating': int(rating),
                'comment': comment or None,
                'timestamp': datetime.utcnow()
            }
            create_feedback(db, feedback_entry)
            db.audit_logs.insert_one({
                'admin_id': 'system',
                'action': 'submit_feedback',
                'details': {'user_id': str(current_user.id), 'tool_name': tool_name},
                'timestamp': datetime.utcnow()
            })

            current_app.logger.info(f'Feedback submitted: tool={tool_name}, rating={rating}', 
                                   extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('general_thank_you', default='Thank you for your feedback!'), 'success')
            return redirect(url_for('general_bp.home'))
        except ValueError as e:
            current_app.logger.error(f'User not found: {str(e)}', extra={'ip_address': request.remote_addr})
            flash(trans('general_error', default='User not found'), 'danger')
            return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang), background_color='#FFF8F0', button_color='#1E3A8A'), 400
        except TemplateNotFound:
            current_app.logger.error(f"Template 'general/feedback.html' not found", extra={'ip_address': request.remote_addr})
            flash(trans('general_error', default='An error occurred'), 'danger')
            return render_template('general/error.html', error_message="Unable to load the feedback page due to a missing template.", title=trans('general_feedback', lang=lang), background_color='#FFF8F0'), 500
        except Exception as e:
            current_app.logger.error(f'Error processing feedback: {str(e)}', exc_info=True, extra={'ip_address': request.remote_addr})
            flash(trans('general_error', default='Error occurred during feedback submission'), 'danger')
            return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang), background_color='#FFF8F0', button_color='#1E3A8A'), 500
    try:
        return render_template(
            'general/feedback.html',
            tool_options=tool_options,
            title=trans('general_feedback', lang=lang, default='Feedback'),
            background_color='#FFF8F0',  # Soft Cream background
            button_color='#1E3A8A'  # Deep Blue for buttons
        )
    except TemplateNotFound:
        current_app.logger.error(f"Template 'general/feedback.html' not found", extra={'session_id': session.get('sid', 'unknown')})
        return render_template(
            'general/error.html',
            error_message="Unable to load the feedback page due to a missing template.",
            title=trans('general_feedback', lang=lang, default='Feedback'),
            background_color='#FFF8F0'
        ), 500

@general_bp.route('/about')
def about():
    """Render the about page."""
    try:
        return render_template(
            'general/about.html',
            title=trans('general_about', lang=session.get('lang', 'en'), default='About Us'),
            background_color='#FFF8F0'
        )
    except TemplateNotFound:
        current_app.logger.error(f"Template 'general/about.html' not found", extra={'session_id': session.get('sid', 'unknown')})
        return render_template(
            'general/error.html',
            error_message="Unable to load the about page due to a missing template.",
            title=trans('general_about', lang=session.get('lang', 'en'), default='About Us'),
            background_color='#FFF8F0'
        ), 500

@general_bp.route('/contact', methods=['GET', 'POST'])
def contact():
    """Render the contact page and handle form submissions."""
    lang = session.get('lang', 'en')
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            email = request.form.get('email')
            message = request.form.get('message', '').strip()
            if not name or not email or not message:
                flash(trans('general_invalid_input', default='Please fill out all required fields'), 'danger')
                return render_template('general/contact.html', title=trans('general_contact', lang=lang, default='Contact Us'), background_color='#FFF8F0', button_color='#1E3A8A')

            db = get_mongo_db()
            db.contacts.insert_one({
                'name': name,
                'email': email,
                'message': message,
                'user_id': current_user.id if current_user.is_authenticated else None,
                'session_id': session.get('sid', 'no-session-id'),
                'timestamp': datetime.utcnow()
            })
            current_app.logger.info(f"Contact form submitted: name={name}, email={email}", extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('general_thank_you', default='Thank you for your message!'), 'success')
            return redirect(url_for('general_bp.contact'))
        except Exception as e:
            current_app.logger.error(f"Error processing contact form: {str(e)}", extra={'ip_address': request.remote_addr})
            flash(trans('general_error', default='Error occurred during form submission'), 'danger')
            return render_template('general/contact.html', title=trans('general_contact', lang=lang, default='Contact Us'), background_color='#FFF8F0', button_color='#1E3A8A'), 500

    try:
        return render_template(
            'general/contact.html',
            title=trans('general_contact', lang=lang, default='Contact Us'),
            background_color='#FFF8F0',
            button_color='#1E3A8A'
        )
    except TemplateNotFound:
        current_app.logger.error(f"Template 'general/contact.html' not found", extra={'session_id': session.get('sid', 'unknown')})
        return render_template(
            'general/error.html',
            error_message="Unable to load the contact page due to a missing template.",
            title=trans('general_contact', lang=lang, default='Contact Us'),
            background_color='#FFF8F0'
        ), 500

@general_bp.route('/personal_finance_tips')
def personal_finance_tips():
    """Render the personal finance tips page."""
    try:
        return render_template(
            'general/personal_finance_tips.html',
            title=trans('general_finance_tips', lang=session.get('lang', 'en'), default='Personal Finance Tips'),
            background_color='#FFF8F0'
        )
    except TemplateNotFound:
        current_app.logger.error(f"Template 'general/personal_finance_tips.html' not found", extra={'session_id': session.get('sid', 'unknown')})
        return render_template(
            'general/error.html',
            error_message="Unable to load the finance tips page due to a missing template.",
            title=trans('general_finance_tips', lang=session.get('lang', 'en'), default='Personal Finance Tips'),
            background_color='#FFF8F0'
        ), 500

@general_bp.route('/privacy')
def privacy():
    """Render the privacy policy page."""
    try:
        return render_template(
            'general/privacy.html',
            title=trans('general_privacy', lang=session.get('lang', 'en'), default='Privacy Policy'),
            background_color='#FFF8F0'
        )
    except TemplateNotFound:
        current_app.logger.error(f"Template 'general/privacy.html' not found", extra={'session_id': session.get('sid', 'unknown')})
        return render_template(
            'general/error.html',
            error_message="Unable to load the privacy policy page due to a missing template.",
            title=trans('general_privacy', lang=session.get('lang', 'en'), default='Privacy Policy'),
            background_color='#FFF8F0'
        ), 500

@general_bp.route('/terms')
def terms():
    """Render the terms of service page."""
    try:
        return render_template(
            'general/terms.html',
            title=trans('general_terms', lang=session.get('lang', 'en'), default='Terms of Service'),
            background_color='#FFF8F0'
        )
    except TemplateNotFound:
        current_app.logger.error(f"Template 'general/terms.html' not found", extra={'session_id': session.get('sid', 'unknown')})
        return render_template(
            'general/error.html',
            error_message="Unable to load the terms of service page due to a missing template.",
            title=trans('general_terms', lang=session.get('lang', 'en'), default='Terms of Service'),
            background_color='#FFF8F0'
        ), 500
