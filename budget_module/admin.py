import logging
from bson import ObjectId
from flask import Blueprint, request, session as flask_session, redirect, url_for, render_template, flash, current_app
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField, validators
import datetime
from models import get_budgets, create_feedback
from credits import ApproveCreditRequestForm, fix_ficore_credit_balances
from utils import get_mongo_db, logger, get_user_query

admin_bp = Blueprint('admin', __name__, template_folder='templates/admin')

# Form Definitions
class CreditRequestsListForm(FlaskForm):
    status = SelectField(
        trans('credits_request_status_filter', default='Filter by Status'),
        choices=[
            ('all', trans('credits_all_statuses', default='All')),
            ('pending', trans('credits_pending', default='Pending')),
            ('approved', trans('credits_approved', default='Approved')),
            ('denied', trans('credits_denied', default='Denied'))
        ],
        validators=[validators.DataRequired()],
        render_kw={'class': 'form-select', 'style': 'background-color: #FFF8F0; border-color: #1E3A8A;'}  # Soft Cream background, Deep Blue border
    )
    submit = SubmitField(
        trans('credits_filter', default='Filter'),
        render_kw={'class': 'btn', 'style': 'background-color: #1E3A8A; color: #FFF8F0;'}  # Deep Blue button, Soft Cream text
    )

# Helper Functions
def log_audit_action(action, details=None):
    """Log an admin action to audit_logs collection."""
    try:
        db = get_mongo_db()
        db.audit_logs.insert_one({
            'admin_id': str(current_user.id),
            'action': action,
            'details': details or {},
            'timestamp': datetime.datetime.utcnow()
        })
    except Exception as e:
        logger.error(f"Error logging audit action: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})

# Routes
@admin_bp.route('/dashboard', methods=['GET'])
@login_required
@utils.requires_role('admin')
def dashboard():
    """Admin dashboard with budget-related statistics."""
    try:
        fix_ficore_credit_balances()
        
        db = get_mongo_db()
        stats = {
            'users': db.users.count_documents({}),
            'budgets': db.budgets.count_documents({}),
            'credit_transactions': db.ficore_credit_transactions.count_documents({}),
            'audit_logs': db.audit_logs.count_documents({})
        }
        
        tool_usage = {
            'audit_logs': db.audit_logs.count_documents({'action': {'$in': ['tool_used', 'tool_accessed']}})
        }
        
        recent_users = list(db.users.find().sort('created_at', -1).limit(5))
        for user in recent_users:
            user['_id'] = str(user['_id'])
            user['ficore_credit_balance'] = int(user.get('ficore_credit_balance', 0))
            
        logger.info(f"Admin {current_user.id} accessed dashboard at {datetime.datetime.utcnow()}",
                    extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return render_template(
            'admin/dashboard.html',
            stats=stats,
            tool_usage=tool_usage,
            recent_users=recent_users,
            title=trans('admin_dashboard', default='Admin Dashboard'),
            background_color='#FFF8F0',  # Soft Cream background
            button_color='#1E3A8A',  # Deep Blue for buttons
            text_color='#2E2E2E'  # Dark Gray for text
        )
    except Exception as e:
        logger.error(f"Error loading admin dashboard for {current_user.id}: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_dashboard_error', default='An error occurred while loading the dashboard'), 'danger')
        return redirect(url_for('general_bp.error'))

@admin_bp.route('/feedbacks', methods=['GET'])
@login_required
@utils.requires_role('admin')
def view_feedbacks():
    """View budget-related feedbacks."""
    try:
        db = get_mongo_db()
        feedbacks = list(db.feedback.find({'tool_name': 'budget'}).sort('timestamp', -1))
        for feedback in feedbacks:
            feedback['_id'] = str(feedback['_id'])
        return render_template(
            'admin/feedback_list.html',
            feedbacks=feedbacks,
            title=trans('admin_feedbacks_title', default='Budget Feedbacks'),
            background_color='#FFF8F0',  # Soft Cream background
            text_color='#2E2E2E'  # Dark Gray for text
        )
    except Exception as e:
        logger.error(f"Error fetching feedbacks for admin: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('admin/feedback_list.html', feedbacks=[], background_color='#FFF8F0', text_color='#2E2E2E'), 500

@admin_bp.route('/users', methods=['GET'])
@login_required
@utils.requires_role('admin')
def manage_users():
    """View and manage users."""
    try:
        db = get_mongo_db()
        users = list(db.users.find({'role': {'$in': ['personal', 'admin']}}).sort('created_at', -1))
        for user in users:
            user['_id'] = str(user['_id'])
            user['username'] = user['_id']
            user['ficore_credit_balance'] = int(user.get('ficore_credit_balance', 0))
        return render_template(
            'admin/users.html',
            users=users,
            title=trans('admin_manage_users_title', default='Manage Users'),
            background_color='#FFF8F0',  # Soft Cream background
            button_color='#1E3A8A',  # Deep Blue for buttons
            text_color='#2E2E2E'  # Dark Gray for text
        )
    except Exception as e:
        logger.error(f"Error fetching users for admin: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('admin/users.html', users=[], background_color='#FFF8F0', text_color='#2E2E2E'), 500

@admin_bp.route('/users/suspend/<user_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
def suspend_user(user_id):
    """Suspend a user account."""
    try:
        db = get_mongo_db()
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans('admin_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('admin.manage_users'))
        if user['role'] == 'admin':
            flash(trans('admin_cannot_suspend_admin', default='Cannot suspend an admin account'), 'danger')
            return redirect(url_for('admin.manage_users'))
        result = db.users.update_one(
            user_query,
            {'$set': {'suspended': True, 'updated_at': datetime.datetime.utcnow()}}
        )
        if result.modified_count == 0:
            flash(trans('admin_user_not_updated', default='User could not be suspended'), 'danger')
        else:
            flash(trans('admin_user_suspended', default='User suspended successfully'), 'success')
            logger.info(f"Admin {current_user.id} suspended user {user_id}",
                        extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('suspend_user', {'user_id': user_id})
        return redirect(url_for('admin.manage_users'))
    except Exception as e:
        logger.error(f"Error suspending user {user_id}: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/delete/<user_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
def delete_user(user_id):
    """Delete a user and their budget data."""
    try:
        db = get_mongo_db()
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans('admin_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('admin.manage_users'))
        if user['role'] == 'admin':
            flash(trans('admin_cannot_delete_admin', default='Cannot delete an admin account'), 'danger')
            return redirect(url_for('admin.manage_users'))
        db.budgets.delete_many({'user_id': user_id})
        db.ficore_credit_transactions.delete_many({'user_id': user_id})
        db.credit_requests.delete_many({'user_id': user_id})
        db.audit_logs.delete_many({'details.user_id': user_id})
        result = db.users.delete_one(user_query)
        if result.deleted_count == 0:
            flash(trans('admin_user_not_deleted', default='User could not be deleted'), 'danger')
        else:
            flash(trans('admin_user_deleted', default='User deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted user {user_id}",
                        extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('delete_user', {'user_id': user_id})
        return redirect(url_for('admin.manage_users'))
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/credits/requests', methods=['GET'])
@login_required
@utils.requires_role('admin')
def view_credit_requests():
    """View all pending credit requests."""
    form = CreditRequestsListForm()
    try:
        db = get_mongo_db()
        status_filter = request.args.get('status', 'pending') if not form.validate_on_submit() else form.status.data
        query = {} if status_filter == 'all' else {'status': status_filter}
        requests = list(db.credit_requests.find(query).sort('created_at', -1).limit(50))
        for req in requests:
            req['_id'] = str(req['_id'])
            req['receipt_file_id'] = str(req['receipt_file_id']) if req.get('receipt_file_id') else None
            user = db.users.find_one({'_id': req['user_id']})
            req['ficore_credit_balance'] = int(user.get('ficore_credit_balance', 0)) if user else 0
        return render_template(
            'admin/credits_requests.html',
            form=form,
            requests=requests,
            title=trans('credits_requests_title', default='Pending Credit Requests'),
            background_color='#FFF8F0',  # Soft Cream background
            button_color='#1E3A8A',  # Deep Blue for buttons
            text_color='#2E2E2E'  # Dark Gray for text
        )
    except Exception as e:
        logger.error(f"Error fetching credit requests for admin {current_user.id}: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('admin/credits_requests.html', form=form, requests=[], title=trans('general_error', default='Error'), background_color='#FFF8F0', text_color='#2E2E2E')

@admin_bp.route('/credits/request/<request_id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
def manage_credit_request(request_id):
    """Approve or deny a credit request."""
    form = ApproveCreditRequestForm()
    try:
        db = get_mongo_db()
        client = db.client
        request_data = db.credit_requests.find_one({'_id': ObjectId(request_id)})
        if not request_data:
            flash(trans('credits_request_not_found', default='Credit request not found'), 'danger')
            return redirect(url_for('admin.view_credit_requests'))

        if form.validate_on_submit():
            status = form.status.data
            ref = f"REQ_PROCESS_{datetime.datetime.utcnow().isoformat()}"
            with client.start_session() as mongo_session:
                with mongo_session.start_transaction():
                    db.credit_requests.update_one(
                        {'_id': ObjectId(request_id)},
                        {
                            '$set': {
                                'status': status,
                                'updated_at': datetime.datetime.utcnow(),
                                'admin_id': str(current_user.id)
                            }
                        },
                        session=mongo_session
                    )
                    if status == 'approved':
                        from ..credits import credit_ficore_credits
                        credit_ficore_credits(
                            user_id=request_data['user_id'],
                            amount=int(request_data['amount']),
                            ref=ref,
                            type='add',
                            admin_id=str(current_user.id)
                        )
                    db.audit_logs.insert_one({
                        'admin_id': str(current_user.id),
                        'action': f'credit_request_{status}',
                        'details': {'request_id': request_id, 'user_id': request_data['user_id'], 'amount': int(request_data['amount'])},
                        'timestamp': datetime.datetime.utcnow()
                    }, session=mongo_session)
            flash(trans(f'credits_request_{status}', default=f'Credit request {status} successfully'), 'success')
            logger.info(f"Admin {current_user.id} {status} credit request {request_id} for user {request_data['user_id']}",
                        extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            return redirect(url_for('admin.view_credit_requests'))
        
        request_data['ficore_credit_balance'] = int(db.users.find_one({'_id': request_data['user_id']}).get('ficore_credit_balance', 0))
        return render_template(
            'admin/credits_request.html',
            form=form,
            request=request_data,
            title=trans('credits_manage_request_title', default='Manage Credit Request'),
            background_color='#FFF8F0',  # Soft Cream background
            button_color='#1E3A8A',  # Deep Blue for buttons
            text_color='#2E2E2E'  # Dark Gray for text
        )
    except Exception as e:
        logger.error(f"Error managing credit request {request_id} by admin {current_user.id}: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return redirect(url_for('admin.view_credit_requests'))

@admin_bp.route('/budgets', methods=['GET'])
@login_required
@utils.requires_role('admin')
def admin_budgets():
    """View all user budgets."""
    try:
        db = get_mongo_db()
        budgets = list(get_budgets(db, {}))
        for budget in budgets:
            budget['_id'] = str(budget['_id'])
        return render_template(
            'admin/budgets.html',
            budgets=budgets,
            title=trans('admin_budgets_title', default='Manage Budgets'),
            background_color='#FFF8F0',  # Soft Cream background
            button_color='#1E3A8A',  # Deep Blue for buttons
            text_color='#2E2E2E'  # Dark Gray for text
        )
    except Exception as e:
        logger.error(f"Error fetching budgets for admin: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('admin/budgets.html', budgets=[], background_color='#FFF8F0', text_color='#2E2E2E'), 500

@admin_bp.route('/budgets/delete/<budget_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
def admin_delete_budget(budget_id):
    """Delete a budget."""
    try:
        db = get_mongo_db()
        result = db.budgets.delete_one({'_id': ObjectId(budget_id)})
        if result.deleted_count == 0:
            flash(trans('admin_item_not_found', default='Budget not found'), 'danger')
        else:
            flash(trans('admin_item_deleted', default='Budget deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted budget {budget_id}",
                        extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('delete_budget', {'budget_id': budget_id})
        return redirect(url_for('admin.admin_budgets'))
    except Exception as e:
        logger.error(f"Error deleting budget {budget_id}: {str(e)}",
                     extra={'session_id': flask_session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')

        return redirect(url_for('admin.admin_budgets'))
