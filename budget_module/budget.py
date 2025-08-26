from flask import Blueprint, request, session, redirect, url_for, render_template, flash, current_app, jsonify, Response
from flask_wtf import FlaskForm
from wtforms import FloatField, IntegerField, SubmitField, StringField, FieldList, FormField
from wtforms.validators import DataRequired, NumberRange, ValidationError, Optional, Length
from flask_login import current_user, login_required
from utils import get_mongo_db, logger, check_ficore_credit_balance, format_date, cache
from datetime import datetime
from bson import ObjectId
from ..models import log_tool_usage, create_budget
import uuid
import bleach
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from io import BytesIO
from reports import draw_ficore_pdf_header

budget_bp = Blueprint(
    'budget',
    __name__,
    template_folder='templates/',
    url_prefix='/budget'
)

# Ficore color palette for template rendering
FICORE_PRIMARY_COLOR = "#1E3A8A"  # Deep Blue for buttons
FICORE_BACKGROUND_COLOR = "#FFF8F0"  # Soft Cream for backgrounds
FICORE_TEXT_COLOR = "#2E2E2E"  # Dark Gray for text
FICORE_SUCCESS_COLOR = "#16A34A"  # Green for success messages
FICORE_DANGER_COLOR = "#DC2626"  # Red for errors

def clean_currency(value):
    """Transform input into a float, removing commas."""
    try:
        if isinstance(value, str):
            value = value.replace(',', '')
        return float(value)
    except (ValueError, TypeError):
        return 0.0

def strip_commas(value):
    """Filter to remove commas and return a float."""
    return clean_currency(value)

def format_currency(value):
    """Format a numeric value with comma separation, no currency symbol."""
    try:
        numeric_value = float(value)
        return f"{numeric_value:,.2f}"
    except (ValueError, TypeError):
        return "0.00"

def deduct_ficore_credits(db, user_id, amount, action, budget_id=None):
    """
    Deduct Ficore Credits from user balance with transaction handling.
    """
    session_id = session.get('sid', 'unknown')
    try:
        if not user_id or amount <= 0:
            logger.error(f"Invalid parameters: user_id={user_id}, amount={amount}, action={action}",
                         extra={'session_id': session_id})
            return False
        
        user = db.users.find_one({'_id': user_id})
        if not user:
            logger.error(f"User {user_id} not found for action: {action}",
                         extra={'session_id': session_id, 'user_id': user_id})
            return False
        
        current_balance = float(user.get('ficore_credit_balance', 0))
        if current_balance < amount:
            logger.warning(f"Insufficient credits: required {amount}, available {current_balance}, action: {action}",
                           extra={'session_id': session_id, 'user_id': user_id})
            return False
        
        with db.client.start_session() as mongo_session:
            with mongo_session.start_transaction():
                result = db.users.update_one(
                    {'_id': user_id},
                    {'$inc': {'ficore_credit_balance': -amount}},
                    session=mongo_session
                )
                if result.modified_count == 0:
                    logger.error(f"Failed to deduct {amount} credits for user {user_id}, action: {action}",
                                 extra={'session_id': session_id, 'user_id': user_id})
                    return False
                
                transaction = {
                    '_id': ObjectId(),
                    'user_id': user_id,
                    'action': action,
                    'amount': float(-amount),
                    'budget_id': str(budget_id) if budget_id else None,
                    'timestamp': datetime.utcnow(),
                    'session_id': session_id,
                    'status': 'completed'
                }
                db.ficore_credit_transactions.insert_one(transaction, session=mongo_session)
                
                db.audit_logs.insert_one({
                    'admin_id': 'system',
                    'action': f'deduct_ficore_credits_{action}',
                    'details': {
                        'user_id': user_id,
                        'amount': amount,
                        'budget_id': str(budget_id) if budget_id else None,
                        'previous_balance': current_balance,
                        'new_balance': current_balance - amount
                    },
                    'timestamp': datetime.utcnow()
                }, session=mongo_session)
                
                mongo_session.commit_transaction()
                
        logger.info(f"Deducted {amount} Ficore Credits for {action} by user {user_id}. New balance: {current_balance - amount}",
                    extra={'session_id': session_id, 'user_id': user_id})
        return True
    except Exception as e:
        logger.error(f"Error deducting {amount} Ficore Credits for {action} by user {user_id}: {str(e)}",
                     extra={'session_id': session_id, 'user_id': user_id})
        return False

class CustomCategoryForm(FlaskForm):
    name = StringField(
        trans('budget_custom_category_name', default='Category Name'),
        validators=[
            DataRequired(message=trans('budget_custom_category_name_required', default='Category name is required')),
            Length(min=2, max=50, message=trans('budget_custom_category_name_length', default='Category name must be between 2 and 50 characters'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    amount = FloatField(
        trans('budget_custom_category_amount', default='Amount'),
        filters=[strip_commas],
        validators=[
            DataRequired(message=trans('budget_custom_category_amount_required', default='Amount is required')),
            NumberRange(min=0.01, max=10000000000, message=trans('budget_amount_max', default='Amount must be between 0.01 and 10 billion'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    class Meta:
        csrf = False

class CommaSeparatedIntegerField(IntegerField):
    def process_formdata(self, valuelist):
        if valuelist:
            try:
                cleaned_value = clean_currency(valuelist[0])
                self.data = int(cleaned_value) if cleaned_value is not None else None
            except (ValueError, TypeError):
                self.data = None
                raise ValidationError(trans('budget_dependents_invalid', default='Not a valid integer'))

class BudgetForm(FlaskForm):
    income = FloatField(
        trans('budget_monthly_income', default='Monthly Income'),
        filters=[strip_commas],
        validators=[
            DataRequired(message=trans('budget_income_required', default='Income is required')),
            NumberRange(min=0.01, max=10000000000, message=trans('budget_income_max', default='Income must be between 0.01 and 10 billion'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    housing = FloatField(
        trans('budget_housing_rent', default='Housing/Rent'),
        filters=[strip_commas],
        validators=[
            DataRequired(message=trans('budget_housing_required', default='Housing cost is required')),
            NumberRange(min=0.01, max=10000000000, message=trans('budget_amount_max', default='Amount must be between 0.01 and 10 billion'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    food = FloatField(
        trans('budget_food', default='Food'),
        filters=[strip_commas],
        validators=[
            DataRequired(message=trans('budget_food_required', default='Food cost is required')),
            NumberRange(min=0.01, max=10000000000, message=trans('budget_amount_max', default='Amount must be between 0.01 and 10 billion'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    transport = FloatField(
        trans('budget_transport', default='Transport'),
        filters=[strip_commas],
        validators=[
            DataRequired(message=trans('budget_transport_required', default='Transport cost is required')),
            NumberRange(min=0.01, max=10000000000, message=trans('budget_amount_max', default='Amount must be between 0.01 and 10 billion'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    dependents = CommaSeparatedIntegerField(
        trans('budget_dependents_support', default='Dependents Support'),
        validators=[
            DataRequired(message=trans('budget_dependents_required', default='Number of dependents is required')),
            NumberRange(min=0, max=100, message=trans('budget_dependents_max', default='Number of dependents cannot exceed 100'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    miscellaneous = FloatField(
        trans('budget_miscellaneous', default='Miscellaneous'),
        filters=[strip_commas],
        validators=[
            DataRequired(message=trans('budget_miscellaneous_required', default='Miscellaneous cost is required')),
            NumberRange(min=0.01, max=10000000000, message=trans('budget_amount_max', default='Amount must be between 0.01 and 10 billion'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    others = FloatField(
        trans('budget_others', default='Others'),
        filters=[strip_commas],
        validators=[
            DataRequired(message=trans('budget_others_required', default='Other expenses are required')),
            NumberRange(min=0.01, max=10000000000, message=trans('budget_amount_max', default='Amount must be between 0.01 and 10 billion'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    savings_goal = FloatField(
        trans('budget_savings_goal', default='Savings Goal'),
        filters=[strip_commas],
        validators=[
            DataRequired(message=trans('budget_savings_goal_required', default='Savings goal is required')),
            NumberRange(min=0.01, max=10000000000, message=trans('budget_amount_max', default='Amount must be between 0.01 and 10 billion'))
        ],
        render_kw={'style': f'background-color: {FICORE_BACKGROUND_COLOR}; border-color: {FICORE_PRIMARY_COLOR};'}
    )
    custom_categories = FieldList(
        FormField(CustomCategoryForm),
        min_entries=0,
        max_entries=10,
        validators=[Optional()]
    )
    submit = SubmitField(
        trans('budget_submit', default='Submit'),
        render_kw={'style': f'background-color: {FICORE_PRIMARY_COLOR}; color: {FICORE_BACKGROUND_COLOR};'}
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        lang = session.get('lang', 'en')
        for field in self:
            if hasattr(field, 'label') and field.label.text:
                field.label.text = trans(field.label.text, lang) or field.label.text

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators):
            logger.debug(f"Form validation failed: {self.errors}", extra={'session_id': session.get('sid', 'unknown')})
            return False
        try:
            category_names = [cat.form.name.data.lower() for cat in self.custom_categories.entries if cat.form.name.data]
            if len(category_names) != len(set(category_names)):
                self.custom_categories.errors.append(
                    trans('budget_duplicate_category_names', default='Custom category names must be unique')
                )
                return False
            total_expenses = sum([
                float(self.housing.data or 0.0),
                float(self.food.data or 0.0),
                float(self.transport.data or 0.0),
                float(self.miscellaneous.data or 0.0),
                float(self.others.data or 0.0),
                sum(float(cat.form.amount.data or 0.0) for cat in self.custom_categories.entries)
            ])
            if total_expenses > float(self.income.data or 0.0):
                self.custom_categories.errors.append(
                    trans('budget_expenses_exceed_income', default='Total expenses cannot exceed income')
                )
                return False
            return True
        except Exception as e:
            logger.error(f"Error in BudgetForm.validate: {str(e)}",
                         extra={'session_id': session.get('sid', 'unknown')})
            self.custom_categories.errors.append(
                trans('budget_validation_error', default='Error validating custom categories.')
            )
            return False

@budget_bp.route('/', methods=['GET'])
@login_required
def index():
    """Budget module landing page."""
    return render_template(
        'budget/index.html',
        tool_title=trans('budget_title', default='Budget Planner'),
        background_color=FICORE_BACKGROUND_COLOR,
        button_color=FICORE_PRIMARY_COLOR,
        text_color=FICORE_TEXT_COLOR
    )

@budget_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    """Create a new budget with Ficore Credits deduction."""
    session_id = session.get('sid', str(uuid.uuid4()))
    session['sid'] = session_id
    form = BudgetForm()
    db = get_mongo_db()
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json

    try:
        log_tool_usage(db=db, user_id=current_user.id, session_id=session_id, action='create_budget_view')
    except Exception as e:
        logger.error(f"Failed to log tool usage: {str(e)}", extra={'session_id': session_id})
        flash(trans('budget_log_error', default='Error logging budget activity.'), 'danger')

    try:
        activities = db.activities.find({'user_id': current_user.id, 'tool_name': 'budget'}).sort('timestamp', -1).limit(10)
        activities = [{
            'action': a['action'],
            'timestamp': format_date(a['timestamp']),
            'details': a.get('details', {})
        } for a in activities]
    except Exception as e:
        logger.error(f"Failed to fetch activities: {str(e)}", extra={'session_id': session_id})
        flash(trans('budget_activities_load_error', default='Error loading recent activities.'), 'danger')
        activities = []

    if request.method == 'POST' and form.validate_on_submit():
        if not check_ficore_credit_balance(required_amount=1, user_id=current_user.id):
            logger.warning(f"Insufficient Ficore Credits for user {current_user.id}", extra={'session_id': session_id})
            error_message = trans('budget_insufficient_credits', default='Insufficient Ficore Credits to create a budget.')
            if is_ajax:
                return jsonify({'success': False, 'message': error_message}), 400
            flash(error_message, 'danger')
            return redirect(url_for('dashboard.index'))

        custom_categories = [
            {'name': bleach.clean(cat.form.name.data), 'amount': float(cat.form.amount.data or 0.0)}
            for cat in form.custom_categories.entries if cat.form.name.data and cat.form.amount.data
        ]
        housing = float(form.housing.data or 0.0)
        food = float(form.food.data or 0.0)
        transport = float(form.transport.data or 0.0)
        miscellaneous = float(form.miscellaneous.data or 0.0)
        others = float(form.others.data or 0.0)
        fixed_expenses = housing + food + transport + miscellaneous + others
        variable_expenses = sum(cat['amount'] for cat in custom_categories)
        expenses = fixed_expenses + variable_expenses
        budget_data = {
            '_id': ObjectId(),
            'user_id': current_user.id,
            'session_id': session_id,
            'user_email': current_user.email,
            'income': float(form.income.data or 0.0),
            'fixed_expenses': fixed_expenses,
            'variable_expenses': variable_expenses,
            'total_expenses': expenses,
            'savings_goal': float(form.savings_goal.data or 0.0),
            'surplus_deficit': float(form.income.data or 0.0) - expenses,
            'housing': housing,
            'food': food,
            'transport': transport,
            'dependents': int(form.dependents.data or 0),
            'miscellaneous': miscellaneous,
            'others': others,
            'custom_categories': custom_categories,
            'created_at': datetime.utcnow()
        }

        try:
            with db.client.start_session() as mongo_session:
                with mongo_session.start_transaction():
                    budget_id = create_budget(db, budget_data)
                    if not deduct_ficore_credits(db, current_user.id, 1, 'create_budget', budget_id):
                        db.budgets.delete_one({'_id': budget_id}, session=mongo_session)
                        raise ValueError("Credit deduction failed")
                    mongo_session.commit_transaction()
            cache.delete_memoized(get_budgets)
            logger.info(f"Budget {budget_id} created for user {current_user.id}", extra={'session_id': session_id})
            success_message = trans('general_budget_created', default='Budget created successfully!')
            if is_ajax:
                return jsonify({'success': True, 'budget_id': str(budget_id), 'message': success_message}), 200
            flash(success_message, 'success')
            return redirect(url_for('budget.dashboard'))
        except Exception as e:
            logger.error(f"Failed to save budget: {str(e)}", extra={'session_id': session_id})
            error_message = trans('budget_storage_error', default='Error saving budget.')
            if is_ajax:
                return jsonify({'success': False, 'message': error_message}), 500
            flash(error_message, 'danger')

    budgets = list(db.budgets.find({'user_id': current_user.id}).sort('created_at', -1).limit(10))
    budgets_dict, latest_budget = process_budgets(budgets, session_id)
    categories = {
        trans('budget_housing_rent', default='Housing/Rent'): latest_budget.get('housing_raw', 0.0),
        trans('budget_food', default='Food'): latest_budget.get('food_raw', 0.0),
        trans('budget_transport', default='Transport'): latest_budget.get('transport_raw', 0.0),
        trans('budget_miscellaneous', default='Miscellaneous'): latest_budget.get('miscellaneous_raw', 0.0),
        trans('budget_others', default='Others'): latest_budget.get('others_raw', 0.0),
        **{cat['name']: cat['amount'] for cat in latest_budget.get('custom_categories', [])}
    }
    categories = {k: v for k, v in categories.items() if v > 0}
    tips, insights = generate_tips_and_insights(latest_budget)

    return render_template(
        'budget/new.html',
        form=form,
        budgets=budgets_dict,
        latest_budget=latest_budget,
        categories=categories,
        tips=tips,
        insights=insights,
        activities=activities,
        tool_title=trans('budget_title', default='Budget Planner'),
        background_color=FICORE_BACKGROUND_COLOR,
        button_color=FICORE_PRIMARY_COLOR,
        text_color=FICORE_TEXT_COLOR,
        success_color=FICORE_SUCCESS_COLOR,
        danger_color=FICORE_DANGER_COLOR
    )

@budget_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Budget dashboard page."""
    session_id = session.get('sid', str(uuid.uuid4()))
    session['sid'] = session_id
    db = get_mongo_db()

    try:
        log_tool_usage(db=db, user_id=current_user.id, session_id=session_id, action='dashboard_view')
    except Exception as e:
        logger.error(f"Failed to log tool usage: {str(e)}", extra={'session_id': session_id})
        flash(trans('budget_log_error', default='Error logging budget activity.'), 'danger')

    try:
        activities = db.activities.find({'user_id': current_user.id, 'tool_name': 'budget'}).sort('timestamp', -1).limit(10)
        activities = [{
            'action': a['action'],
            'timestamp': format_date(a['timestamp']),
            'details': a.get('details', {})
        } for a in activities]
    except Exception as e:
        logger.error(f"Failed to fetch activities: {str(e)}", extra={'session_id': session_id})
        flash(trans('budget_activities_load_error', default='Error loading recent activities.'), 'danger')
        activities = []

    budgets = list(db.budgets.find({'user_id': current_user.id}).sort('created_at', -1).limit(10))
    budgets_dict, latest_budget = process_budgets(budgets, session_id)
    categories = {
        trans('budget_housing_rent', default='Housing/Rent'): latest_budget.get('housing_raw', 0.0),
        trans('budget_food', default='Food'): latest_budget.get('food_raw', 0.0),
        trans('budget_transport', default='Transport'): latest_budget.get('transport_raw', 0.0),
        trans('budget_miscellaneous', default='Miscellaneous'): latest_budget.get('miscellaneous_raw', 0.0),
        trans('budget_others', default='Others'): latest_budget.get('others_raw', 0.0),
        **{cat['name']: cat['amount'] for cat in latest_budget.get('custom_categories', [])}
    }
    categories = {k: v for k, v in categories.items() if v > 0}
    tips, insights = generate_tips_and_insights(latest_budget)

    return render_template(
        'budget/dashboard.html',
        budgets=budgets_dict,
        latest_budget=latest_budget,
        categories=categories,
        tips=tips,
        insights=insights,
        activities=activities,
        tool_title=trans('budget_dashboard', default='Budget Dashboard'),
        background_color=FICORE_BACKGROUND_COLOR,
        button_color=FICORE_PRIMARY_COLOR,
        text_color=FICORE_TEXT_COLOR,
        success_color=FICORE_SUCCESS_COLOR,
        danger_color=FICORE_DANGER_COLOR
    )

@budget_bp.route('/manage', methods=['GET', 'POST'])
@login_required
def manage():
    """Manage budgets page."""
    session_id = session.get('sid', str(uuid.uuid4()))
    session['sid'] = session_id
    db = get_mongo_db()

    try:
        log_tool_usage(db=db, user_id=current_user.id, session_id=session_id, action='manage_view')
    except Exception as e:
        logger.error(f"Failed to log tool usage: {str(e)}", extra={'session_id': session_id})
        flash(trans('budget_log_error', default='Error logging budget activity.'), 'danger')

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            budget_id = request.form.get('budget_id')
            if not ObjectId.is_valid(budget_id):
                flash(trans('budget_invalid_id', default='Invalid budget ID.'), 'danger')
                return redirect(url_for('budget.manage'))

            budget = db.budgets.find_one({'_id': ObjectId(budget_id), 'user_id': current_user.id})
            if not budget:
                flash(trans('budget_not_found', default='Budget not found.'), 'danger')
                return redirect(url_for('budget.manage'))

            if not check_ficore_credit_balance(required_amount=1, user_id=current_user.id):
                logger.warning(f"Insufficient Ficore Credits for user {current_user.id}", extra={'session_id': session_id})
                flash(trans('budget_insufficient_credits', default='Insufficient Ficore Credits to delete a budget.'), 'danger')
                return redirect(url_for('dashboard.index'))

            try:
                with db.client.start_session() as mongo_session:
                    with mongo_session.start_transaction():
                        result = db.budgets.delete_one({'_id': ObjectId(budget_id)}, session=mongo_session)
                        if result.deleted_count > 0:
                            if not deduct_ficore_credits(db, current_user.id, 1, 'delete_budget', budget_id):
                                flash(trans('budget_credit_deduction_failed', default='Failed to deduct Ficore Credit.'), 'danger')
                                return redirect(url_for('budget.manage'))
                            mongo_session.commit_transaction()
                cache.delete_memoized(get_budgets)
                flash(trans('budget_deleted_success', default='Budget deleted successfully!'), 'success')
            except Exception as e:
                logger.error(f"Failed to delete budget {budget_id}: {str(e)}", extra={'session_id': session_id})
                flash(trans('budget_delete_failed', default='Error deleting budget.'), 'danger')
            return redirect(url_for('budget.manage'))

    budgets = list(db.budgets.find({'user_id': current_user.id}).sort('created_at', -1).limit(20))
    budgets_dict, _ = process_budgets(budgets, session_id)

    return render_template(
        'budget/manage.html',
        budgets=budgets_dict,
        tool_title=trans('budget_manage_budgets', default='Manage Budgets'),
        background_color=FICORE_BACKGROUND_COLOR,
        button_color=FICORE_PRIMARY_COLOR,
        text_color=FICORE_TEXT_COLOR,
        success_color=FICORE_SUCCESS_COLOR,
        danger_color=FICORE_DANGER_COLOR
    )

@budget_bp.route('/summary', methods=['GET'])
@login_required
def summary():
    """Return budget summary as JSON."""
    db = get_mongo_db()
    session_id = session.get('sid', str(uuid.uuid4()))
    try:
        log_tool_usage(db=db, user_id=current_user.id, session_id=session_id, action='summary_view')
        latest_budget = db.budgets.find_one({'user_id': current_user.id}, sort=[('created_at', -1)])
        if not latest_budget:
            return jsonify({
                'totalBudget': format_currency(0.0),
                'user_email': current_user.email
            })
        return jsonify({
            'totalBudget': format_currency(latest_budget.get('income', 0.0)),
            'user_email': latest_budget.get('user_email', current_user.email)
        })
    except Exception as e:
        logger.error(f"Error in budget.summary: {str(e)}", extra={'session_id': session_id})
        return jsonify({
            'totalBudget': format_currency(0.0),
            'user_email': current_user.email
        }), 500

@budget_bp.route('/export_pdf', methods=['GET'])
@login_required
def export_pdf():
    """Export budget to PDF with Ficore Credits deduction."""
    session_id = session.get('sid', str(uuid.uuid4()))
    db = get_mongo_db()
    budget_id = request.args.get('budget_id')
    is_single_budget = bool(budget_id)
    credit_cost = 1 if is_single_budget else 2
    export_type = 'single_budget' if is_single_budget else 'full_history'

    try:
        if not check_ficore_credit_balance(required_amount=credit_cost, user_id=current_user.id):
            flash(trans('budget_insufficient_credits_pdf', default=f'Insufficient credits for PDF export. {export_type.replace("_", " ").title()} export costs {credit_cost} FC.'), 'danger')
            return redirect(url_for('budget.manage'))

        filter_criteria = {'user_id': current_user.id}
        if is_single_budget:
            if not ObjectId.is_valid(budget_id):
                flash(trans('budget_invalid_id', default='Invalid budget ID.'), 'danger')
                return redirect(url_for('budget.manage'))
            budget = db.budgets.find_one({'_id': ObjectId(budget_id), **filter_criteria})
            if not budget:
                flash(trans('budget_no_data_for_pdf', default='No budget data found for PDF export.'), 'danger')
                return redirect(url_for('budget.manage'))
            budgets = [budget]
            report_title = f"Budget Report - {format_date(budget.get('created_at'))}"
            filename = f"budget_report_{budget_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        else:
            budgets = list(db.budgets.find(filter_criteria).sort('created_at', -1).limit(10))
            if not budgets:
                flash(trans('budget_no_data_for_pdf', default='No budget data found for PDF export.'), 'danger')
                return redirect(url_for('budget.manage'))
            report_title = "Budget History Report"
            filename = f"budget_history_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"

        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        draw_ficore_pdf_header(p, current_user, y_start=height/inch - 0.7)
        
        p.setFont("Helvetica-Bold", 16)
        p.drawString(50, height - 120, report_title)
        p.setFont("Helvetica", 12)
        y = height - 150
        p.drawString(50, y, f"Generated: {format_date(datetime.utcnow())}")
        p.drawString(50, y - 20, f"Total Budget Records: {len(budgets)}")
        y -= 60

        if is_single_budget:
            budget = budgets[0]
            p.setFont("Helvetica-Bold", 12)
            p.drawString(50, y, "Budget Details")
            y -= 20
            p.setFont("Helvetica", 10)
            p.drawString(50, y, f"Date: {format_date(budget.get('created_at'))}")
            p.drawString(50, y - 15, f"Income: {format_currency(budget.get('income', 0))}")
            p.drawString(50, y - 30, f"Fixed Expenses: {format_currency(budget.get('fixed_expenses', 0))}")
            p.drawString(50, y - 45, f"Variable Expenses: {format_currency(budget.get('variable_expenses', 0))}")
            p.drawString(50, y - 60, f"Total Expenses: {format_currency(float(budget.get('fixed_expenses', 0)) + float(budget.get('variable_expenses', 0)))}")
            p.drawString(50, y - 75, f"Savings Goal: {format_currency(budget.get('savings_goal', 0))}")
            p.drawString(50, y - 90, f"Surplus/Deficit: {format_currency(budget.get('surplus_deficit', 0))}")
            p.drawString(50, y - 105, f"Dependents: {budget.get('dependents', 0)}")
            y -= 125
            p.setFont("Helvetica-Bold", 10)
            p.drawString(50, y, "Expense Categories")
            y -= 15
            p.setFont("Helvetica", 9)
            p.drawString(50, y, f"Housing: {format_currency(budget.get('housing', 0))}")
            p.drawString(50, y - 15, f"Food: {format_currency(budget.get('food', 0))}")
            p.drawString(50, y - 30, f"Transport: {format_currency(budget.get('transport', 0))}")
            p.drawString(50, y - 45, f"Miscellaneous: {format_currency(budget.get('miscellaneous', 0))}")
            p.drawString(50, y - 60, f"Others: {format_currency(budget.get('others', 0))}")
            y -= 75
            if budget.get('custom_categories', []):
                p.setFont("Helvetica-Bold", 10)
                p.drawString(50, y, "Custom Categories")
                y -= 15
                p.setFont("Helvetica", 9)
                for cat in budget.get('custom_categories', []):
                    if y < 50:
                        p.showPage()
                        draw_ficore_pdf_header(p, current_user, y_start=height/inch - 0.7)
                        y = height - 50
                        p.setFont("Helvetica", 9)
                    p.drawString(50, y, f"{cat['name']}: {format_currency(cat['amount'])}")
                    y -= 15
        else:
            p.setFont("Helvetica-Bold", 10)
            p.drawString(50, y, "Date")
            p.drawString(150, y, "Income")
            p.drawString(220, y, "Fixed Exp.")
            p.drawString(290, y, "Variable Exp.")
            p.drawString(370, y, "Savings Goal")
            p.drawString(450, y, "Surplus/Deficit")
            y -= 20
            p.setFont("Helvetica", 9)
            for budget in budgets:
                if y < 50:
                    p.showPage()
                    draw_ficore_pdf_header(p, current_user, y_start=height/inch - 0.7)
                    y = height - 120
                    p.setFont("Helvetica-Bold", 10)
                    p.drawString(50, y, "Date")
                    p.drawString(150, y, "Income")
                    p.drawString(220, y, "Fixed Exp.")
                    p.drawString(290, y, "Variable Exp.")
                    p.drawString(370, y, "Savings Goal")
                    p.drawString(450, y, "Surplus/Deficit")
                    y -= 20
                    p.setFont("Helvetica", 9)
                p.drawString(50, y, format_date(budget.get('created_at')))
                p.drawString(150, y, format_currency(budget.get('income', 0)))
                p.drawString(220, y, format_currency(budget.get('fixed_expenses', 0)))
                p.drawString(290, y, format_currency(budget.get('variable_expenses', 0)))
                p.drawString(370, y, format_currency(budget.get('savings_goal', 0)))
                p.drawString(450, y, format_currency(budget.get('surplus_deficit', 0)))
                y -= 15

        p.save()
        buffer.seek(0)

        if not deduct_ficore_credits(db, current_user.id, credit_cost, f'export_budget_pdf_{export_type}', budget_id if is_single_budget else None):
            flash(trans('budget_credit_deduction_failed', default=f'Failed to deduct credits for {export_type.replace("_", " ").title()} PDF export.'), 'danger')
            return redirect(url_for('budget.manage'))

        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    except Exception as e:
        logger.error(f"Error exporting {export_type} PDF: {str(e)}", extra={'session_id': session_id})
        flash(trans('budget_pdf_error', default='Error generating PDF report.'), 'danger')
        return redirect(url_for('budget.manage'))

@budget_bp.route('/delete_budget', methods=['POST'])
@login_required
def delete_budget():
    """Delete a budget record with Ficore Credits deduction."""
    session_id = session.get('sid', str(uuid.uuid4()))
    db = get_mongo_db()

    try:
        data = request.get_json() or {}
        budget_id = data.get('budget_id')
        if not ObjectId.is_valid(budget_id):
            return jsonify({'success': False, 'error': trans('budget_invalid_id', default='Invalid budget ID.')}), 400

        budget = db.budgets.find_one({'_id': ObjectId(budget_id), 'user_id': current_user.id})
        if not budget:
            return jsonify({'success': False, 'error': trans('budget_not_found', default='Budget not found.')}), 404

        if not check_ficore_credit_balance(required_amount=1, user_id=current_user.id):
            logger.warning(f"Insufficient Ficore Credits for user {current_user.id}", extra={'session_id': session_id})
            return jsonify({'success': False, 'error': trans('budget_insufficient_credits', default='Insufficient Ficore Credits to delete a budget.')}), 400

        with db.client.start_session() as mongo_session:
            with mongo_session.start_transaction():
                result = db.budgets.delete_one({'_id': ObjectId(budget_id)}, session=mongo_session)
                if result.deleted_count > 0:
                    if not deduct_ficore_credits(db, current_user.id, 1, 'delete_budget', budget_id):
                        logger.warning(f"Failed to deduct Ficore Credit for budget {budget_id}", extra={'session_id': session_id})
                    mongo_session.commit_transaction()
                else:
                    return jsonify({'success': False, 'error': trans('budget_delete_failed', default='Failed to delete budget.')}), 500

        cache.delete_memoized(get_budgets)
        log_tool_usage(db=db, user_id=current_user.id, session_id=session_id, action='delete_budget')
        return jsonify({'success': True, 'message': trans('budget_deleted', default='Budget deleted successfully!')})
    except Exception as e:
        logger.error(f"Error deleting budget: {str(e)}", extra={'session_id': session_id})
        return jsonify({'success': False, 'error': trans('budget_delete_error', default='Error deleting budget.')}), 500

def process_budgets(budgets, session_id):
    """Helper function to process budgets for rendering."""
    budgets_dict = {}
    latest_budget = None
    for budget in budgets:
        fixed_raw = float(budget.get('fixed_expenses', 0.0))
        var_raw = float(budget.get('variable_expenses', 0.0))
        total_raw = fixed_raw + var_raw
        budget_data = {
            'id': str(budget['_id']),
            'user_id': budget.get('user_id'),
            'session_id': budget.get('session_id'),
            'user_email': budget.get('user_email', current_user.email),
            'income': format_currency(budget.get('income', 0.0)),
            'income_raw': float(budget.get('income', 0.0)),
            'fixed_expenses': format_currency(fixed_raw),
            'fixed_expenses_raw': fixed_raw,
            'variable_expenses': format_currency(var_raw),
            'variable_expenses_raw': var_raw,
            'total_expenses': format_currency(total_raw),
            'total_expenses_raw': total_raw,
            'savings_goal': format_currency(budget.get('savings_goal', 0.0)),
            'savings_goal_raw': float(budget.get('savings_goal', 0.0)),
            'surplus_deficit': float(budget.get('surplus_deficit', 0.0)),
            'surplus_deficit_formatted': format_currency(budget.get('surplus_deficit', 0.0)),
            'housing': format_currency(budget.get('housing', 0.0)),
            'housing_raw': float(budget.get('housing', 0.0)),
            'food': format_currency(budget.get('food', 0.0)),
            'food_raw': float(budget.get('food', 0.0)),
            'transport': format_currency(budget.get('transport', 0.0)),
            'transport_raw': float(budget.get('transport', 0.0)),
            'dependents': str(budget.get('dependents', 0)),
            'dependents_raw': int(budget.get('dependents', 0)),
            'miscellaneous': format_currency(budget.get('miscellaneous', 0.0)),
            'miscellaneous_raw': float(budget.get('miscellaneous', 0.0)),
            'others': format_currency(budget.get('others', 0.0)),
            'others_raw': float(budget.get('others', 0.0)),
            'custom_categories': budget.get('custom_categories', []),
            'created_at': format_date(budget.get('created_at')) if budget.get('created_at') else 'N/A'
        }
        budgets_dict[budget_data['id']] = budget_data
        if not latest_budget or (budget.get('created_at') and (latest_budget['created_at'] == 'N/A' or budget.get('created_at') > datetime.strptime(latest_budget['created_at'], '%Y-%m-%d'))):
            latest_budget = budget_data
    if not latest_budget:
        latest_budget = {
            'id': None,
            'user_id': None,
            'session_id': session_id,
            'user_email': current_user.email,
            'income': format_currency(0.0),
            'income_raw': 0.0,
            'fixed_expenses': format_currency(0.0),
            'fixed_expenses_raw': 0.0,
            'variable_expenses': format_currency(0.0),
            'variable_expenses_raw': 0.0,
            'total_expenses': format_currency(0.0),
            'total_expenses_raw': 0.0,
            'savings_goal': format_currency(0.0),
            'savings_goal_raw': 0.0,
            'surplus_deficit': 0.0,
            'surplus_deficit_formatted': format_currency(0.0),
            'housing': format_currency(0.0),
            'housing_raw': 0.0,
            'food': format_currency(0.0),
            'food_raw': 0.0,
            'transport': format_currency(0.0),
            'transport_raw': 0.0,
            'dependents': str(0),
            'dependents_raw': 0,
            'miscellaneous': format_currency(0.0),
            'miscellaneous_raw': 0.0,
            'others': format_currency(0.0),
            'others_raw': 0.0,
            'custom_categories': [],
            'created_at': 'N/A'
        }
    return budgets_dict, latest_budget

def generate_tips_and_insights(latest_budget):
    """Generate budget tips and insights."""
    tips = [
        trans("budget_tip_track_expenses", default='Track your expenses daily to stay within budget.'),
        trans("budget_tip_ajo_savings", default='Contribute to ajo savings for financial discipline.'),
        trans("budget_tip_data_subscriptions", default='Optimize data subscriptions to reduce costs.'),
        trans("budget_tip_plan_dependents", default='Plan for dependents’ expenses in advance.')
    ]
    insights = []
    try:
        income_float = float(latest_budget.get('income_raw', 0.0))
        surplus_deficit_float = float(latest_budget.get('surplus_deficit', 0.0))
        savings_goal_float = float(latest_budget.get('savings_goal_raw', 0.0))
        if income_float > 0:
            if surplus_deficit_float < 0:
                insights.append(trans("budget_insight_budget_deficit", default='Your expenses exceed your income. Consider reducing costs.'))
            elif surplus_deficit_float > 0:
                insights.append(trans("budget_insight_budget_surplus", default='You have a surplus. Consider increasing savings.'))
            if savings_goal_float == 0:
                insights.append(trans("budget_insight_set_savings_goal", default='Set a savings goal to build financial security.'))
            if income_float > 0 and latest_budget.get('housing_raw', 0.0) / income_float > 0.4:
                insights.append(trans("budget_insight_high_housing", default='Housing costs exceed 40% of income. Consider cost-saving measures.'))
    except (ValueError, TypeError) as e:
        logger.warning(f"Error generating insights: {str(e)}", extra={'session_id': session.get('sid', 'unknown')})

    return tips, insights
