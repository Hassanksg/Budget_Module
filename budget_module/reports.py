from flask import Blueprint, session, request, render_template, redirect, url_for, flash, jsonify, Response
from flask_login import login_required, current_user
from translations import trans
from utils import get_mongo_db, logger, format_date, format_currency, requires_role, check_ficore_credit_balance, is_admin
from bson import ObjectId
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
from flask_wtf import FlaskForm
from wtforms import DateField, SubmitField
from wtforms.validators import Optional
from branding_helpers import draw_ficore_pdf_header

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')

class ReportForm(FlaskForm):
    start_date = DateField(trans('reports_start_date', default='Start Date'), validators=[Optional()])
    end_date = DateField(trans('reports_end_date', default='End Date'), validators=[Optional()])
    submit = SubmitField(trans('reports_generate_report', default='Generate Report'))

class CustomerReportForm(FlaskForm):
    submit = SubmitField('Generate Report')

class BudgetPerformanceReportForm(FlaskForm):
    start_date = DateField(trans('reports_start_date', default='Start Date'), validators=[Optional()])
    end_date = DateField(trans('reports_end_date', default='End Date'), validators=[Optional()])
    submit = SubmitField(trans('reports_generate_report', default='Generate Report'))

def to_dict_budget(record):
    if not record:
        return {'surplus_deficit': None, 'savings_goal': None}
    return {
        'id': str(record.get('_id', '')),
        'income': record.get('income', 0),
        'fixed_expenses': record.get('fixed_expenses', 0),
        'variable_expenses': record.get('variable_expenses', 0),
        'savings_goal': record.get('savings_goal', 0),
        'surplus_deficit': record.get('surplus_deficit', 0),
        'housing': record.get('housing', 0),
        'food': record.get('food', 0),
        'transport': record.get('transport', 0),
        'dependents': record.get('dependents', 0),
        'miscellaneous': record.get('miscellaneous', 0),
        'others': record.get('others', 0),
        'custom_categories': record.get('custom_categories', []),  # Support for custom budget categories
        'created_at': format_date(record.get('created_at'), format_type='iso')
    }

@reports_bp.route('/')
@login_required
@requires_role(['personal', 'admin'])
def index():
    """Display report selection page for budget reports."""
    try:
        return render_template(
            'reports/index.html',
            title=trans('reports_index', default='Reports', lang=session.get('lang', 'en')),
            background_color='#FFF8F0'  # Soft Cream for background
        )
    except Exception as e:
        logger.error(f"Error loading reports index for user {current_user.id}: {str(e)}", exc_info=True)
        flash(trans('reports_load_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@reports_bp.route('/budget_performance', methods=['GET', 'POST'])
@login_required
@requires_role(['personal', 'admin'])
def budget_performance():
    """Generate budget performance report with filters, including custom categories."""
    form = BudgetPerformanceReportForm()
    if not is_admin() and not check_ficore_credit_balance(1):
        flash(trans('debtors_insufficient_credits', default='Insufficient credits to generate a report. Request more credits.'), 'danger')
        return redirect(url_for('credits.request_credits'))
    
    budget_data = []
    query = {} if is_admin() else {'user_id': str(current_user.id)}
    
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            budget_query = query.copy()
            if form.start_date.data:
                start_datetime = datetime.combine(form.start_date.data, datetime.min.time())
                budget_query['created_at'] = {'$gte': start_datetime}
            if form.end_date.data:
                end_datetime = datetime.combine(form.end_date.data, datetime.max.time())
                budget_query['created_at'] = budget_query.get('created_at', {}) | {'$lte': end_datetime}
            
            budgets = list(db.budgets.find(budget_query).sort('created_at', -1))
            for budget in budgets:
                budget_dict = to_dict_budget(budget)
                # Calculate totals for custom categories
                custom_total = sum(category.get('amount', 0) for category in budget_dict['custom_categories'])
                budget_dict['custom_total'] = custom_total
                budget_data.append(budget_dict)
            
            logger.info(f"Generated budget performance report for user {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id')})
            return generate_budget_performance_pdf(budget_data)
        except Exception as e:
            logger.error(f"Error generating budget performance report for user {current_user.id}: {str(e)}", exc_info=True)
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    else:
        try:
            db = get_mongo_db()
            budgets = list(db.budgets.find(query).sort('created_at', -1))
            for budget in budgets:
                budget_dict = to_dict_budget(budget)
                custom_total = sum(category.get('amount', 0) for category in budget_dict['custom_categories'])
                budget_dict['custom_total'] = custom_total
                budget_data.append(budget_dict)
        except Exception as e:
            logger.error(f"Error fetching budget data for user {current_user.id}: {str(e)}", exc_info=True)
            flash(trans('reports_generation_error', default='An error occurred'), 'danger')
    
    return render_template(
        'reports/budget_performance.html',
        form=form,
        budget_data=budget_data,
        title=trans('reports_budget_performance', default='Budget Performance Report', lang=session.get('lang', 'en')),
        background_color='#FFF8F0',  # Soft Cream for background
        button_color='#1E3A8A'  # Deep Blue for buttons
    )

@reports_bp.route('/admin/customer-reports', methods=['GET', 'POST'])
@login_required
@requires_role('admin')
def customer_reports():
    """Generate customer reports for admin, focusing on budget and credit data."""
    form = CustomerReportForm()
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            pipeline = [
                {'$match': {'role': {'$in': ['personal', 'admin']}}},
                {'$lookup': {
                    'from': 'budgets',
                    'let': {'user_id': '$_id'},
                    'pipeline': [
                        {'$match': {'$expr': {'$eq': ['$user_id', '$$user_id']}}},
                        {'$sort': {'created_at': -1}},
                        {'$limit': 1}
                    ],
                    'as': 'latest_budget'
                }},
                {'$lookup': {
                    'from': 'ficore_credit_transactions',
                    'let': {'user_id': '$_id'},
                    'pipeline': [
                        {'$match': {'$expr': {'$eq': ['$user_id', '$$user_id']}}},
                        {'$sort': {'timestamp': -1}},
                        {'$limit': 1}
                    ],
                    'as': 'latest_credit_transaction'
                }}
            ]
            users = list(db.users.aggregate(pipeline))
            report_data = []
            for user in users:
                budget = to_dict_budget(user['latest_budget'][0] if user['latest_budget'] else None)
                credit_transaction = user['latest_credit_transaction'][0] if user['latest_credit_transaction'] else {'amount': 0}
                data = {
                    'username': user['_id'],
                    'email': user.get('email', ''),
                    'role': user.get('role', ''),
                    'ficore_credit_balance': user.get('ficore_credit_balance', 0),
                    'language': user.get('language', 'en'),
                    'budget_income': budget['income'] if budget['income'] is not None else '-',
                    'budget_fixed_expenses': budget['fixed_expenses'] if budget['fixed_expenses'] is not None else '-',
                    'budget_variable_expenses': budget['variable_expenses'] if budget['variable_expenses'] is not None else '-',
                    'budget_surplus_deficit': budget['surplus_deficit'] if budget['surplus_deficit'] is not None else '-',
                    'custom_categories_count': len(budget['custom_categories']),
                    'last_credit_transaction': format_currency(credit_transaction['amount']) if credit_transaction['amount'] else '-'
                }
                report_data.append(data)
            logger.info(f"Generated customer report by admin {current_user.id}", extra={'session_id': session.get('sid', 'no-session-id')})
            return generate_customer_report_pdf(report_data)
        except Exception as e:
            logger.error(f"Error generating customer report: {str(e)}", exc_info=True)
            flash('An error occurred while generating the report', 'danger')
    
    return render_template(
        'reports/customer_reports_form.html',
        form=form,
        title='Generate Customer Report',
        background_color='#FFF8F0',  # Soft Cream for background
        button_color='#1E3A8A'  # Deep Blue for buttons
    )

def generate_budget_performance_pdf(budget_data):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    # Page setup
    header_height = 0.7
    extra_space = 0.2
    row_height = 0.3
    bottom_margin = 0.5
    max_y = 10.5
    title_y = max_y - header_height - extra_space
    page_height = (max_y - bottom_margin) * inch
    rows_per_page = int((page_height - (title_y - 0.6) * inch) / (row_height * inch))

    def draw_table_headers(y):
        p.setFillColor(colors.HexColor('#1E3A8A'))  # Deep Blue for headers
        headers = [
            trans('general_date', default='Date'),
            trans('general_income', default='Income'),
            trans('general_fixed_expenses', default='Fixed Expenses'),
            trans('general_variable_expenses', default='Variable Expenses'),
            trans('general_custom_total', default='Custom Categories Total'),
            trans('general_savings_goal', default='Savings Goal'),
            trans('general_surplus_deficit', default='Surplus/Deficit')
        ]
        x_positions = [1 * inch + i * 0.9 * inch for i in range(len(headers))]
        for header, x in zip(headers, x_positions):
            p.drawString(x, y * inch, header)
        return y - row_height, x_positions

    # Initialize first page
    draw_ficore_pdf_header(p, current_user, y_start=max_y)
    p.setFont("Helvetica", 10)
    p.setFillColor(colors.HexColor('#1E3A8A'))  # Deep Blue for title
    p.drawString(1 * inch, title_y * inch, trans('reports_budget_performance_report', default='Budget Performance Report'))
    p.drawString(1 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {format_date(datetime.utcnow())}")
    y = title_y - 0.6
    y, x_positions = draw_table_headers(y)

    row_count = 0
    p.setFillColor(colors.HexColor('#2E2E2E'))  # Dark Gray for text
    for bd in budget_data:
        if row_count >= rows_per_page:
            p.showPage()
            draw_ficore_pdf_header(p, current_user, y_start=max_y)
            y = title_y - 0.6
            y, x_positions = draw_table_headers(y)
            row_count = 0

        values = [
            format_date(bd['created_at']),
            format_currency(bd['income']),
            format_currency(bd['fixed_expenses']),
            format_currency(bd['variable_expenses']),
            format_currency(bd['custom_total']),
            format_currency(bd['savings_goal']),
            format_currency(bd['surplus_deficit'])
        ]
        for value, x in zip(values, x_positions):
            p.drawString(x, y * inch, value)
        y -= row_height
        row_count += 1

    p.save()
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=budget_performance.pdf'})

def generate_customer_report_pdf(report_data):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    # Page setup
    header_height = 0.7
    extra_space = 0.2
    row_height = 0.2
    bottom_margin = 0.5
    max_y = 10.5
    title_y = max_y - header_height - extra_space
    page_height = (max_y - bottom_margin) * inch
    rows_per_page = int((page_height - (title_y - 0.6) * inch) / (row_height * inch))

    def draw_table_headers(y):
        p.setFillColor(colors.HexColor('#1E3A8A'))  # Deep Blue for headers
        headers = [
            'Username', 'Email', 'Role', 'Credits', 'Lang',
            'Income', 'Fixed Exp', 'Var Exp', 'Surplus',
            'Custom Categories', 'Last Credit'
        ]
        x_positions = [0.5 * inch + i * 0.35 * inch for i in range(len(headers))]
        for header, x in zip(headers, x_positions):
            p.drawString(x, y * inch, header)
        return y - row_height, x_positions

    # Initialize first page
    draw_ficore_pdf_header(p, current_user, y_start=max_y)
    p.setFont("Helvetica", 8)
    p.setFillColor(colors.HexColor('#1E3A8A'))  # Deep Blue for title
    p.drawString(0.5 * inch, title_y * inch, trans('reports_customer_report', default='Customer Report'))
    p.drawString(0.5 * inch, (title_y - 0.3) * inch, f"{trans('reports_generated_on', default='Generated on')}: {format_date(datetime.utcnow())}")
    y = title_y - 0.6
    y, x_positions = draw_table_headers(y)

    row_count = 0
    p.setFillColor(colors.HexColor('#2E2E2E'))  # Dark Gray for text
    for data in report_data:
        if row_count >= rows_per_page:
            p.showPage()
            draw_ficore_pdf_header(p, current_user, y_start=max_y)
            y = title_y - 0.6
            y, x_positions = draw_table_headers(y)
            row_count = 0

        values = [
            data['username'][:15],
            data['email'][:15],
            data['role'],
            str(data['ficore_credit_balance']),
            data['language'],
            str(data['budget_income']),
            str(data['budget_fixed_expenses']),
            str(data['budget_variable_expenses']),
            str(data['budget_surplus_deficit']),
            str(data['custom_categories_count']),
            data['last_credit_transaction']
        ]
        for value, x in zip(values, x_positions):
            p.drawString(x, y * inch, str(value)[:15])
        y -= row_height
        row_count += 1

    p.save()
    buffer.seek(0)

    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=customer_report.pdf'})

