import uuid
from flask import Blueprint, jsonify, session
from flask_login import login_required, current_user
from utils import get_mongo_db, logger, format_currency, format_date

# Create a new Blueprint for activities
activities_bp = Blueprint('activities', __name__)
## API Endpoints

@activities_bp.route('/summary', methods=['GET'])
@login_required
def summary():
    """Return budget summary as JSON."""
    db = get_mongo_db()
    session_id = session.get('sid', str(uuid.uuid4()))
    
    try:
        user = db.users.find_one({'_id': current_user.id})
        user_currency = user.get('currency', 'USD') if user else 'USD'
        
        latest_budget = db.budgets.find_one({'user_id': current_user.id}, sort=[('created_at', -1)])
        
        if not latest_budget:
            return jsonify({
                'totalIncome': format_currency(0.0, user_currency),
                'totalExpenses': format_currency(0.0, user_currency),
                'user_email': current_user.email
            })

        total_income = latest_budget.get('income', 0.0)
        total_expenses = latest_budget.get('total_expenses', 0.0)
        
        return jsonify({
            'totalIncome': format_currency(total_income, user_currency),
            'totalExpenses': format_currency(total_expenses, user_currency),
            'user_email': current_user.email
        })
    except Exception as e:
        logger.error(f"Error in activities.summary: {str(e)}", extra={'session_id': session_id})
        user = db.users.find_one({'_id': current_user.id})
        user_currency = user.get('currency', 'USD') if user else 'USD'
        return jsonify({
            'totalIncome': format_currency(0.0, user_currency),
            'totalExpenses': format_currency(0.0, user_currency),
            'user_email': current_user.email
        }), 500

@activities_bp.route('/recent-activities', methods=['GET'])
@login_required
def recent_activities():
    """Return a list of recent activities (budgets and expenses) as JSON."""
    db = get_mongo_db()
    session_id = session.get('sid', str(uuid.uuid4()))
    
    try:
        user = db.users.find_one({'_id': current_user.id})
        user_currency = user.get('currency', 'USD') if user else 'USD'

        # Query a single activities collection for simplicity and efficiency
        activities = db.activities.find({'user_id': current_user.id, 'tool_name': 'budget'}).sort('timestamp', -1).limit(10)
        
        formatted_activities = [{
            'action': act.get('action', 'N/A'),
            'type': act.get('type', 'N/A'),
            'details': act.get('details', {}),
            'amount': format_currency(act.get('amount', 0.0), user_currency),
            'date': format_date(act.get('timestamp'))
        } for act in activities]

        return jsonify(formatted_activities)
    except Exception as e:
        logger.error(f"Error in recent_activities: {str(e)}", extra={'session_id': session_id})
        return jsonify({'error': 'An error occurred while fetching recent activities.'}), 500
