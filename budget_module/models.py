from datetime import datetime
from pymongo import ASCENDING, DESCENDING
from bson import ObjectId
from pymongo.errors import DuplicateKeyError, OperationFailure, PyMongoError, WriteError
from flask_login import UserMixin
from utils import get_mongo_db, logger
from werkzeug.security import generate_password_hash
import uuid
from translations import trans

def get_db():
    """Get MongoDB database connection using the global client from utils.py.
    
    Returns:
        Database object
    """
    try:
        db = get_mongo_db()
        logger.info(f"Successfully connected to MongoDB database: {db.name}", extra={'session_id': 'no-session-id'})
        return db
    except Exception as e:
        logger.error(f"Error connecting to database: {str(e)}", exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def initialize_app_data(app):
    """Initialize MongoDB collections and indexes for budget-related collections.
    
    Args:
        app: Flask application instance
    """
    with app.app_context():
        try:
            db = get_db()
            db.command('ping')
            logger.info(f"{trans('general_database_connection_established', default='MongoDB connection established')}", extra={'session_id': 'no-session-id'})

            # Check for existing ficorerecords user
            if not db.users.find_one({'_id': 'ficorerecords'}):
                try:
                    db.users.insert_one({
                        '_id': 'ficorerecords',
                        'user_id': str(uuid.uuid4()),
                        'ficore_credit_balance': 0.0,
                        'role': 'system',
                        'created_at': datetime.utcnow(),
                        'setup_complete': True
                    })
                    logger.info("Created ficorerecords user", extra={'session_id': 'no-session-id'})
                except DuplicateKeyError:
                    logger.warning("ficorerecords user already exists", extra={'session_id': 'no-session-id'})

            collections = db.list_collection_names()
            # Define collection schemas
            collection_schemas = {
                'users': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['_id', 'ficore_credit_balance', 'created_at'],
                            'properties': {
                                '_id': {'bsonType': 'string'},
                                'user_id': {'bsonType': ['string', 'null']},
                                'email': {'bsonType': ['string', 'null']},
                                'password_hash': {'bsonType': ['string', 'null']},
                                'ficore_credit_balance': {'bsonType': ['double', 'int'], 'minimum': 0},
                                'role': {'enum': ['personal', 'admin', 'system']},
                                'created_at': {'bsonType': 'date'},
                                'setup_complete': {'bsonType': 'bool'},
                                'language': {'bsonType': ['string', 'null']},
                                'personal_details': {'bsonType': ['object', 'null']},
                                'settings': {'bsonType': ['object', 'null']},
                                'security_settings': {'bsonType': ['object', 'null']},
                                'profile_picture': {'bsonType': ['string', 'null']},
                                'display_name': {'bsonType': ['string', 'null']},
                                'is_admin': {'bsonType': 'bool'},
                                'username': {'bsonType': ['string', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING)], 'unique': True, 'partialFilterExpression': {'user_id': {'$exists': True}}},
                        {'key': [('email', ASCENDING)], 'unique': True, 'partialFilterExpression': {'email': {'$exists': True}}}
                    ]
                },
                'budgets': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'income', 'fixed_expenses', 'variable_expenses', 'created_at'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'session_id': {'bsonType': ['string', 'null']},
                                'income': {'bsonType': ['double', 'int'], 'minimum': 0},
                                'fixed_expenses': {'bsonType': ['double', 'int'], 'minimum': 0},
                                'variable_expenses': {'bsonType': ['double', 'int'], 'minimum': 0},
                                'savings_goal': {'bsonType': ['double', 'int', 'null'], 'minimum': 0},
                                'surplus_deficit': {'bsonType': ['double', 'int', 'null']},
                                'housing': {'bsonType': ['double', 'int', 'null'], 'minimum': 0},
                                'food': {'bsonType': ['double', 'int', 'null'], 'minimum': 0},
                                'transport': {'bsonType': ['double', 'int', 'null'], 'minimum': 0},
                                'dependents': {'bsonType': ['int', 'null'], 'minimum': 0},
                                'miscellaneous': {'bsonType': ['double', 'int', 'null'], 'minimum': 0},
                                'others': {'bsonType': ['double', 'int', 'null'], 'minimum': 0},
                                'custom_categories': {
                                    'bsonType': 'array',
                                    'items': {
                                        'bsonType': 'object',
                                        'required': ['name', 'amount'],
                                        'properties': {
                                            'name': {'bsonType': 'string', 'maxLength': 50},
                                            'amount': {'bsonType': ['double', 'int'], 'minimum': 0, 'maximum': 10000000000}
                                        },
                                        'additionalProperties': False
                                    },
                                    'maxItems': 20
                                },
                                'created_at': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('created_at', DESCENDING)]}
                    ]
                },
                'ficore_credit_transactions': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'action', 'amount', 'timestamp', 'session_id', 'status'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'action': {'bsonType': 'string'},
                                'amount': {'bsonType': ['double', 'int']},
                                'budget_id': {'bsonType': ['string', 'null']},
                                'timestamp': {'bsonType': 'date'},
                                'session_id': {'bsonType': 'string'},
                                'status': {'enum': ['completed', 'failed', 'pending']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('timestamp', DESCENDING)]},
                        {'key': [('status', ASCENDING)]},
                        {'key': [('action', ASCENDING)]}
                    ]
                },
                'audit_logs': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'action', 'timestamp', 'session_id'],
                            'properties': {
                                'user_id': {'bsonType': ['string', 'null']},
                                'action': {'bsonType': 'string'},
                                'timestamp': {'bsonType': 'date'},
                                'session_id': {'bsonType': 'string'},
                                'details': {'bsonType': ['object', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('timestamp', DESCENDING)]}
                    ]
                },
                'sessions': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['_id', 'user_id', 'timestamp'],
                            'properties': {
                                '_id': {'bsonType': 'string'},
                                'user_id': {'bsonType': 'string'},
                                'timestamp': {'bsonType': 'date'},
                                'data': {'bsonType': 'object'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('timestamp', DESCENDING)]}
                    ]
                }
            }

            # Initialize collections and indexes
            for collection_name, config in collection_schemas.items():
                if collection_name in collections:
                    try:
                        db.command('collMod', collection_name, validator=config.get('validator', {}))
                        logger.info(f"Updated validator for collection: {collection_name}", extra={'session_id': 'no-session-id'})
                    except OperationFailure as e:
                        logger.warning(f"Could not update validator for collection {collection_name}: {e}")
                    except Exception as e:
                        logger.error(f"Failed to update validator for collection {collection_name}: {str(e)}", exc_info=True, extra={'session_id': 'no-session-id'})
                        raise
                else:
                    try:
                        db.create_collection(collection_name, validator=config.get('validator', {}))
                        logger.info(f"{trans('general_collection_created', default='Created collection')}: {collection_name}", extra={'session_id': 'no-session-id'})
                    except Exception as e:
                        logger.error(f"Failed to create collection {collection_name}: {str(e)}", exc_info=True, extra={'session_id': 'no-session-id'})
                        raise

                # Manage indexes
                existing_indexes = db[collection_name].index_information()
                for index in config.get('indexes', []):
                    keys = index['key']
                    options = {k: v for k, v in index.items() if k != 'key'}
                    index_found = False
                    for existing_index_name, existing_index_info in existing_indexes.items():
                        if tuple(existing_index_info['key']) == tuple(keys):
                            existing_options = {k: v for k, v in existing_index_info.items() if k not in ['key', 'v', 'ns', 'name']}
                            if existing_options == options:
                                logger.info(f"Index already exists on {collection_name}: {keys}", extra={'session_id': 'no-session-id'})
                                index_found = True
                                break
                            else:
                                if existing_index_name != '_id_':
                                    logger.warning(f"Dropping conflicting index {existing_index_name} on {collection_name} to create new one")
                                    db[collection_name].drop_index(existing_index_name)
                    if not index_found:
                        try:
                            index_name = options.get('name', None)
                            db[collection_name].create_index(keys, name=index_name, **options)
                            logger.info(f"Created index on {collection_name}: {keys} with options {options}", extra={'session_id': 'no-session-id'})
                        except DuplicateKeyError:
                            logger.error(f"Failed to create UNIQUE index on {collection_name} due to existing duplicate data. "
                                        f"Please clean up duplicates manually.", extra={'session_id': 'no-session-id'})
                        except PyMongoError as e:
                            logger.error(f"Failed to create index on {collection_name}: {str(e)}", exc_info=True, extra={'session_id': 'no-session-id'})
                            raise

        except Exception as e:
            logger.error(f"{trans('general_database_initialization_failed', default='Failed to initialize database')}: {str(e)}", 
                        exc_info=True, extra={'session_id': 'no-session-id'})
            raise

class User(UserMixin):
    """User class for Flask-Login compatibility."""
    def __init__(self, user_doc):
        self.id = str(user_doc.get('_id', ''))
        self.user_id = user_doc.get('user_id', '')
        self.email = user_doc.get('email', '')
        self.password_hash = user_doc.get('password_hash', '')
        self.ficore_credit_balance = float(user_doc.get('ficore_credit_balance', 0))
        self.role = user_doc.get('role', 'personal')
        self.created_at = user_doc.get('created_at', None)
        self.setup_complete = user_doc.get('setup_complete', False)
        self.language = user_doc.get('language', 'en')
        self.personal_details = user_doc.get('personal_details', {})
        self.settings = user_doc.get('settings', {})
        self.security_settings = user_doc.get('security_settings', {})
        self.profile_picture = user_doc.get('profile_picture', None)
        self.display_name = user_doc.get('display_name', '')

    @property
    def is_active(self):
        db = get_db()
        user = db.users.find_one({'_id': self.id})
        return user.get('is_active', True) if user else False

    def get_id(self):
        return str(self.id)
    
    def get_first_name(self):
        """Get the first name from display_name or email"""
        if self.display_name and self.display_name != self.id:
            return self.display_name.split()[0] if ' ' in self.display_name else self.display_name
        return self.email.split('@')[0] if '@' in self.email else self.id

def get_budgets(db, filter_kwargs):
    """Retrieve budget records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of budget records
    """
    try:
        return list(db.budgets.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_budgets_fetch_error', default='Error getting budgets')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_budget(db, budget_data):
    """Create a new budget record in the budgets collection.
    
    Args:
        db: MongoDB database instance
        budget_data: Dictionary containing budget information
    
    Returns:
        str: ID of the created budget record
    """
    try:
        required_fields = ['user_id', 'income', 'fixed_expenses', 'variable_expenses', 'created_at']
        if not all(field in budget_data for field in required_fields):
            raise ValueError(trans('general_missing_budget_fields', default='Missing required budget fields'))
        budget_data['custom_categories'] = budget_data.get('custom_categories', [])
        logger.debug(f"Inserting budget_data into {db.budgets.name}: {budget_data}", 
                    extra={'session_id': budget_data.get('session_id', 'no-session-id')})
        result = db.budgets.insert_one(budget_data)
        logger.info(f"{trans('general_budget_created', default='Created budget record with ID')}: {result.inserted_id}", 
                    extra={'session_id': budget_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except WriteError as e:
        logger.error(f"WriteError creating budget record: {str(e)}", 
                    exc_info=True, extra={'session_id': budget_data.get('session_id', 'no-session-id')})
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating budget record: {str(e)}", 
                    exc_info=True, extra={'session_id': budget_data.get('session_id', 'no-session-id')})
        raise

def update_budget(db, budget_id, update_data):
    """Update a budget record in the budgets collection.
    
    Args:
        db: MongoDB database instance
        budget_id: The ID of the budget record to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        result = db.budgets.update_one(
            {'_id': ObjectId(budget_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_budget_updated', default='Updated budget record with ID')}: {budget_id}", 
                        extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_budget_no_change', default='No changes made to budget record with ID')}: {budget_id}", 
                    extra={'session_id': 'no-session-id'})
        return False
    except WriteError as e:
        logger.error(f"{trans('general_budget_update_error', default='Error updating budget record with ID')} {budget_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise
    except Exception as e:
        logger.error(f"{trans('general_budget_update_error', default='Error updating budget record with ID')} {budget_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_budget(record):
    """Convert budget record to dictionary."""
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
        'custom_categories': record.get('custom_categories', []),
        'created_at': record.get('created_at')
    }

def get_user(db, user_id):
    """Get user by ID.
    
    Args:
        db: MongoDB database instance
        user_id: User ID
    
    Returns:
        User object or None
    """
    try:
        user_doc = db.users.find_one({'_id': user_id})
        if user_doc:
            return User(user_doc)
        return None
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {str(e)}")
        return None

def get_user_by_email(db, email):
    """Get user by email.
    
    Args:
        db: MongoDB database instance
        email: User email
    
    Returns:
        User object or None
    """
    try:
        user_doc = db.users.find_one({'email': {'$regex': f'^{email}$', '$options': 'i'}})
        if user_doc:
            return User(user_doc)
        return None
    except Exception as e:
        logger.error(f"Error getting user by email {email}: {str(e)}")
        return None

def create_user(db, user_data):
    """Create a new user in the database.
    
    Args:
        db: MongoDB database instance
        user_data: Dictionary containing user information
    
    Returns:
        str: ID of the created user
    """
    try:
        if user_data.get('role') != 'admin' and ('user_id' not in user_data or user_data['user_id'] is None):
            user_data['user_id'] = str(uuid.uuid4())
        if 'password' in user_data:
            user_data['password_hash'] = generate_password_hash(user_data.pop('password'))
        user_data.setdefault('created_at', datetime.utcnow())
        user_data.setdefault('ficore_credit_balance', 10.0)
        user_data.setdefault('role', 'personal')
        user_data.setdefault('is_admin', False)
        user_data.setdefault('setup_complete', False)
        user_data.setdefault('language', 'en')
        user_data.setdefault('settings', {})
        user_data.setdefault('security_settings', {})
        result = db.users.insert_one(user_data)
        logger.info(f"Created user with ID: {result.inserted_id}", extra={'session_id': 'no-session-id'})
        return str(result.inserted_id)
    except DuplicateKeyError as e:
        logger.error(f"Duplicate key error creating user with user_id {user_data.get('user_id')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise
    except WriteError as e:
        logger.error(f"WriteError creating user: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating user: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_user_balance(db, user_id, amount, session_id='no-session-id'):
    """Update a user's ficore_credit_balance atomically.
    
    Args:
        db: MongoDB database instance
        user_id: The ID of the user to update
        amount: The amount to add to the balance (can be positive or negative)
        session_id: Session ID for logging
    
    Returns:
        bool: True if updated, False otherwise
    """
    try:
        result = db.users.update_one(
            {'user_id': user_id},
            {'$inc': {'ficore_credit_balance': amount}}
        )
        if result.modified_count > 0:
            logger.info(f"Updated user {user_id} ficore_credit_balance by {amount}", 
                        extra={'session_id': session_id})
            return True
        return False
    except WriteError as e:
        logger.error(f"Error updating user balance for {user_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': session_id})
        raise
    except Exception as e:
        logger.error(f"Error updating user balance for {user_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': session_id})
        raise

def get_ficore_credit_transactions(db, filter_kwargs):
    """Retrieve ficore credit transactions based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of transaction records
    """
    try:
        return list(db.ficore_credit_transactions.find(filter_kwargs).sort('timestamp', DESCENDING))
    except Exception as e:
        logger.error(f"Error getting ficore credit transactions: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_ficore_credit_transaction(transaction):
    """Convert a ficore_credit_transaction document to a dictionary."""
    return {
        'user_id': str(transaction.get('user_id', '')),
        'action': transaction.get('action', ''),
        'amount': transaction.get('amount', 0),
        'timestamp': transaction.get('timestamp', None),
        'session_id': transaction.get('session_id', ''),
        'status': transaction.get('status', ''),
        'budget_id': transaction.get('budget_id', None)
    }

def create_credit_request(db, request_data):
    """Insert a new credit request document into the credit_requests collection.
    
    Args:
        db: MongoDB database instance
        request_data: Dictionary containing request info
    
    Returns:
        str: Inserted request ID
    """
    try:
        result = db.credit_requests.insert_one(request_data)
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error creating credit request: {str(e)}", 
                    exc_info=True, extra={'session_id': request_data.get('session_id', 'no-session-id')})
        raise

def update_credit_request(db, request_id, update_data):
    """Update a credit request document by ID.
    
    Args:
        db: MongoDB database instance
        request_id: The ID (_id) of the credit request
        update_data: dict of fields to update
    
    Returns:
        bool: True if updated, False otherwise
    """
    try:
        result = db.credit_requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': update_data}
        )
        return result.modified_count > 0
    except Exception as e:
        logger.error(f"Error updating credit request {request_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_credit_requests(db, filter_kwargs):
    """Retrieve credit request documents matching filter.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: dict of filter criteria
    
    Returns:
        list: List of requests
    """
    try:
        return list(db.credit_requests.find(filter_kwargs).sort('created_at', -1))
    except Exception as e:
        logger.error(f"Error fetching credit requests: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_credit_request(doc):
    """Convert a credit request document to a serializable dict.
    
    Args:
        doc: MongoDB document
    
    Returns:
        dict
    """
    if not doc:
        return {}
    return {
        'id': str(doc.get('_id', '')),
        'user_id': doc.get('user_id', ''),
        'amount': doc.get('amount', 0),
        'payment_method': doc.get('payment_method', ''),
        'receipt_file_id': str(doc.get('receipt_file_id', '')) if doc.get('receipt_file_id', '') else None,
        'status': doc.get('status', ''),
        'created_at': doc.get('created_at'),
        'updated_at': doc.get('updated_at', None),
        'admin_id': doc.get('admin_id', None)
    }

def create_feedback(db, feedback_data):
    """Insert a feedback document into the feedback collection.
    
    Args:
        db: MongoDB database instance
        feedback_data: dict containing feedback info
    
    Returns:
        str: Inserted feedback ID
    """
    try:
        result = db.feedback.insert_one(feedback_data)
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"Error creating feedback: {str(e)}", 
                    exc_info=True, extra={'session_id': feedback_data.get('session_id', 'no-session-id')})
        raise
