from datetime import datetime
from pymongo import ASCENDING, DESCENDING
from bson import ObjectId
from pymongo.errors import DuplicateKeyError, OperationFailure, PyMongoError, WriteError
from utils import get_mongo_db, logger
from werkzeug.security import generate_password_hash
import uuid
from translations import trans

def get_db():
    """
    Get MongoDB database connection using the global client from utils.py.
    
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
    """
    Initialize MongoDB collections and indexes for budget-related collections.
    
    Args:
        app: Flask application instance
    """
    with app.app_context():
        try:
            db = get_db()
            db.command('ping')
            logger.info(f"{trans('general_database_connection_established', default='MongoDB connection established')}",
                        extra={'session_id': 'no-session-id'})
            
            collections = db.list_collection_names()
            
            # Define collection schemas for budgets, users, and ficore credit transactions
            collection_schemas = {
                'users': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'properties': {
                                '_id': {'bsonType': 'string'},
                                'user_id': {'bsonType': 'string'},
                                'ficore_credit_balance': {'bsonType': ['double', 'int'], 'minimum': 0}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING)], 'unique': True}
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
                                'savings_goal': {'bsonType': ['double', 'int'], 'minimum': 0},
                                'surplus_deficit': {'bsonType': ['double', 'int']},
                                'housing': {'bsonType': ['double', 'int'], 'minimum': 0},
                                'food': {'bsonType': ['double', 'int'], 'minimum': 0},
                                'transport': {'bsonType': ['double', 'int'], 'minimum': 0},
                                'dependents': {'bsonType': 'int', 'minimum': 0},
                                'miscellaneous': {'bsonType': ['double', 'int'], 'minimum': 0},
                                'others': {'bsonType': ['double', 'int'], 'minimum': 0},
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
                }
            }
                
            # Initialize collections and indexes
            for collection_name, config in collection_schemas.items():
                if collection_name in collections:
                    try:
                        db.command('collMod', collection_name, validator=config.get('validator', {}))
                        logger.info(f"Updated validator for collection: {collection_name}",
                                    extra={'session_id': 'no-session-id'})
                    except OperationFailure as e:
                        logger.warning(f"Could not update validator for collection {collection_name}: {e}.")
                    except Exception as e:
                        logger.error(f"Failed to update validator for collection {collection_name}: {str(e)}",
                                     exc_info=True, extra={'session_id': 'no-session-id'})
                        raise
                else:
                    try:
                        db.create_collection(collection_name, validator=config.get('validator', {}))
                        logger.info(f"{trans('general_collection_created', default='Created collection')}: {collection_name}",
                                   extra={'session_id': 'no-session-id'})
                    except Exception as e:
                        logger.error(f"Failed to create collection {collection_name}: {str(e)}",
                                     exc_info=True, extra={'session_id': 'no-session-id'})
                        raise
                
                # Manage indexes
                existing_indexes = db[collection_name].index_information()
                for index in config.get('indexes', []):
                    keys = index['key']
                    options = {k: v for k, v in index.items() if k != 'key'}
                    
                    # Check if an index with these keys and options already exists
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
                                    logger.warning(f"Dropping conflicting index {existing_index_name} on {collection_name} to create new one.")
                                    db[collection_name].drop_index(existing_index_name)
                    
                    if not index_found:
                        try:
                            index_name = options.get('name', None)
                            db[collection_name].create_index(keys, name=index_name, **options)
                            logger.info(f"Created index on {collection_name}: {keys} with options {options}",
                                        extra={'session_id': 'no-session-id'})
                        except DuplicateKeyError:
                            logger.error(f"Failed to create UNIQUE index on {collection_name} due to existing duplicate data. "
                                         f"Please clean up duplicates manually.",
                                         extra={'session_id': 'no-session-id'})
                        except PyMongoError as e:
                            logger.error(f"Failed to create index on {collection_name}: {str(e)}",
                                         exc_info=True, extra={'session_id': 'no-session-id'})
                            raise
                            
        except Exception as e:
            logger.error(f"{trans('general_database_initialization_failed', default='Failed to initialize database')}: {str(e)}",
                         exc_info=True, extra={'session_id': 'no-session-id'})
            raise

def get_budgets(db, filter_kwargs):
    """
    Retrieve budget records based on filter criteria.
    
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
    """
    Create a new budget record in the budgets collection.
    
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
        budget_data['custom_categories'] = budget_data.get('custom_categories', [])  # Ensure custom_categories is included
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
    """
    Update a budget record in the budgets collection.
    
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
    """
    Get user by ID.
    
    Args:
        db: MongoDB database instance
        user_id: User ID
    
    Returns:
        User object or None
    """
    try:
        user_doc = db.users.find_one({'_id': user_id})
        if user_doc:
            class UserObj:
                def __init__(self, doc):
                    for key, value in doc.items():
                        setattr(self, key, value)
                    self.ficore_credit_balance = float(doc.get('ficore_credit_balance', 0))
            return UserObj(user_doc)
        return None
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {str(e)}")
        return None

def get_user_by_email(db, email):
    """
    Get user by email.
    
    Args:
        db: MongoDB database instance
        email: User email
    
    Returns:
        User object or None
    """
    try:
        user_doc = db.users.find_one({'email': email.lower()})
        if user_doc:
            class UserObj:
                def __init__(self, doc):
                    for key, value in doc.items():
                        setattr(self, key, value)
                    self.ficore_credit_balance = float(doc.get('ficore_credit_balance', 0))
            return UserObj(user_doc)
        return None
    except Exception as e:
        logger.error(f"Error getting user by email {email}: {str(e)}")
        return None

def create_user(db, user_data):
    """
    Create a new user in the database or update an existing user if the _id already exists.
    
    Args:
        db: MongoDB database instance
        user_data: Dictionary containing user information
    
    Returns:
        str: ID of the created or updated user
    """
    try:
        if 'password' in user_data:
            user_data['password_hash'] = generate_password_hash(user_data.pop('password'))
        
        user_data.setdefault('created_at', datetime.utcnow())
        user_data.setdefault('ficore_credit_balance', 10.0)
        user_data.setdefault('role', 'personal')
        user_data.setdefault('is_admin', False)
        user_data.setdefault('setup_complete', False)
        
        # Check if user with the given _id already exists
        existing_user = db.users.find_one({'_id': user_data['_id']})
        if existing_user:
            # Update existing user
            result = db.users.update_one(
                {'_id': user_data['_id']},
                {'$set': user_data}
            )
            if result.modified_count > 0:
                logger.info(f"Updated user with ID: {user_data['_id']}")
            else:
                logger.info(f"No changes made to user with ID: {user_data['_id']}")
            return str(user_data['_id'])
        
        # Insert new user
        result = db.users.insert_one(user_data)
        logger.info(f"Created user with ID: {result.inserted_id}")
        return str(result.inserted_id)
    except WriteError as e:
        logger.error(f"Error creating or updating user: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error creating or updating user: {str(e)}")
        raise

def update_user_balance(db, user_id, amount):
    """
    Update a user's ficore_credit_balance atomically.
    
    Args:
        db: MongoDB database instance
        user_id: The ID of the user to update
        amount: The amount to add to the balance (can be positive or negative)
    
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
                        extra={'session_id': 'no-session-id'})
            return True
        return False
    except WriteError as e:
        logger.error(f"Error updating user balance for {user_id}: {str(e)}", 
                     exc_info=True, extra={'session_id': 'no-session-id'})
        raise
    except Exception as e:
        logger.error(f"Error updating user balance for {user_id}: {str(e)}", 
                     exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def get_ficore_credit_transactions(db, filter_kwargs):
    """
    Retrieve ficore credit transactions based on filter criteria.
    
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


