from flask import Flask, jsonify, request, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.ext.mutable import Mutable
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime, timedelta
from flask_session import Session
import pytz
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from functools import wraps


app = Flask(__name__)
# CORS(app, resources={r"/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}}, supports_credentials=True)
CORS(app, supports_credentials=True, origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_headers=["Content-Type", "Authorization"],)

app.secret_key = "supersecretkey" 
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///jwhit.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REMEMBER_COOKIE_SECURE"] = False
app.config["BCRYPT_LOG_ROUNDS"] = 12  # Set work factor to 12 if not already configured
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevents client-side scripts from accessing cookies
app.config["SESSION_COOKIE_SAMESITE"] = "None"  # Allows cookies in cross-origin requests

app.json.compact = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)  # Initialize bcrypt for password hashing
SECRET_KEY = app.secret_key  # Use Flask’s secret key or define a new one

@app.get("/")
def index():
    return jsonify({"message": "Hello World!"})
def generate_token(user):
    payload = {
        'user_id': user.id,
        'username': user.username,
        'user_type': user.user_type,
        'exp': datetime.utcnow() + timedelta(hours=6)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token
def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').split(" ")[1] if 'Authorization' in request.headers else None
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token!'}), 401

        # Set user information as attributes of the request object
        request.user_id = payload['user_id']
        request.username = payload.get('username')
        request.user_type = payload.get('user_type')
        return f(*args, **kwargs)
    return decorated
@app.before_request
def before_request():
    # Skip token verification for preflight (OPTIONS) requests
    if request.method == 'OPTIONS':
        return '', 204

    token = request.headers.get('Authorization', '').split(" ")[1] if 'Authorization' in request.headers else None
    if token:
        try:
            payload = verify_token(token)
            if payload:
                # Attach user data to the request object
                request.user_id = payload['user_id']
                request.username = payload.get('username')
                request.user_type = payload.get('user_type')
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    else:
        return jsonify({'error': 'Token is missing'}), 401

@app.after_request
def after_request(response):
    # response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5173')
    # response.headers.add('Access-Control-Allow-Credentials', 'true')
    # response.headers.add('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
    # response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    return response

# ---------------------BOOKING-------------------------------------------------------------------#
class Booking(db.Model, SerializerMixin):
    __tablename__ = "bookings"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    booking_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    event_date = db.Column(db.DateTime, nullable=False)
    event_name = db.Column(db.String(100), nullable=False, server_default='Unnamed Event')
    event_type = db.Column(db.String(20), nullable=False, server_default='Karaoke')
    location = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    price = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(20), nullable=False, default="unpaid")
    number_of_guests = db.Column(db.Integer, nullable=True)
    special_requests = db.Column(db.Text, nullable=True)
    client_name = db.Column(db.String(100), nullable=True, server_default='Unknown')  # New field
    client_email = db.Column(db.String(100), nullable=True, server_default='noemail@example.com')  # New field
    client_phone = db.Column(db.String(20), nullable=True, server_default='N/A')   # New field
    rating = db.Column(db.Integer, nullable=True)  # Rating from 1 to 5

    
    # Relationship with User
    user = db.relationship("User", back_populates="bookings")

    def to_dict(self):
        local_timezone = pytz.timezone("America/New_York")  
        booking_date_local = self.booking_date.astimezone(local_timezone) if self.booking_date else None
        event_date_local = self.event_date.astimezone(local_timezone) if self.event_date else None
        formatted_booking_date = booking_date_local.strftime('%A, %B %d, %Y %I:%M %p') if booking_date_local else None
        formatted_event_date = event_date_local.strftime('%A, %B %d, %Y %I:%M %p') if event_date_local else None
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username,
            "booking_date": formatted_booking_date,
            "event_date": formatted_event_date,
            "event_name": self.event_name,
            "event_type": self.event_type,
            "location": self.location,
            "status": self.status,
            "price": self.price,
            "payment_status": self.payment_status,
            "number_of_guests": self.number_of_guests,
            "special_requests": self.special_requests,
            "client_name": self.client_name,
            "client_email": self.client_email,
            "client_phone": self.client_phone,
            "rating": self.rating,

        }

@app.post('/api/bookings')
@token_required
def create_booking():
    print("Entering create_booking route.")

    data = request.get_json()
    user_id = request.user_id
    username = request.username
    user_type = request.user_type
    print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})
    event_date = data.get('event_date')
    location = data.get('location')
    event_name = data.get('event_name', 'Unnamed Event')
    event_type = data.get('event_type', 'Karaoke')
    price = data.get('price')
    number_of_guests = data.get('number_of_guests')
    special_requests = data.get('special_requests')
    client_name = data.get('client_name')
    client_email = data.get('client_email')
    client_phone = data.get('client_phone')
    print("Request Data:", data)


    # Validation: Required fields
    if not all([user_id, event_date, location, price, client_name, client_phone, client_email, number_of_guests, special_requests, event_type]):
        missing_fields = [field for field in ["user_id", "number_of_guests", "special_requests", "client_name", "client_email", "client_phone", "event_type" , "event_date", "location", "price"] if not locals().get(field)]
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
    
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, client_email):
            print("Invalid email format:", client_email)
            return jsonify({'error': 'Invalid email format.'}), 400
    # Validation: Price
    try:
        price = round(float(price), 2)
        if price <= 0:
            raise ValueError
    except ValueError:
        return jsonify({'error': 'Price must be a positive number.'}), 400

    # Validation: Event Date format and future check
    try:
        event_date_obj = datetime.strptime(event_date, '%A, %B %d, %Y %I:%M %p')
        if event_date_obj <= datetime.now():
            return jsonify({'error': 'Event date must be in the future.'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use "Friday, June 26, 2024 05:00 PM".'}), 400

    # Validation: Location length
    if len(location) > 100:
        return jsonify({'error': 'Location cannot exceed 100 characters.'}), 400

    # Validation: Number of guests (if provided)
    if number_of_guests is not None:
        if not isinstance(number_of_guests, int) or number_of_guests <= 0:
            return jsonify({'error': 'Number of guests must be a positive integer.'}), 400
    
    # Validation: Special requests character limit
    if special_requests and len(special_requests) > 500:
        return jsonify({'error': 'Special requests cannot exceed 500 characters.'}), 400
    new_booking = Booking(
        user_id=user_id,
        event_date=event_date_obj,
        event_name=event_name,
        event_type=event_type,
        location=location,
        price=price,
        number_of_guests=number_of_guests,
        special_requests=special_requests,
        client_name=client_name,
        client_email=client_email,
        client_phone=client_phone
    )

    db.session.add(new_booking)
    db.session.commit()

    return jsonify(new_booking.to_dict()), 201
@app.patch('/api/bookings/<int:booking_id>/rate')
@token_required
def rate_booking(booking_id):
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload

    print("Token Data:", {"user_id": user_id, "user_type": user_type})

    # Check if the user is a client
    if user_type != 'client':
        return jsonify({'error': 'Unauthorized access. Only clients can rate.'}), 403

    booking = Booking.query.get(booking_id)
    if not booking:
        return jsonify({'error': 'Booking not found.'}), 404

    # Ensure the booking belongs to the user
    if booking.user_id != user_id:
        return jsonify({'error': 'Permission denied. You cannot rate this booking.'}), 403

    data = request.get_json()
    rating = data.get('rating')

    # Debug: Print the received rating value
    print("Received rating:", rating)

    # Validate rating
    if not isinstance(rating, int) or rating < 1 or rating > 5:
        return jsonify({'error': 'Rating must be an integer between 1 and 5.'}), 400

    # Update rating
    booking.rating = rating
    db.session.commit()

    # Debug: Print booking data after updating the rating
    print("Booking Data After Rating Update:", booking.to_dict())

    # Return the updated booking data
    return jsonify(booking.to_dict()), 200


@app.get('/api/average-rating')
def get_average_rating():
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload (if needed)

    print("Token Data:", {"user_id": user_id, "user_type": user_type})
    average_rating = db.session.query(db.func.avg(Booking.rating)).scalar() or 0
    return jsonify({'average_rating': round(average_rating, 2)}), 200

@app.get('/api/bookings')
def get_all_bookings():
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload (if needed)

    print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})



    # Determine the base queries based on user role
    if user_type == 'admin':
        booking_query = Booking.query
        engineering_query = EngineeringBooking.query
    else:
        booking_query = Booking.query.filter_by(user_id=user_id)
        engineering_query = EngineeringBooking.query.filter_by(user_id=user_id)

    # Retrieve optional query parameters
    status = request.args.get('status')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    location = request.args.get('location')
    event_type = request.args.get('event_type')
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')
    search = request.args.get('search')
    sort_by = request.args.get('sort_by', 'event_date')
    order = request.args.get('order', 'asc')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))

    # Filter by status if provided
    if status:
        booking_query = booking_query.filter(Booking.status.ilike(f"%{status}%"))
        engineering_query = engineering_query.filter(EngineeringBooking.status.ilike(f"%{status}%"))

    # Filter by date range if provided
    if start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%m/%d/%Y')
            end_date_obj = datetime.strptime(end_date, '%m/%d/%Y')
            if start_date_obj > end_date_obj:
                return jsonify({'error': 'Start date must be before end date.'}), 400

            booking_query = booking_query.filter(
                Booking.event_date >= start_date_obj,
                Booking.event_date <= end_date_obj
            )
            engineering_query = engineering_query.filter(
                EngineeringBooking.project_start_date >= start_date_obj,
                EngineeringBooking.project_end_date <= end_date_obj
            )
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use "MM/DD/YYYY".'}), 400

    # Filter by location if provided
    if location:
        booking_query = booking_query.filter(Booking.location.ilike(f"%{location}%"))
        engineering_query = engineering_query.filter(EngineeringBooking.project_description.ilike(f"%{location}%"))

    # Filter by event type
    if event_type:
        booking_query = booking_query.filter(Booking.event_type.ilike(f"%{event_type}%"))

    # Filter by price range
    if min_price and max_price:
        try:
            min_price = float(min_price)
            max_price = float(max_price)
            booking_query = booking_query.filter(Booking.price.between(min_price, max_price))
            engineering_query = engineering_query.filter(EngineeringBooking.price.between(min_price, max_price))
        except ValueError:
            return jsonify({'error': 'Price must be a valid number.'}), 400

    # Apply search filter
    if search:
        booking_query = booking_query.filter(
            Booking.event_name.ilike(f"%{search}%") |
            Booking.client_name.ilike(f"%{search}%")
        )
        engineering_query = engineering_query.filter(
            EngineeringBooking.project_name.ilike(f"%{search}%")
        )

    # Sorting
    if sort_by == 'event_date':
        sort_order = Booking.event_date.asc() if order == 'asc' else Booking.event_date.desc()
        booking_query = booking_query.order_by(sort_order)
    else:
        sort_order = Booking.price.asc() if order == 'asc' else Booking.price.desc()
        booking_query = booking_query.order_by(sort_order)

    # Sorting for engineering bookings
    if sort_by == 'event_date':
        sort_order = EngineeringBooking.project_start_date.asc() if order == 'asc' else EngineeringBooking.project_start_date.desc()
        engineering_query = engineering_query.order_by(sort_order)
    else:
        sort_order = EngineeringBooking.price.asc() if order == 'asc' else EngineeringBooking.price.desc()
        engineering_query = engineering_query.order_by(sort_order)

    # Pagination
    booking_results = booking_query.paginate(page=page, per_page=per_page, error_out=False)
    engineering_results = engineering_query.paginate(page=page, per_page=per_page, error_out=False)

    regular_bookings_data = [booking.to_dict() for booking in booking_results.items]
    engineering_bookings_data = [eng_booking.to_dict() for eng_booking in engineering_results.items]

    # Combine the results
    all_bookings = regular_bookings_data + engineering_bookings_data

    print(f"Total bookings fetched: {len(all_bookings)}")
    print(f"Filters applied: Status={status}, Location={location}, Event Type={event_type}, Price Range=({min_price}, {max_price}), Search={search}")
    print(f"Pagination: Page={page}, Per Page={per_page}, Total Pages={booking_results.pages + engineering_results.pages}")

    return jsonify({
        'bookings': all_bookings,
        'total_pages': max(booking_results.pages, engineering_results.pages),
        'current_page': page,
        'per_page': per_page,
        'total_results': booking_results.total + engineering_results.total
    }), 200


def can_edit_booking(booking):
    """
    Helper function to check if the current user can edit the booking.
    Only the booking creator or an admin can edit the booking.
    """
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload

    # Print user and booking info for debugging
    print("Checking edit permissions for user:", {"user_id": user_id, "user_type": user_type})
    print("Booking Info:", {"booking_user_id": booking.user_id})

    # Allow edit if the user is an admin or the creator of the booking
    if user_type == 'admin' or booking.user_id == user_id:
        print("Permission granted.")
        return True

    print("Permission denied.")
    return False


@app.patch('/api/bookings/<int:booking_id>')
@token_required
def update_booking(booking_id):
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload (if needed)

    print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})

    booking = Booking.query.get(booking_id)

    if not booking:
        return jsonify({'error': 'Booking not found.'}), 404

    # Check if the user is allowed to edit the booking
    if not can_edit_booking(booking):
        print("Permission denied for user:", {"user_id": user_id, "user_type": user_type})
        return jsonify({'error': 'Permission denied.'}), 403

    print("Booking Data Before Update:", booking.to_dict())

    # Get the update data from the request body
    data = request.get_json()

    # Update fields
    booking.booking_date = datetime.strptime(data.get('booking_date'), '%A, %B %d, %Y %I:%M %p') if data.get('booking_date') else booking.booking_date
    booking.client_name = data.get('client_name', booking.client_name)
    booking.client_email = data.get('client_email', booking.client_email)
    booking.client_phone = data.get('client_phone', booking.client_phone)
    booking.event_date = datetime.strptime(data.get('event_date'), '%A, %B %d, %Y %I:%M %p') if data.get('event_date') else booking.event_date
    booking.event_name = data.get('event_name', booking.event_name)
    booking.event_type = data.get('event_type', booking.event_type)
    booking.location = data.get('location', booking.location)
    booking.number_of_guests = data.get('number_of_guests', booking.number_of_guests)
    booking.price = round(float(data.get('price')), 2) if data.get('price') else booking.price
    booking.special_requests = data.get('special_requests', booking.special_requests)
    booking.payment_status = data.get('payment_status', booking.payment_status)

    if 'rating' in data:
        rating = data.get('rating')
        if not isinstance(rating, int) or rating < 1 or rating > 5:
            return jsonify({'error': 'Rating must be an integer between 1 and 5.'}), 400
        booking.rating = rating
    # Validate email format
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if booking.client_email and not re.match(email_regex, booking.client_email):
        return jsonify({'error': 'Invalid email format.'}), 400

    # Validate price
    if booking.price <= 0:
        return jsonify({'error': 'Price must be a positive number.'}), 400

    # Commit the changes to the database
    db.session.commit()
    print("Booking Data After Update:", booking.to_dict())

    return jsonify(booking.to_dict()), 200


@app.delete('/api/bookings/<int:booking_id>')
@token_required
def delete_booking(booking_id):
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload (if needed)

    print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})

    booking = Booking.query.get(booking_id)

    if not booking:
        return jsonify({'error': 'Booking not found.'}), 404

    # Check if the user is allowed to delete the booking
    if not can_edit_booking(booking):
        print("Permission denied for user:", {"user_id": user_id, "user_type": user_type})
        return jsonify({'error': 'Permission denied.'}), 403

    print("Deleting Booking:", booking.to_dict())

    # Delete the booking and commit the changes
    db.session.delete(booking)
    db.session.commit()

    return jsonify({'message': 'Booking deleted successfully.'}), 200


@app.get('/api/calendar-bookings')
def get_calendar_bookings():
    local_timezone = pytz.timezone("America/New_York")

    # Fetch all regular bookings with future event dates
    regular_bookings = Booking.query.filter(Booking.event_date >= datetime.now()).all()
    regular_bookings_data = [
        {
            "id": booking.id,
            "title": f"Booking: {booking.location}",
            "start": booking.event_date.astimezone(local_timezone).strftime('%A, %B %d, %Y'),
            "end": (booking.event_date + timedelta(hours=2)).astimezone(local_timezone).strftime('%A, %B %d, %Y'),
            "type": "regular"
        }
        for booking in regular_bookings
    ]

    # Fetch all engineering bookings with future project start dates
    engineering_bookings = EngineeringBooking.query.filter(EngineeringBooking.project_end_date >= datetime.now()).all()
    engineering_bookings_data = [
        {
            "id": eng_booking.id,
            "title": "Engineering Project",
            "start": eng_booking.project_start_date.astimezone(local_timezone).strftime('%A, %B %d, %Y'),
            "end": eng_booking.project_end_date.astimezone(local_timezone).strftime('%A, %B %d, %Y'),
            "type": "engineering"
        }
        for eng_booking in engineering_bookings
    ]

    # Combine the data and return it
    all_bookings = regular_bookings_data + engineering_bookings_data
    return jsonify(all_bookings), 200

# Example User and Event models (to give context, you would adapt based on your actual models)
# ----------------------------------------------------------------------------------------------------------USER-------------------------------------------------------------------#

class User(db.Model, SerializerMixin):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    user_type = db.Column(db.String(50), nullable=False)  # 'artist', 'attendee', etc.
    bookings = db.relationship("Booking", back_populates="user")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Creation time
    last_login = db.Column(db.DateTime)  # Updated on each login
    engineering_bookings = db.relationship("EngineeringBooking", back_populates="user")

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute.')
    def is_admin(self):
        return self.user_type == 'admin'
    

    def is_client(self):
        return self.user_type == 'client'
    @password.setter
    def password(self, plaintext_password):
        self.password_hash = bcrypt.generate_password_hash(plaintext_password).decode('utf-8')

    def verify_password(self, plaintext_password):
        return bcrypt.check_password_hash(self.password_hash, plaintext_password)

    def to_dict(self):
        local_timezone = pytz.timezone("America/New_York")  # You can use other timezones as needed

        formatted_created_at = self.created_at.strftime('%A, %B %d, %Y %I:%M %p') if self.created_at else None
        formatted_last_login = self.last_login.strftime('%A, %B %d, %Y %I:%M %p') if self.last_login else None
        return {
            'id': self.id,
            'username': self.username,
            'user_type': self.user_type,
            'created_at': formatted_created_at,
            'last_login': formatted_last_login
        }
def validate_password(password):
    """
    Validates the password against the defined criteria.
    Raises a 400 Bad Request error with an appropriate message if validation fails.
    """
    if not password:
        abort(400, description="Password is required.")

    if len(password) < 8:
        abort(400, description="Password must be at least 8 characters long.")

    if len(password) > 128:
        abort(400, description="Password must not exceed 128 characters.")

    if not re.search(r'[A-Z]', password):
        abort(400, description="Password must contain at least one uppercase letter.")

    if not re.search(r'[a-z]', password):
        abort(400, description="Password must contain at least one lowercase letter.")

    if not re.search(r'\d', password):
        abort(400, description="Password must contain at least one digit.")

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        abort(400, description="Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>).")

    
@app.post('/api/signup')
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user_type = data.get('user_type')

    # Validate required fields
    if not all([username, password, user_type]):
        return jsonify({'error': 'Username, password, and user type are required.'}), 400

    if user_type not in ["admin", "client"]:
        return jsonify({'error': 'User type must be either "admin" or "client".'}), 400

    # Check if the username is valid (optional improvement)
    if not re.match(r'^\w+$', username):
        return jsonify({'error': 'Username can only contain letters, digits, and underscores.'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists.'}), 400

    # Validate password
    try:
        validate_password(password)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    # Create new user
    new_user = User(username=username, user_type=user_type, last_login=datetime.utcnow())
    new_user.password = password

    db.session.add(new_user)
    db.session.commit()
    token = generate_token(new_user)

    # Generate JWT token
    print(f"User '{username}' signed up and is automatically signed in.")
    return jsonify({'message': 'Signup successful! You are now logged in.', 'token': token, 'user': new_user.to_dict()}), 201

@app.post('/api/signin')
def signin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    print('\n\n\n\n USERN NAME IS', username)
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.verify_password(password):
        # Update last login timestamp
        user.last_login = datetime.utcnow()
        db.session.commit()

        # Generate JWT token
        token = generate_token(user)
        print(f"User '{username}' signed in successfully.")
        return jsonify({'message': 'Sign-in successful!', 'token': token, 'user': user.to_dict()}), 200

    print(f"Failed sign-in attempt for username: {username}")
    return jsonify({'error': 'Invalid username or password.'}), 401

def is_admin_user():
    user_type = getattr(request, 'user_type', None)
    return user_type == 'admin'


@app.post('/api/signout')
@token_required
def signout():
    print("User signing out:", {"user_id": request.user_id, "username": request.username})
    return jsonify({'message': 'Sign-out successful! Please remove the token on the client side.'}), 200


@app.get('/api/admin-dashboard')
@token_required
def admin_dashboard():
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload

    print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})

    # Check if the user is an admin
    if not is_admin_user():
        print("Admin check failed. User is not an admin.")
        return jsonify({'error': 'Unauthorized access'}), 403

    print("Admin check passed. User is an admin.")

    # Aggregate booking statistics
    total_regular_bookings = Booking.query.count()
    total_engineering_bookings = EngineeringBooking.query.count()
    total_bookings = total_regular_bookings + total_engineering_bookings

    # Revenue summary
    total_revenue_regular = db.session.query(db.func.sum(Booking.price)).scalar() or 0
    total_revenue_engineering = db.session.query(db.func.sum(EngineeringBooking.price)).scalar() or 0
    total_revenue = total_revenue_regular + total_revenue_engineering

    # Booking status summary
    status_summary = {
        "pending": Booking.query.filter_by(status="pending").count(),
        "confirmed": Booking.query.filter_by(status="confirmed").count(),
        "completed": Booking.query.filter_by(status="completed").count(),
        "canceled": Booking.query.filter_by(status="canceled").count(),
    }

    # Payment status summary
    payment_summary = {
        "unpaid": Booking.query.filter_by(payment_status="unpaid").count() + EngineeringBooking.query.filter_by(payment_status="unpaid").count(),
        "paid": Booking.query.filter_by(payment_status="paid").count() + EngineeringBooking.query.filter_by(payment_status="paid").count(),
    }

    # User statistics
    total_users = User.query.count()
    active_clients = User.query.filter(User.last_login >= datetime.now() - timedelta(days=30)).count()

    # Recent bookings (limit to 5)
    recent_bookings = Booking.query.order_by(Booking.event_date.desc()).limit(5).all()
    recent_engineering_bookings = EngineeringBooking.query.order_by(EngineeringBooking.project_start_date.desc()).limit(5).all()

    recent_bookings_data = [booking.to_dict() for booking in recent_bookings]
    recent_engineering_bookings_data = [eng_booking.to_dict() for eng_booking in recent_engineering_bookings]

    # Response data
    response_data = {
        "message": "Admin dashboard",
        "overview": {
            "total_bookings": total_bookings,
            "total_revenue": total_revenue,
            "total_users": total_users,
            "active_clients": active_clients,
            "status_summary": status_summary,
            "payment_summary": payment_summary,
        },
        "recent_bookings": recent_bookings_data,
        "recent_engineering_bookings": recent_engineering_bookings_data,
    }

    return jsonify(response_data), 200


@app.get('/api/client-dashboard')
@token_required
def client_dashboard():
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload

    print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})

    # Ensure the user is logged in and is a client
    if user_type != 'client':
        print("Unauthorized access. User is not a client.")
        return jsonify({'error': 'Unauthorized access. Only clients can access this dashboard.'}), 403

    # Fetch all regular bookings made by the user
    user_bookings = Booking.query.filter_by(user_id=user_id).all()
    bookings_data = [booking.to_dict() for booking in user_bookings]
    print("User Bookings:", bookings_data)

    # Fetch all engineering bookings made by the user
    user_engineering_bookings = EngineeringBooking.query.filter_by(user_id=user_id).all()
    engineering_bookings_data = [eng_booking.to_dict() for eng_booking in user_engineering_bookings]
    print("User Engineering Bookings:", engineering_bookings_data)

    # Calculate Overview Data
    total_bookings = len(bookings_data) + len(engineering_bookings_data)
    print("Total Bookings:", total_bookings)

    upcoming_bookings = sum(1 for booking in bookings_data if datetime.strptime(booking['event_date'], '%A, %B %d, %Y %I:%M %p') > datetime.now())
    print("Upcoming Bookings:", upcoming_bookings)

    total_spent = sum(booking['price'] for booking in bookings_data) + sum(eng_booking['price'] for eng_booking in engineering_bookings_data)
    print("Total Spent:", total_spent)


    # Most Frequent Location (for regular bookings)
    locations = [booking['location'] for booking in bookings_data]
    most_frequent_location = max(set(locations), key=locations.count) if locations else "N/A"
    print("Most Frequent Location:", most_frequent_location)

    # Average Number of Guests
    guests = [booking['number_of_guests'] for booking in bookings_data if booking['number_of_guests'] is not None]
    avg_guests = round(sum(guests) / len(guests), 2) if guests else 0
    print("Average Number of Guests:", avg_guests)

    # Booking Status Summary
    status_summary = {
        'pending': sum(1 for booking in bookings_data if booking['status'] == 'pending'),
        'confirmed': sum(1 for booking in bookings_data if booking['status'] == 'confirmed'),
        'completed': sum(1 for booking in bookings_data if booking['status'] == 'completed'),
    }
    print("Booking Status Summary:", status_summary)


    # Prepare the response data
    response_data = {
        "message": "Client dashboard",
        "overview": {
            "total_bookings": total_bookings,
            "upcoming_bookings": upcoming_bookings,
            "total_spent": total_spent,
            "most_frequent_location": most_frequent_location,
            "average_guests": avg_guests,
            "status_summary": status_summary
        },
        "regular_bookings": bookings_data,
        "engineering_bookings": engineering_bookings_data,
    }
    print("Client Dashboard Response Data:", response_data)
    print("Session Data:", {"user_id": user_id, "username": username, "user_type": user_type})

    return jsonify(response_data), 200

@app.get('/api/users/<int:user_id>')
@token_required
def get_user(user_id):
    user_type = request.user_type  # Extracted from JWT token payload
    user_id_from_token = request.user_id  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload (if needed)

    print("Token Data:", {"user_id": user_id_from_token, "username": username, "user_type": user_type})

    # Check if the user is an admin
    if not is_admin_user():
        print("Access denied. User is not an admin.")
        abort(403, description="Access denied.")

    # Retrieve the user by ID
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(user.to_dict()), 200

@app.patch('/api/users/<int:user_id>')
@token_required
def edit_user(user_id):
    user_id_from_token = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload

    print("Token Data:", {"user_id": user_id_from_token, "username": username, "user_type": user_type})

    # Check if the user making the request is an admin
    if not is_admin_user():
        print("Access denied. User is not an admin.")
        abort(403, description="Access denied: User is not an admin.")

    # Retrieve the user to be edited
    user = User.query.get(user_id)
    if not user:
        print("User not found with ID:", user_id)
        return jsonify({"error": "User not found"}), 404
    print("Admin check passed. Proceeding with user edit.")

    print("User to be edited:", user.to_dict())

    # Get the data from the request body
    data = request.get_json()
    new_username = data.get("username", user.username)
    new_user_type = data.get("user_type", user.user_type)

    # Update the user's information
    user.username = new_username
    user.user_type = new_user_type

    # Commit changes to the database
    try:
        db.session.commit()
        print("User updated successfully:", user.to_dict())
    except Exception as e:
        print("Error updating user:", str(e))
        return jsonify({"error": "Failed to update user data."}), 500

    # Return the updated user data
    return jsonify({
        "message": "User updated successfully.",
        "user": user.to_dict()
    }), 200



@app.delete('/api/users/<int:user_id>')
@token_required
def delete_user(user_id):
    user_id_from_token = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload

    print("Token Data:", {"user_id": user_id_from_token, "username": username, "user_type": user_type})

    # Check if the user is an admin
    if not is_admin_user():
        print("Admin check failed. User is not an admin.")
        abort(403, description="Access denied: User is not an admin.")

    # Prevent self-deletion
    if user_id_from_token == user_id:
        print("Admin attempted to delete their own account.")
        return jsonify({"error": "You cannot delete your own account."}), 400

    # Retrieve the user to be deleted
    user = User.query.get(user_id)
    if not user:
        print("User not found with ID:", user_id)
        return jsonify({"error": "User not found"}), 404

    # Debugging: Print user info before deletion
    print("User to be deleted:", user.to_dict())

    # Clean up associated data (if needed)
    try:
        # Delete associated bookings
        Booking.query.filter_by(user_id=user_id).delete()
        EngineeringBooking.query.filter_by(user_id=user_id).delete()

        # Delete the user
        db.session.delete(user)
        db.session.commit()
        print("User deleted successfully:", user_id)
    except Exception as e:
        print("Error during deletion:", str(e))
        return jsonify({"error": "Failed to delete user."}), 500

    return jsonify({"message": "User deleted successfully"}), 200




#---------------------------------------ENGINEERING----------------------------#

class EngineeringBooking(db.Model, SerializerMixin):
    __tablename__ = "engineering_bookings"
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    booking_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    project_name = db.Column(db.String(100), nullable=True)  # New field
    service_type = db.Column(db.String(50), nullable=False, default="New Website")  # New field
    project_start_date = db.Column(db.DateTime, nullable=False)  # Date when the project starts
    project_end_date = db.Column(db.DateTime, nullable=False)  # Date when the project is expected to end
    project_description = db.Column(db.Text, nullable=False)  # Detailed description of the project
    status = db.Column(db.String(20), nullable=False, default="pending")  # e.g., pending, completed, canceled
    price = db.Column(db.Float, nullable=False)  # Price for the engineering project
    payment_status = db.Column(db.String(20), nullable=False, default="unpaid")  # e.g., unpaid, paid
    special_requests = db.Column(db.Text, nullable=True)  # Any additional requests for the booking
    project_manager = db.Column(db.String(100), nullable=True)  # Name of the project manager
    contact_email = db.Column(db.String(100), nullable=True)    # Email of the contact person
    contact_phone = db.Column(db.String(20), nullable=True)     # Phone number of the contact person
    rating = db.Column(db.Integer, nullable=True)  # New field for rating

    # Relationship with User
    user = db.relationship("User", back_populates="engineering_bookings")

    def to_dict(self):
        local_timezone = pytz.timezone("America/New_York")  # Use your timezone here
        booking_date_local = self.booking_date.astimezone(local_timezone) if self.booking_date else None
        project_start_date_local = self.project_start_date.astimezone(local_timezone) if self.project_start_date else None
        project_end_date_local = self.project_end_date.astimezone(local_timezone) if self.project_end_date else None
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username,  # Adding username for verification
            "booking_date": booking_date_local.strftime('%A, %B %d, %Y %I:%M %p') if booking_date_local else None,
            "project_name": self.project_name,
            "service_type": self.service_type,
            "project_start_date": project_start_date_local.strftime('%A, %B %d, %Y') if project_start_date_local else None,
            "project_end_date": project_end_date_local.strftime('%A, %B %d, %Y') if project_end_date_local else None,
            "project_description": self.project_description,
            "status": self.status,
            "price": self.price,
            "payment_status": self.payment_status,
            "special_requests": self.special_requests,
            "project_manager": self.project_manager,       # New field
            "contact_email": self.contact_email,           # New field
            "contact_phone": self.contact_phone,            # New field
            "rating": self.rating  # Include rating

    }
    
    @app.post('/api/engineeringbookings')
    @token_required
    def create_engineering_booking():
        user_id = request.user_id  # Extracted from JWT token payload
        username = request.username  # Extracted from JWT token payload
        user_type = request.user_type  # Extracted from JWT token payload

    # Print token data for debugging
        print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})
        if not user_id:
            print("User not logged in. Returning 401 Unauthorized.")

            return jsonify({'error': 'Unauthorized. Please log in.'}), 401
    
        data = request.get_json()
        print("Request Data:", data)
        project_name = data.get('project_name')
        service_type = data.get('service_type', 'New Website')
        project_start_date = data.get('project_start_date')
        project_end_date = data.get('project_end_date')
        project_description = data.get('project_description')
        price = data.get('price')
        special_requests = data.get('special_requests')
        project_manager = data.get('project_manager')
        contact_email = data.get('contact_email')
        contact_phone = data.get('contact_phone')

        # Validation: Required fields
        if not all([project_start_date, project_end_date, project_description, price]):
            return jsonify({'error': 'Project start date, end date, description, and price are required.'}), 400
        print("Missing required fields. Returning 400 Bad Request.")

        # Validation: Project description not empty and character limit
        if not project_description or len(project_description) > 1000:
            return jsonify({'error': 'Project description must not be empty and cannot exceed 1000 characters.'}), 400
        # Validation: Price
        try:
            price = round(float(price), 2)
            if price <= 0:
                raise ValueError
        except ValueError:
            return jsonify({'error': 'Price must be a positive number.'}), 400
        try:
            project_start_date_obj = datetime.strptime(project_start_date, '%A, %B %d, %Y')
            project_end_date_obj = datetime.strptime(project_end_date, '%A, %B %d, %Y')
            if project_start_date_obj <= datetime.now() or project_end_date_obj <= project_start_date_obj:
                return jsonify({'error': 'Invalid project dates. Start date must be in the future and before the end date.'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use "Thursday, January 6, 2025".'}), 400

        new_engineering_booking = EngineeringBooking(
            user_id=user_id,
            project_name=project_name,
            service_type=service_type,
            project_start_date=project_start_date_obj,
            project_end_date=project_end_date_obj,
            project_description=project_description,
            price=price,
            special_requests=special_requests,
            project_manager=project_manager,
            contact_email=contact_email,
            contact_phone=contact_phone,
        )

        db.session.add(new_engineering_booking)
        db.session.commit()
        print("New Engineering Booking Created:", new_engineering_booking.to_dict())

        return jsonify(new_engineering_booking.to_dict()), 201

    @app.patch('/api/engineeringbookings/<int:booking_id>')
    @token_required
    def update_engineering_booking(booking_id):
        user_id = request.user_id  # Extracted from JWT token payload
        user_type = request.user_type  # Extracted from JWT token payload
        username = request.username  # Extracted from JWT token payload
        engineering_booking = EngineeringBooking.query.get(booking_id)

        print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})

        if not engineering_booking:
            print("Engineering booking not found.")
            return jsonify({'error': 'Engineering booking not found.'}), 404

        # Check if the user is the creator or an admin
        if not can_edit_booking(engineering_booking):
            print("Permission denied for user:", {"user_id": user_id, "user_type": user_type})
            return jsonify({'error': 'Permission denied.'}), 403
        print("Engineering Booking Before Update:", engineering_booking.to_dict())

        data = request.get_json()
        if 'project_start_date' in data:
            project_start_date = datetime.strptime(data['project_start_date'], '%A, %B %d, %Y')
            engineering_booking.project_start_date = project_start_date
        if 'project_end_date' in data:
            project_end_date = datetime.strptime(data['project_end_date'], '%A, %B %d, %Y')
            engineering_booking.project_end_date = project_end_date
        if 'project_description' in data:
            engineering_booking.project_description = data['project_description']
        if 'price' in data:
            price = round(float(data['price']), 2)
            engineering_booking.price = price
        if 'special_requests' in data:
            engineering_booking.special_requests = data['special_requests']
        if 'project_name' in data:
            engineering_booking.project_name = data['project_name']
        if 'service_type' in data:
            if data['service_type'] not in ['New Website', 'Consultation']:
                return jsonify({'error': 'Invalid service type. Choose "New Website" or "Consultation".'}), 400
            engineering_booking.service_type = data['service_type']
            # Update new fields: project_manager, contact_email, and contact_phone
        if 'project_manager' in data:
            engineering_booking.project_manager = data['project_manager']

        if 'contact_email' in data:
            contact_email = data['contact_email']
            if '@' not in contact_email:
                return jsonify({'error': 'Invalid contact email format.'}), 400
            engineering_booking.contact_email = contact_email

        if 'contact_phone' in data:
            contact_phone = data['contact_phone']
            if not contact_phone.isdigit():
                return jsonify({'error': 'Contact phone must contain only digits.'}), 400
            engineering_booking.contact_phone = contact_phone

        if 'rating' in data:
            rating = data.get('rating')
            if not isinstance(rating, int) or rating < 1 or rating > 5:
                return jsonify({'error': 'Rating must be an integer between 1 and 5.'}), 400
            engineering_booking.rating = rating

        db.session.commit()
        print("Engineering Booking After Update:", engineering_booking.to_dict())

        return jsonify(engineering_booking.to_dict()), 200

@app.delete('/api/engineeringbookings/<int:booking_id>')
@token_required
def delete_engineering_booking(booking_id):
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload

    print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})

    engineering_booking = EngineeringBooking.query.get(booking_id)

    if not engineering_booking:
        print("Engineering booking not found.")
        return jsonify({'error': 'Engineering booking not found.'}), 404

    # Check if the user is the creator or an admin
    if not can_edit_booking(engineering_booking):
        print("Permission denied for user:", {"user_id": user_id, "user_type": user_type})
        return jsonify({'error': 'Permission denied.'}), 403

    print("Engineering Booking to be Deleted:", engineering_booking.to_dict())

    # Delete the booking
    db.session.delete(engineering_booking)
    db.session.commit()
    print("Engineering booking deleted successfully:", {"booking_id": booking_id})

    return jsonify({'message': 'Engineering booking deleted successfully.'}), 200

    
@app.get('/api/admin/users')
@token_required
def get_all_users():
    user_id = request.user_id  # Extracted from JWT token payload
    user_type = request.user_type  # Extracted from JWT token payload
    username = request.username  # Extracted from JWT token payload

    print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})

    # Check if the user is an admin
    if not is_admin_user():
        print("Unauthorized access. User is not an admin.")
        return jsonify({'error': 'Unauthorized access'}), 403
    print("Admin check passed. User is an admin.")

    # Retrieve optional query parameters
    search = request.args.get('search', '').strip()
    user_type_filter = request.args.get('user_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Base query
    query = User.query

    # Apply search filter (username contains search term)
    if search:
        query = query.filter(User.username.ilike(f"%{search}%"))

    # Apply user type filter
    if user_type_filter:
        query = query.filter(User.user_type.ilike(user_type_filter))

    # Apply date range filter (creation date)
    if start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%m/%d/%Y')
            end_date_obj = datetime.strptime(end_date, '%m/%d/%Y')
            if start_date_obj > end_date_obj:
                return jsonify({'error': 'Start date must be before end date.'}), 400
            query = query.filter(User.created_at >= start_date_obj, User.created_at <= end_date_obj)
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use "MM/DD/YYYY".'}), 400

    # Execute the query
    users = query.all()
    print(f"Total users fetched: {len(users)}")

    # Convert each user to a dictionary including creation date and last login
    users_data = [
        {
            'id': user.id,
            'username': user.username,
            'user_type': user.user_type,
            'created_at': user.created_at.strftime('%A, %B %d, %Y %I:%M %p') if user.created_at else None,
            'last_login': user.last_login.strftime('%A, %B %d, %Y %I:%M %p') if user.last_login else None
        }
        for user in users
    ]
    print("Users Data Prepared for Response:", users_data)

    return jsonify(users_data), 200


#-----------------------------------------DASHBOARD---------------------#
@app.get('/api/check-session')
@token_required
def check_session():
    user_id = request.user_id
    username = request.username
    user_type = request.user_type

    print("Token Data:", {"user_id": user_id, "username": username, "user_type": user_type})

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    return jsonify({'user': user.to_dict()}), 200

if __name__ == "__main__":
    app.run(debug=True)
