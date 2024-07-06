from flask import request, session, make_response, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
import jwt
import bcrypt
import stripe
import logging

from config import app, db, api
from models import User, Library

stripe.api_key = app.config['STRIPE_API_KEY']

print("Hello", app.config['DOMAIN_URL'])
   
class Checkout(Resource):
    def post(self):
        if request.method == 'OPTIONS':
            headers = {
                'Access-Control-Allow-Origin': 'http://localhost:3001',
                'Access-Control-Allow-Methods': 'POST',
                'Access-Control-Allow-Headers': 'Content-Type',
            }
            return ('', 204, headers)
        elif request.method == 'POST':
            try:
                data = request.get_json()
                cartItems = data.get('cartItems', [])

                line_items = []
                for item in cartItems:
                    line_items.append({
                        'price': item['priceID'],  # Use 'priceID' as specified in your React component
                        'quantity': 1  # Adjust quantity as needed
                    })

                checkout_session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=line_items,
                    mode='payment',
                    success_url=app.config['DOMAIN_URL'] + '/success',
                    cancel_url=app.config['DOMAIN_URL'] + '/canceled'
                )

                # Return success response with checkout data
                return jsonify({
                    'sessionId': checkout_session['id'],
                    'success_url': app.config['DOMAIN_URL'] + '/success',
                    'cancel_url': app.config['DOMAIN_URL'] + '/canceled'
                })

            except stripe.error.StripeError as e:
                # Log specific Stripe errors
                app.logger.error(f"Stripe Error: {str(e)}")
                return jsonify(error=str(e)), 400  # Return user-friendly error message

            except Exception as e:
                # Log generic exceptions
                app.logger.error(f"Unexpected Error: {str(e)}")
                return jsonify(error="Internal Server Error"), 500  # Generic error message

        # Handle other methods if necessary
        return jsonify(error='Method not allowed'), 405

api.add_resource(Checkout, '/create-checkout-session')

class Products(Resource):
    def get(self):

        try:
            products = stripe.Product.list(expand=['data.default_price'])

            products_data = []
            for product in products.data:
                product_dict = {
                    'id': product.id,
                    'name': product.name,
                    'description': product.description,
                    'images': product.images,
                    'default_price': product.default_price,
                    'metadata': product.metadata
                }
                products_data.append(product_dict)

            return jsonify(products_data)

        except stripe.error.StripeError as e:
            return jsonify(error=str(e)), 500

api.add_resource(Products, '/products')

class ProductByID(Resource):
    def get(self, id):
        try:
            product = stripe.Product.retrieve(id, expand=['default_price'])
            
            product_data = {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'images': product.images,
                'default_price': product.default_price,
                'metadata': product.metadata
            }
            
            return jsonify(product_data)
        
        except stripe.error.InvalidRequestError as e:
            return jsonify({
                'error': {
                    'code': e.code,
                    'message': e.user_message or str(e),
                }
            }), 404
        except stripe.error.StripeError as e:
            return jsonify({
                'error': {
                    'message': str(e),
                }
            }), 500

# Register ProductByID resource with endpoint /products/<id>
api.add_resource(ProductByID, '/products/<id>')

class ProductLibrary(Resource):
    def post(self):
        try:
            data = request.get_json()
            cart_items = data.get('cartItems', [])

            products_added = []

            for item in cart_items:
                new_product = Library(
                    product_id=item['product_id'],
                    product_name=item['product_name'],
                    product_description=item.get('product_description', ''),
                    product_author=item.get('product_author', ''),
                    product_genre=item.get('product_genre', ''),
                    product_logo=item.get('product_logo', ''),
                    product_cover=item.get('product_cover', ''),
                    product_images=item.get('product_images', ''),
                    user_id=item['user_id']
                )

                db.session.add(new_product)
                products_added.append(new_product)

            db.session.commit()

            # Return the list of new products added as JSON response
            return make_response(jsonify([product.to_dict() for product in products_added]), 201)

        except Exception as e:
            print(e)
            db.session.rollback()
            return make_response(jsonify({'error': 'Internal Server Error', 'message': str(e)}), 500)

api.add_resource(ProductLibrary, '/library')

class Login(Resource):
    def post(self):
        try:
            data = request.get_json()
            if not data or 'email' not in data or 'password' not in data:
                return {'error': 'Bad Request', 'message': 'Email and password are required'}, 400

            email = data['email']
            password = data['password']

            check_user = User.query.filter(User.email == email).first()

            if not check_user or not check_user.authenticate(password):
                return {'error': 'Unauthorized', 'message': 'Invalid email or password'}, 401

            access_token, refresh_token = self.generate_tokens(check_user.id)

            return make_response(jsonify({
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': check_user.to_dict(rules=('libraries', '-_password_hash'))
            }), 200)

        except Exception as e:
            app.logger.error(f"Error during login: {e}")
            return {'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}, 500

    def generate_tokens(self, user_id):
        access_payload = {
            'sub': user_id,  # Set user_id as the subject
            'exp': datetime.utcnow() + timedelta(hours=48)  # Access token expiration time (adjust as needed)
        }
        refresh_payload = {
            'sub': user_id,  # Set user_id as the subject
            'exp': datetime.utcnow() + timedelta(days=30)  # Refresh token expiration time (adjust as needed)
        }
        access_token = jwt.encode(access_payload, app.config['SECRET_KEY'], algorithm='HS256')
        refresh_token = jwt.encode(refresh_payload, app.config['SECRET_KEY'], algorithm='HS256')

        return access_token, refresh_token

api.add_resource(Login, '/login')

class Logout(Resource):
    # Logs a user out
    def delete(self):
        session['user_id'] = None 
        response = make_response('',204)
        return response
    
api.add_resource(Logout, '/logout')

class Register(Resource):
    # Registers a new user
    def post(self):
        data = request.get_json()

        # Validate required fields
        required_fields = ['fname', 'lname', 'email', 'phone_number', 'street_address', 'city', 'state', 'postal_code', '_password_hash']
        for field in required_fields:
            if field not in data:
                return make_response({'error': f'Missing required field: {field}'}, 400)

        hashed_password = bcrypt.hashpw(data['_password_hash'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        new_user = User(
            fname=data['fname'],
            lname=data['lname'],
            email=data['email'],
            phone_number=data['phone_number'],
            street_address=data['street_address'],
            city=data['city'],
            state=data['state'],
            postal_code=data['postal_code'],
            _password_hash=hashed_password  # Store hashed password in the database
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            return make_response({
                'message': 'User registered successfully',
                'user': new_user.to_dict()
            }, 200)
        
        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f"Error during registration: {e}")
            return make_response({'error': 'Duplicate email or other integrity error'}, 409)  # Conflict
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during registration: {e}")
            return make_response({'error': 'Internal Server Error'}, 500)

api.add_resource(Register, '/register')

if __name__ == '__main__':
    app.run(port=5000, host="0.0.0.0", debug=True)
