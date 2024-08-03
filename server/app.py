#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def login_check():
    ok_endpoints = ['signup', 'login', 'check_session']
    if not session.get('user_id') and request.endpoint not in ok_endpoints:
        return {}, 401

class Signup(Resource):
    def post(self):
        raw_json = request.get_json()
        user = User(
            username = raw_json.get('username'),
            image_url = raw_json.get('image_url'),
            bio = raw_json.get('bio')
        )
        # I don't fully understand the difference between raw_json['thing'] and raw_json.get('thing') so review that later.
        user.password_hash = raw_json['password']
        
        try:
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(), 201

        except:
            return {'error': 'Could not process request.'}, 422

class CheckSession(Resource):
    
    def get(self):
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        return {}, 401

class Login(Resource):
    def post(self):
        raw_json = request.get_json()
        username = raw_json.get('username')
        user = User.query.filter(User.username == username).first()
        password = raw_json.get('password')

        if user:
            if user.authenticate(password):
                session['user_id'] = user.id
                return user.to_dict(), 200
        return {}, 401

class Logout(Resource):
    def delete(self):
        if session['user_id']:
            session['user_id'] = None
            return {}, 204
        else:
            return {}, 401

class RecipeIndex(Resource):
    def get(self):
        user = User.query.filter(User.id == session['user_id']).first()
        return [recipe.to_dict() for recipe in user.recipes], 200
    
    def post(self):
        # user = User.query.filter(User.id == session['user_id']).first()
        # if user:
            raw_json = request.get_json()
            try:
                recipe = Recipe(
                    title = raw_json.get('title'),
                    instructions = raw_json.get('instructions'),
                    minutes_to_complete = raw_json.get('minutes_to_complete'),
                    # user_id = user.id
                    user_id = session['user_id']
                )
                db.session.add(recipe)
                db.session.commit()
                return recipe.to_dict(), 201
            except:
                return {}, 422
    # If user is unnecessary because will already not be accessible if the user isn't logged in.

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)