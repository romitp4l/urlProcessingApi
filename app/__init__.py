from flask import Flask

def create_app():
    """Factory function to create the Flask app."""
    app = Flask(__name__)

    # Import and register routes
    from app.routes import api_blueprint
    app.register_blueprint(api_blueprint)

    return app
