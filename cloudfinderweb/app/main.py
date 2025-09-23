"""
Main application factory module.
"""

import os
from flask import Flask, send_from_directory, current_app

from .api import api
from .web import web
from .utils.error_handlers import register_error_handlers
from ..config.config import active_config, CLOUDS_DIR


def create_app(config_class=None):
    """
    Create and configure the Flask application.

    Args:
        config_class: Configuration class to use (optional)

    Returns:
        Configured Flask application
    """
    # Create app
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')

    # Load configuration
    if config_class:
        app.config.from_object(config_class)
    else:
        app.config.from_object(active_config)

    # Ensure clouds directory exists
    os.makedirs(CLOUDS_DIR, exist_ok=True)

    # Register blueprints
    app.register_blueprint(api, url_prefix='/api')
    app.register_blueprint(web)

    # Register context processors
    @app.context_processor
    def inject_version():
        from .. import __version__
        return {'version': __version__}

    # Register static file routes
    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(app.static_folder, 'favicon.ico')

    @app.route('/site.webmanifest')
    def site_webmanifest():
        return send_from_directory(app.static_folder, 'site.webmanifest')

    @app.route('/apple-touch-icon.png')
    def apple_icon():
        return send_from_directory(app.static_folder, 'apple-touch-icon.png')

    @app.route('/android-chrome-192x192.png')
    def chrome_icon_192():
        return send_from_directory(app.static_folder, 'android-chrome-192x192.png')

    @app.route('/android-chrome-512x512.png')
    def chrome_icon_512():
        return send_from_directory(app.static_folder, 'android-chrome-512x512.png')

    @app.route('/favicon-16x16.png')
    def favicon_16():
        return send_from_directory(app.static_folder, 'favicon-16x16.png')

    @app.route('/favicon-32x32.png')
    def favicon_32():
        return send_from_directory(app.static_folder, 'favicon-32x32.png')

    # Register error handlers
    register_error_handlers(app)

    return app