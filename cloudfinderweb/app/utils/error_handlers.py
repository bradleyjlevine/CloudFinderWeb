"""
Error handling utilities for CloudFinderWeb.
"""

from flask import Blueprint, jsonify, render_template, current_app, request


def register_error_handlers(app):
    """
    Register error handlers with the Flask application.

    Args:
        app: Flask application instance
    """
    @app.errorhandler(400)
    def bad_request(error):
        """Handle 400 Bad Request errors."""
        if request.path.startswith('/api'):
            return jsonify({
                'error': 'Bad Request',
                'message': str(error) or 'Invalid request parameters'
            }), 400
        return render_template('error.html',
                               error_code=400,
                               error_message='Bad Request: The server could not understand your request.'), 400

    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found errors."""
        if request.path.startswith('/api'):
            return jsonify({
                'error': 'Not Found',
                'message': 'The requested resource was not found on this server'
            }), 404
        return render_template('error.html',
                               error_code=404,
                               error_message='Not Found: The requested resource does not exist.'), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        """Handle 405 Method Not Allowed errors."""
        if request.path.startswith('/api'):
            return jsonify({
                'error': 'Method Not Allowed',
                'message': f'The {request.method} method is not allowed for this endpoint'
            }), 405
        return render_template('error.html',
                               error_code=405,
                               error_message='Method Not Allowed: The request method is not supported.'), 405

    @app.errorhandler(429)
    def too_many_requests(error):
        """Handle 429 Too Many Requests errors."""
        if request.path.startswith('/api'):
            return jsonify({
                'error': 'Too Many Requests',
                'message': 'You have sent too many requests in a short period of time'
            }), 429
        return render_template('error.html',
                               error_code=429,
                               error_message='Too Many Requests: Please try again later.'), 429

    @app.errorhandler(500)
    def internal_server_error(error):
        """Handle 500 Internal Server Error."""
        if request.path.startswith('/api'):
            return jsonify({
                'error': 'Internal Server Error',
                'message': 'An unexpected error occurred on the server'
            }), 500
        return render_template('error.html',
                               error_code=500,
                               error_message='Internal Server Error: Something went wrong on our end.'), 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        """Handle any uncaught exceptions."""
        current_app.logger.error(f'Unhandled exception: {str(error)}')

        if request.path.startswith('/api'):
            return jsonify({
                'error': 'Internal Server Error',
                'message': 'An unexpected error occurred on the server'
            }), 500
        return render_template('error.html',
                               error_code=500,
                               error_message='Internal Server Error: Something went wrong on our end.'), 500