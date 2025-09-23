"""
Web routes for CloudFinderWeb.
"""

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, current_app
import asyncio

from ..utils.ip_utils import is_valid_ip
from ..providers import provider_registry

# Create blueprint
web = Blueprint('web', __name__)


@web.route('/', methods=['GET'])
def index():
    """Render the main page."""
    return render_template('page.html')


@web.route('/submission', methods=['POST'])
async def submission():
    """Handle form submission from the web UI."""
    try:
        # Get form data
        data = request.form
        ip_address = data.get('ip', '')
        update_lists = data.get('updatelists') == 'yes'

        # First, handle list updates if requested
        if update_lists:
            try:
                print(f"Starting update of all provider lists...")
                results = await provider_registry.update_all()
                print(f"Update results: {results}")
            except Exception as e:
                import traceback
                print(f"Error updating providers: {str(e)}")
                print(traceback.format_exc())
                return jsonify({'error': f'Failed to update IP lists: {str(e)}'}), 500

        # Then, handle IP lookup if provided
        if ip_address and is_valid_ip(ip_address):
            print(f"Looking up IP: {ip_address}")
            results = provider_registry.lookup_ip(ip_address)
            print(f"Lookup results: {results}")
            return jsonify(results)
        else:
            if ip_address:
                print(f"Invalid IP address format: {ip_address}")
            return jsonify({})

    except Exception as e:
        import traceback
        print(f"Error in submission: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500