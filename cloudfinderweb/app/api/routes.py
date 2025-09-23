"""
API routes for CloudFinderWeb.
"""

from flask import Blueprint, request, jsonify, current_app
import asyncio
from werkzeug.exceptions import BadRequest

from ..utils.ip_utils import is_valid_ip
from ..providers import provider_registry

# Create blueprint
api = Blueprint('api', __name__)


@api.route('/lookup', methods=['POST'])
def lookup_ip():
    """
    Look up an IP address across all cloud providers.

    Request parameters:
        ip: The IP address to look up

    Returns:
        JSON object with lookup results
    """
    data = request.get_json() or {}

    # Get IP from JSON body or form data
    ip_address = data.get('ip') if data else request.form.get('ip')

    if not ip_address:
        return jsonify({
            'error': 'Missing IP address parameter'
        }), 400

    if not is_valid_ip(ip_address):
        return jsonify({
            'error': 'Invalid IP address format'
        }), 400

    # Look up the IP address
    results = provider_registry.lookup_ip(ip_address)

    if not results:
        return jsonify({
            'ip': ip_address,
            'found': False,
            'providers': {}
        })

    return jsonify({
        'ip': ip_address,
        'found': True,
        'providers': results
    })


@api.route('/update', methods=['POST'])
async def update_providers():
    """
    Update IP ranges for all providers.

    Returns:
        JSON object with update results
    """
    try:
        # Use asyncio to run the update
        update_results = await provider_registry.update_all()

        return jsonify({
            'success': True,
            'results': update_results
        })
    except Exception as e:
        current_app.logger.error(f"Error updating providers: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@api.route('/providers', methods=['GET'])
def list_providers():
    """
    List all available cloud providers.

    Returns:
        JSON object with provider details
    """
    providers = []

    for provider in provider_registry.get_all_providers():
        providers.append({
            'id': provider.provider_id,
            'name': provider.display_name,
            'range_count': provider.range_count()
        })

    return jsonify({
        'providers': providers
    })