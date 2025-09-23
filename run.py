#!/usr/bin/env python3
"""
Entry point for running CloudFinderWeb.
"""

import argparse
import os
import sys

from cloudfinderweb import create_app

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Run CloudFinderWeb server')

    parser.add_argument('--host', default='127.0.0.1',
                        help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5050,
                        help='Port to bind to (default: 5050)')
    parser.add_argument('--debug', action='store_true',
                        help='Run in debug mode')

    return parser.parse_args()

def main():
    """Main entry point."""
    args = parse_args()

    # Configure environment based on arguments
    if args.debug:
        os.environ['FLASK_ENV'] = 'development'
    else:
        os.environ['FLASK_ENV'] = 'production'

    # Create and run the app
    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    sys.exit(main())