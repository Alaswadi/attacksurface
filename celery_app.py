#!/usr/bin/env python3
"""
Celery worker entry point for Attack Surface Discovery SaaS
This file is used by the Celery worker to initialize the Celery app
"""

import os
from app import create_app

# Create Flask app
flask_app = create_app()

# Get the Celery instance from the Flask app
celery = flask_app.celery

# Import tasks to register them with Celery
from tasks import *

if __name__ == '__main__':
    celery.start()
