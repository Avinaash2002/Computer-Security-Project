"""
PythonAnywhere WSGI Configuration File
=======================================
DO NOT upload this file directly. Instead, COPY its contents into
PythonAnywhere's built-in WSGI editor.

Steps:
  1. Go to Web tab -> click on WSGI configuration file link
  2. Delete everything in that file
  3. Paste the code below
  4. Save -> Reload your web app
"""

import sys
import os

# ============================================================
# CHANGE 'yourusername' to your actual PythonAnywhere username
# ============================================================
project_path = '/home/yourusername/project'

if project_path not in sys.path:
    sys.path.insert(0, project_path)

os.chdir(project_path)

from app import app as application
