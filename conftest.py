import os
import sys

# Let the tests import guard.py, injection_clf.py, api.py from the project folder.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
