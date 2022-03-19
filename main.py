import os
import sys
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
sys.path.insert(0, os.path.join(currentdir,'encryption'))
sys.path.insert(0, os.path.join(currentdir,'decryption'))


