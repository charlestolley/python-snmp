import os.path
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".."))
)

project = "snmp"
copyright = "2021-2022, Charles C. D. Tolley"
author = "Charles C. D. Tolley"
version = "0.3.1"
release = version
extensions = ["sphinx.ext.autodoc"]
html_theme = "python_docs_theme"

# Tack __init__ docstring onto the end of the class docstring
# when auto-generating sphinx documentation for a class
autoclass_content = "both"
