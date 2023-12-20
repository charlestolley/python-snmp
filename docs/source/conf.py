import os.path
import sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".."))
)

project = "snmp"
copyright = "2021-2023, Charles C. D. Tolley"
author = "Charles C. D. Tolley"
version = "0.7.0"
release = version
extensions = ["sphinx.ext.autodoc"]
html_theme = "python_docs_theme"

autodoc_typehints = "none"
autodoc_member_order = "bysource"
