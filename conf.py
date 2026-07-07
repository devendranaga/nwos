import os

# 1. Enable Breathe and Read the Docs theme extensions
extensions = [
    'breathe',
    'sphinx_rtd_theme'
]

# 2. Tell Breathe where Doxygen put the XML files
breathe_projects = { "MyProject": "./docs/xml" }
breathe_default_project = "MyProject"

# 3. Visual Configuration
project = 'NwOS Code Documentation'
html_theme = 'sphinx_rtd_theme'
