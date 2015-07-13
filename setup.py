try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Evolver',
    'author': 'uboscolo',
    'url': 'file://Applications/evolver',
    'download_url': 'file://Applications/evolver',
    'author_email': 'uboscolo@gmail.com',
    'version': '0.1',
    'install_requires': ['nose'],
    'packages': ['evolver'],
    'scripts': [],
    'name': 'evolver'
}

setup(**config)
