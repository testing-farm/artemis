from setuptools import setup


setup(
    name='artemis',
    version='0.0.1',
    package_dir={
        'artemis': 'artemis'
    },
    packages=[
        'artemis'
    ],
    entry_points={
        'console_scripts': [
            'artemis-server = artemis:main'
        ]
    },

    install_requires=[
        'ansible-vault',
        'gluetool',

        # required by gluetool but we want to get rid of it
        'setuptools-scm'
    ],

    author='tft',
    author_email='',
    description='',
    license='',
    keywords='',
    url='',
    long_description=''
)
