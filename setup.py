from setuptools import setup

setup(
    name='tBB',
    version='0.1.0b0',
    description='A network monitoring tool written in Python.',
    long_description=open('README.md').read(),
    license='GPLv3',
    url='https://github.com/dpdani/tBB',
    author='Daniele Parmeggiani',
    author_email='dani.parmeggiani@gmail.com',
    packages=['tBB'],
    platforms=['POSIX'],
    install_requires=['aiohttp>=0.22.2'],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    ],
    keywords='network security',
    #data_files=[
    #    ('certs', 'certs/key.pem'),
    #    ('certs', 'certs/cert.pem'),
    #],
    entry_points={
        'console_scripts': [
            'tBB=tBB.main:main'
        ]
    },
    package_data={
        'tBB': [
             'LICENSE',
             'README.md',
             'run',
             'scans/DELETEME',
             'certs/*',
         ],
    }
)
