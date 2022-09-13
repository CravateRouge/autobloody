from setuptools import setup
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(name='autobloody',
      version='0.1.1',
      description='AD Privesc Automation',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='CravateRouge',
      author_email='baptiste.crepin@ntymail.com',
      url='https://github.com/CravateRouge/autobloody',
      download_url='https://github.com/CravateRouge/bloodyAD/archive/refs/tags/v0.1.1.tar.gz',
      packages=['autobloody'],
      license='MIT',
      install_requires=['bloodyAD>=0.1','neo4j>=4.4.6'],
      keywords = ['Active Directory', 'Privilege Escalation'],
      classifiers=[
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10'
      ],
      python_requires='>=3.6',
      entry_points={
        "console_scripts":["autobloody = autobloody.main:main"]
      }
)