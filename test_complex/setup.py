from setuptools import setup, find_packages

setup(
    name="ml-project",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'numpy>=1.18.0',  # Conflict with requirements.txt
        'pandas>=1.0.0',
        'scikit-learn>=0.23.0',
        'tensorflow>=2.3.0',  # Older version
        'torch>=1.7.0',    # Conflict with transformers
    ],
)
