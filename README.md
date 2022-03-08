# basic-auth

## steps to setup

1. Create a virtualenv and install all dependencies.
```
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```
2. Create a .flaskenv file with the *FLASK_APP* environment variable.
3. Create a .env file with *SECRET_KEY*, *IP*, as *PORT* env variables.
4. Apply db migrations.
```
flask db init
flask db upgrade
```
