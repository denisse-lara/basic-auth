# basic-auth

API Docs: https://documenter.getpostman.com/view/19926071/UVsEWpsm

## steps to setup

1. Create a virtualenv and install all dependencies.

```
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Create a .flaskenv file with the _FLASK_APP_ environment variable.
3. Create a .env file with _SECRET_KEY_, _IP_, as _PORT_ env variables.
4. Apply db migrations.

```
flask db init
flask db upgrade
```
