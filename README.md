# To_Do_List


# Run in terminal

  - python3 -m venv venv
  - source venv/bin/activate
  - pip install flask flask_sqlalchemy sqlalchemy flask_login flask_wtf email_validator

# After that run in terminal
  - export FLASK_APP=app.py
  - flask shell
  >>> from app import db, User, Task
  >>> db.create_all()
  >>> exit()
 
# And run flask in terminal
  - flask run
