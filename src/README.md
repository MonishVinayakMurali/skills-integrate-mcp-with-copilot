# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Teacher login to manage student registrations
- Students can view activities and participant lists without logging in

## Configure teacher access

Signup and unregister requests are restricted to authenticated teachers. Teacher
credentials are stored as PBKDF2-SHA256 hashes in `src/teachers.json`, which is
ignored by Git. Create the file with this shape for each teacher:

```json
{
  "teachers": {
    "teacher-username": {
      "salt": "HEX_ENCODED_RANDOM_SALT",
      "password_hash": "HEX_ENCODED_PBKDF2_SHA256_HASH"
    }
  }
}
```

Generate a unique salt and password hash for each teacher with Python:

```python
import getpass
import hashlib
import secrets

salt = secrets.token_bytes(16)
password = getpass.getpass("Teacher password: ").encode("utf-8")
password_hash = hashlib.pbkdf2_hmac("sha256", password, salt, 600_000)
print("salt:", salt.hex())
print("password_hash:", password_hash.hex())
```

Put the generated values in the credentials file. Alternatively, set
`TEACHER_CREDENTIALS_FILE` to the path of a protected credentials file. Keep
the credentials file private and use HTTPS when deploying the API. Restart the
API after changing credentials. Teacher sessions expire after eight hours or
when the teacher logs out.

## Getting Started

1. From the repository root, install the dependencies:

   ```
   pip install -r requirements.txt
   ```

2. Run the application:

   ```
   uvicorn src.app:app --reload
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/auth/login`                                                      | Log in a teacher and receive an access token                        |
| POST   | `/auth/logout`                                                     | Log out the authenticated teacher                                   |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up a student (teacher authentication required)                 |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Unregister a student (teacher authentication required)            |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
