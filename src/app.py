"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(current_dir,
          "static")), name="static")

TEACHER_CREDENTIALS_FILE = Path(
    os.environ.get("TEACHER_CREDENTIALS_FILE", current_dir / "teachers.json")
)
TEACHER_SESSION_SECONDS = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 600_000
teacher_sessions: dict[str, float] = {}
bearer_scheme = HTTPBearer(auto_error=False)


class TeacherLogin(BaseModel):
    username: str
    password: str


def get_teacher_credentials() -> dict:
    try:
        with TEACHER_CREDENTIALS_FILE.open(encoding="utf-8") as credentials_file:
            data = json.load(credentials_file)
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=503,
            detail="Teacher login is not configured. Set up the teacher credentials file.",
        ) from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=500,
            detail="The teacher credentials file could not be read.",
        ) from error

    teachers = data.get("teachers") if isinstance(data, dict) else None
    if not isinstance(teachers, dict):
        raise HTTPException(
            status_code=500,
            detail="The teacher credentials file must contain a teachers object.",
        )
    return teachers


def get_authenticated_teacher(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> str:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Teacher login required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expires_at = teacher_sessions.get(credentials.credentials)
    if expires_at is None or expires_at <= time.time():
        teacher_sessions.pop(credentials.credentials, None)
        raise HTTPException(
            status_code=401,
            detail="Teacher login required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "teacher"


# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/auth/login")
def login(teacher_login: TeacherLogin):
    teachers = get_teacher_credentials()
    teacher = teachers.get(teacher_login.username)
    if not isinstance(teacher, dict):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    try:
        salt = bytes.fromhex(teacher["salt"])
        expected_hash = bytes.fromhex(teacher["password_hash"])
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(
            status_code=500,
            detail="The teacher credentials file contains an invalid entry.",
        ) from error
    if len(salt) < 16 or len(expected_hash) != hashlib.sha256().digest_size:
        raise HTTPException(
            status_code=500,
            detail="The teacher credentials file contains an invalid entry.",
        )

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        teacher_login.password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_urlsafe(32)
    teacher_sessions[token] = time.time() + TEACHER_SESSION_SECONDS
    return {"access_token": token, "token_type": "bearer", "username": teacher_login.username}


@app.post("/auth/logout")
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    _teacher: str = Depends(get_authenticated_teacher),
):
    if credentials is not None:
        teacher_sessions.pop(credentials.credentials, None)
    return {"message": "Logged out"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str,
    _teacher: str = Depends(get_authenticated_teacher),
):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    _teacher: str = Depends(get_authenticated_teacher),
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
