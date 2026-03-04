"""
ID-Networkers Combined Lab 2: The XML Gateway
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
FastAPI application with two chained vulnerabilities:
  1. JWT "none" algorithm authentication bypass
  2. XXE (XML External Entity) injection via lxml
"""

from fastapi import FastAPI, Request, Form, UploadFile, File, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from lxml import etree

from app.auth import authenticate_user, create_token, verify_token

app = FastAPI(
    title="ID-Networkers Combined Lab 2",
    docs_url=None,
    redoc_url=None,
)

templates = Jinja2Templates(directory="app/templates")


# --------------------------------------------------------------------------- #
#  Login
# --------------------------------------------------------------------------- #

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the login portal."""
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """Authenticate user and issue a JWT session cookie."""
    user = authenticate_user(username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials. Try again."},
        )

    token = create_token(username, user["role"])
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(key="session_token", value=token, httponly=False)  # httponly=False so students can inspect it
    return response


# --------------------------------------------------------------------------- #
#  Dashboard (Admin only)
# --------------------------------------------------------------------------- #

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, session_token: str = Cookie(None)):
    """Render the admin dashboard — requires admin role in the JWT."""
    if not session_token:
        return RedirectResponse(url="/")

    payload = verify_token(session_token)
    if not payload:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid or expired session. Please log in."},
        )

    if payload.get("role") != "admin":
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "⛔ Access Denied — Admin privileges required."},
        )

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "username": payload.get("sub")},
    )


# --------------------------------------------------------------------------- #
#  XML Upload (Vulnerable XXE)
# --------------------------------------------------------------------------- #

@app.post("/upload-xml", response_class=HTMLResponse)
async def upload_xml(
    request: Request,
    session_token: str = Cookie(None),
    xmlfile: UploadFile = File(...),
):
    """
    Parse an uploaded XML configuration file.

    *** VULNERABLE IMPLEMENTATION ***
    The lxml parser is configured with resolve_entities=True and load_dtd=True,
    which enables XML External Entity (XXE) expansion.
    """
    # --- Auth guard ---
    if not session_token:
        return RedirectResponse(url="/")

    payload = verify_token(session_token)
    if not payload or payload.get("role") != "admin":
        return RedirectResponse(url="/")

    # --- Read uploaded XML ---
    content = await xmlfile.read()

    # --- Vulnerable XML parsing ---
    try:
        parser = etree.XMLParser(
            resolve_entities=True,   # VULNERABILITY: resolves external entities
            dtd_validation=False,
            load_dtd=True,           # VULNERABILITY: loads DTDs (enables ENTITY declarations)
            no_network=False,        # Allow network access for entities (not strictly needed for file://)
        )
        tree = etree.fromstring(content, parser=parser)
        result = etree.tostring(tree, pretty_print=True, encoding="unicode")
    except etree.XMLSyntaxError as e:
        result = f"XML Syntax Error:\n{e}"
    except Exception as e:
        result = f"Error parsing XML:\n{e}"

    return templates.TemplateResponse(
        "result.html",
        {"request": request, "result": result, "username": payload.get("sub")},
    )


# --------------------------------------------------------------------------- #
#  Logout
# --------------------------------------------------------------------------- #

@app.get("/logout")
async def logout():
    """Clear session and redirect to login."""
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("session_token")
    return response
