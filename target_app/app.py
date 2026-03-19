"""Intentionally branch-heavy demo Flask app for local fuzzing experiments."""

from __future__ import annotations

from flask import Flask, request

try:
    from target_app.coverage_tracker import get_coverage, mark, reset_coverage
except ModuleNotFoundError:
    # Support direct execution via `python target_app/app.py`.
    from coverage_tracker import get_coverage, mark, reset_coverage

app = Flask(__name__)


@app.get("/")
def home() -> str:
    mark("home:view")
    return """
    <html>
      <head><title>MiniGrey Target</title></head>
      <body>
        <h1>MiniGrey Demo App</h1>
        <p>This app is intentionally branch-heavy for local fuzzing demos.</p>

        <ul>
          <li><a href="/search">Search</a></li>
          <li><a href="/login">Login</a></li>
          <li><a href="/item">Item</a></li>
          <li><a href="/profile">Profile</a></li>
          <li><a href="/debug?token=demo">Debug</a></li>
          <li><a href="/item?id=1">Item 1</a></li>
          <li><a href="/item?id=9999">Item 9999</a></li>
        </ul>

        <h2>Quick Search</h2>
        <form action="/search" method="get">
          <input name="q" type="text" value="flask" />
          <button type="submit">Search</button>
        </form>

        <h2>Quick Profile</h2>
        <form action="/profile" method="get">
          <input name="name" type="text" value="student" />
          <button type="submit">Open Profile</button>
        </form>
      </body>
    </html>
    """


@app.get("/search")
def search() -> tuple[str, int]:
    q = request.args.get("q", "")
    if not q.strip():
        mark("search:empty")
        msg = "No query submitted."
        status = 200
    elif len(q) > 64:
        mark("search:long")
        msg = "Query too long; showing trimmed summary."
        status = 200
    elif any(token in q.lower() for token in ["<script>", "'", '"', "<", ">", "&"]):
        mark("search:suspicious")
        msg = "Suspicious search pattern detected."
        status = 422
    else:
        mark("search:normal")
        msg = "Normal search executed."
        status = 200

    body = f"""
    <html>
      <body>
        <h1>Search</h1>
        <p>{msg}</p>
        <div id="query-reflection">You searched for: {q}</div>
        <a href="/">Home</a>
      </body>
    </html>
    """
    return body, status


@app.route("/login", methods=["GET", "POST"])
def login() -> tuple[str, int] | str:
    if request.method == "GET":
        mark("login:get")
        return """
        <html>
          <body>
            <h1>Login</h1>
            <form action="/login" method="post">
              <label>Username <input name="username" type="text" /></label>
              <label>Password <input name="password" type="password" /></label>
              <button type="submit">Submit</button>
            </form>
            <a href="/">Home</a>
          </body>
        </html>
        """

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username and not password:
        mark("login:both-empty")
        return "Both fields are empty. invalid login input", 400
    if not username or not password:
        mark("login:one-empty")
        return "One field is missing. invalid login input", 400
    if len(username) > 40:
        mark("login:username-long")
        return "Username length warning", 422
    if username.lower().startswith("admin"):
        mark("login:admin-prefix")
        if password == "letmein":
            mark("login:admin-letmein")
            return "Admin simulation branch reached", 200
        return "Admin prefix seen, wrong password", 403
    if "token:" in username.lower() and password.endswith("::debug"):
        mark("login:token-path")
        return "Special token-like branch reached", 202
    if "::" in username and " " in password:
        mark("login:malformed-combo")
        return "Malformed input combination", 409

    mark("login:default")
    return f"Login simulation complete for user={username}", 200


@app.get("/item")
def item() -> tuple[str, int]:
    item_id = request.args.get("id")
    if item_id is None:
        mark("item:missing")
        return "Item id is required", 400

    if not item_id.lstrip("-").isdigit():
        mark("item:non-numeric")
        return f"Invalid item id format: {item_id}", 422

    value = int(item_id)
    if value < 0:
        mark("item:negative")
        return "Negative item ids are not allowed", 404
    if value == 0:
        mark("item:zero")
        return "Zero is a reserved item id", 418
    if value > 1_000_000:
        mark("item:very-large")
        return "Item id too large", 422
    if value == 31337:
        mark("item:special-31337")
        return "Unique collector item path reached", 200

    mark("item:normal")
    return f"Item details for id={value}", 200


@app.get("/profile")
def profile() -> tuple[str, int]:
    name = request.args.get("name", "guest")
    if len(name) > 48:
        mark("profile:long")
        status = 413
        note = "Profile name too long"
    elif any(ch in name for ch in ["<", ">", "'", '"', "&"]):
        mark("profile:suspicious")
        status = 422
        note = "Profile contains suspicious characters"
    else:
        mark("profile:normal")
        status = 200
        note = "Profile rendered"

    return (
        f"""
        <html>
          <body>
            <h1>Profile</h1>
            <p>{note}</p>
            <div id="name">Hello, {name}</div>
            <a href="/">Home</a>
          </body>
        </html>
        """,
        status,
    )


@app.get("/debug")
def debug() -> tuple[str, int]:
    token = request.args.get("token", "")
    if not token:
        mark("debug:empty")
        return "Debug token missing", 403
    if token == "demo":
        mark("debug:demo")
        return "Demo debug branch", 200
    if token.startswith("dbg-"):
        mark("debug:prefix")
        if token.endswith("-open"):
            mark("debug:prefix-open")
            return "Deep debug branch opened", 200
        return "Partial debug token accepted", 202
    if len(token) > 20 and token.isalnum():
        mark("debug:long-alnum")
        return "Long alphanumeric token path", 206

    mark("debug:reject")
    return "Invalid debug token", 401


@app.get("/__coverage")
def coverage() -> tuple[dict[str, list[str]], int]:
    return {"coverage": get_coverage()}, 200


@app.route("/__reset_coverage", methods=["GET", "POST"])
def reset_cov() -> tuple[dict[str, str], int]:
    reset_coverage()
    return {"status": "coverage reset"}, 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
