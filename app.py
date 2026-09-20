"""
CyberShield - AI-Powered Cyber Security Assessment Toolkit
Phase 1 & 2: Project setup + Flask app with page shells.
Phase 3: Password & crypto tools.
Phase 4: Authentication + database.
"""

import io
import os
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for, session

from modules.password_checker import check_password_strength
from modules.password_generator import generate_password
from modules.aes_encryption import encrypt_file, decrypt_file
from modules.rsa_generator import generate_rsa_keypair
from modules.auth import register_user, authenticate_user, change_password
from modules.port_scanner import scan_target
from modules.packet_sniffer import capture_packets
from modules.website_checker import check_website, calculate_risk
from modules.ssl_checker import check_ssl_certificate
from modules.subdomain_scanner import scan_subdomains
from modules.directory_scanner import scan_directories
from modules.sql_injection_detector import detect_sql_injection
from modules.xss_scanner import detect_xss
from modules.ai_analysis import generate_ai_analysis
from modules.report_generator import generate_single_scan_report, generate_full_history_report
from utils.db import init_db, get_db, log_activity, add_scan_history

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-in-production"  # move to env var later
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["REPORTS_FOLDER"] = os.path.join(os.path.dirname(__file__), "reports")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload limit

init_db()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_user():
    return {"current_user": session.get("username")}


@app.route("/")
def home():
    return render_template("home.html", active_page="home")


@app.route("/about")
def about():
    return render_template("about.html", active_page="about")


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    user_id = session["user_id"]

    total_scans = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    reports_generated = conn.execute(
        "SELECT COUNT(*) FROM reports WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    high_risk = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND risk_level = 'High'", (user_id,)
    ).fetchone()[0]
    medium_risk = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND risk_level = 'Medium'", (user_id,)
    ).fetchone()[0]
    low_risk = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND risk_level = 'Low'", (user_id,)
    ).fetchone()[0]
    recent = conn.execute(
        "SELECT * FROM scan_history WHERE user_id = ? ORDER BY date DESC LIMIT 5", (user_id,)
    ).fetchall()
    conn.close()

    stats = {
        "total_scans": total_scans,
        "reports_generated": reports_generated,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
    }
    return render_template("dashboard.html", active_page="dashboard", stats=stats, recent=recent)


@app.route("/tools")
@login_required
def tools():
    return render_template("tools.html", active_page="tools")


@app.route("/reports")
@login_required
def reports():
    conn = get_db()
    user_reports = conn.execute(
        "SELECT * FROM reports WHERE user_id = ? ORDER BY date DESC", (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("reports.html", active_page="reports", user_reports=user_reports)


@app.route("/history")
@login_required
def history():
    conn = get_db()
    scans = conn.execute(
        "SELECT * FROM scan_history WHERE user_id = ? ORDER BY date DESC", (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("history.html", active_page="history", scans=scans)


@app.route("/history/delete/<int:scan_id>", methods=["POST"])
@login_required
def delete_history(scan_id):
    conn = get_db()
    conn.execute(
        "DELETE FROM scan_history WHERE scan_id = ? AND user_id = ?",
        (scan_id, session["user_id"]),
    )
    conn.commit()
    conn.close()
    flash("Scan record deleted.", "info")
    return redirect(url_for("history"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        ok, message = register_user(username, email, password)
        if ok:
            log_activity(None, f"New user registered: {username}")
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        flash(message, "danger")
        return redirect(url_for("register"))

    return render_template("register.html", active_page="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = authenticate_user(identifier, password)
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_activity(user["id"], "User logged in")
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username/email or password.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html", active_page="login")


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        log_activity(user_id, "User logged out")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        old_pw = request.form.get("old_password", "")
        new_pw = request.form.get("new_password", "")
        ok, message = change_password(session["user_id"], old_pw, new_pw)
        flash(message, "success" if ok else "danger")
        if ok:
            log_activity(session["user_id"], "Password changed")
        return redirect(url_for("profile"))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return render_template("profile.html", active_page="profile", user=user)


@app.route("/contact")
def contact():
    return render_template("contact.html", active_page="contact")


# ---------------------------------------------------------------------------
# Password Strength Checker
# ---------------------------------------------------------------------------
@app.route("/tools/password-checker", methods=["GET", "POST"])
@login_required
def password_checker_page():
    result = None
    if request.method == "POST":
        password = request.form.get("password", "")
        result = check_password_strength(password)
        risk_map = {"Weak": "High", "Medium": "Medium", "Strong": "Low"}
        add_scan_history(
            session["user_id"], "Password Strength Check", "user-provided password",
            result["label"], risk_map.get(result["label"], "Low"),
        )
    return render_template("password_checker.html", active_page="tools", result=result)


@app.route("/api/check-password", methods=["POST"])
def api_check_password():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    return jsonify(check_password_strength(password))


# ---------------------------------------------------------------------------
# Password Generator
# ---------------------------------------------------------------------------
@app.route("/tools/password-generator", methods=["GET", "POST"])
@login_required
def password_generator_page():
    generated = None
    settings = {"length": 16, "use_upper": True, "use_numbers": True, "use_symbols": True}
    if request.method == "POST":
        settings["length"] = int(request.form.get("length", 16))
        settings["use_upper"] = "use_upper" in request.form
        settings["use_numbers"] = "use_numbers" in request.form
        settings["use_symbols"] = "use_symbols" in request.form
        generated = generate_password(**settings)
    return render_template(
        "password_generator.html", active_page="tools", generated=generated, settings=settings
    )


@app.route("/api/generate-password", methods=["POST"])
def api_generate_password():
    data = request.get_json(silent=True) or {}
    password = generate_password(
        length=int(data.get("length", 16)),
        use_upper=bool(data.get("use_upper", True)),
        use_numbers=bool(data.get("use_numbers", True)),
        use_symbols=bool(data.get("use_symbols", True)),
    )
    return jsonify({"password": password})


# ---------------------------------------------------------------------------
# AES File Encryption
# ---------------------------------------------------------------------------
@app.route("/tools/aes-encryption", methods=["GET", "POST"])
@login_required
def aes_encryption_page():
    if request.method == "POST":
        action = request.form.get("action")
        uploaded_file = request.files.get("file")
        password = request.form.get("password", "")

        if not uploaded_file or uploaded_file.filename == "":
            flash("Please choose a file.", "danger")
            return redirect(url_for("aes_encryption_page"))
        if not password:
            flash("Please enter a password.", "danger")
            return redirect(url_for("aes_encryption_page"))

        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        input_path = os.path.join(app.config["UPLOAD_FOLDER"], uploaded_file.filename)
        uploaded_file.save(input_path)

        try:
            if action == "encrypt":
                output_name = uploaded_file.filename + ".enc"
                output_path = os.path.join(app.config["UPLOAD_FOLDER"], output_name)
                encrypt_file(input_path, output_path, password)
                add_scan_history(session["user_id"], "AES Encryption", uploaded_file.filename, "Encrypted", "Low")
            else:  # decrypt
                output_name = uploaded_file.filename.replace(".enc", "") + ".dec"
                output_path = os.path.join(app.config["UPLOAD_FOLDER"], output_name)
                ok = decrypt_file(input_path, output_path, password)
                if not ok:
                    flash("Decryption failed. Wrong password or corrupted file.", "danger")
                    return redirect(url_for("aes_encryption_page"))
                add_scan_history(session["user_id"], "AES Decryption", uploaded_file.filename, "Decrypted", "Low")

            return send_file(output_path, as_attachment=True, download_name=output_name)
        except Exception as e:
            flash(f"Error: {e}", "danger")
            return redirect(url_for("aes_encryption_page"))
        finally:
            if os.path.exists(input_path):
                os.remove(input_path)

    return render_template("aes_encryption.html", active_page="tools")


# ---------------------------------------------------------------------------
# RSA Key Generator
# ---------------------------------------------------------------------------
@app.route("/tools/rsa-generator", methods=["GET", "POST"])
@login_required
def rsa_generator_page():
    keys = None
    if request.method == "POST":
        key_size = int(request.form.get("key_size", 2048))
        keys = generate_rsa_keypair(key_size)
        add_scan_history(session["user_id"], "RSA Key Generation", f"{key_size}-bit", "Generated", "Low")
    return render_template("rsa_generator.html", active_page="tools", keys=keys)


@app.route("/tools/rsa-generator/download/<key_type>", methods=["POST"])
def download_rsa_key(key_type):
    key_content = request.form.get("key_content", "")
    filename = "private_key.pem" if key_type == "private" else "public_key.pem"
    buffer = io.BytesIO(key_content.encode())
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/x-pem-file")


# ---------------------------------------------------------------------------
# Port Scanner
# ---------------------------------------------------------------------------
@app.route("/tools/port-scanner", methods=["GET", "POST"])
@login_required
def port_scanner_page():
    scan_result = None
    target = ""
    port_range = "1-1024"

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        port_range = request.form.get("port_range", "1-1024").strip() or "1-1024"

        if not target:
            flash("Please enter a target IP or hostname.", "danger")
        else:
            scan_result = scan_target(target, port_range)

            if scan_result.get("error"):
                flash(scan_result["error"], "danger")
            else:
                open_ports = [r for r in scan_result["results"] if r["status"] == "open"]
                risk = "High" if len(open_ports) > 5 else ("Medium" if open_ports else "Low")
                summary = f"{len(open_ports)} open port(s) of {len(scan_result['results'])} scanned"
                add_scan_history(session["user_id"], "Port Scan", target, summary, risk)

    return render_template(
        "port_scanner.html", active_page="tools",
        scan_result=scan_result, target=target, port_range=port_range,
    )


# ---------------------------------------------------------------------------
# Packet Sniffer
# ---------------------------------------------------------------------------
@app.route("/tools/packet-sniffer", methods=["GET", "POST"])
@login_required
def packet_sniffer_page():
    capture_result = None

    if request.method == "POST":
        count = int(request.form.get("count", 20))
        timeout = int(request.form.get("timeout", 15))
        count = max(1, min(count, 200))
        timeout = max(1, min(timeout, 60))

        capture_result = capture_packets(count=count, timeout=timeout)

        if capture_result.get("error"):
            flash(capture_result["error"], "danger")
        else:
            packets = capture_result["packets"]
            protocol_counts = {}
            for p in packets:
                protocol_counts[p["protocol"]] = protocol_counts.get(p["protocol"], 0) + 1
            capture_result["protocol_counts"] = protocol_counts

            add_scan_history(
                session["user_id"], "Packet Capture", "local interface",
                f"{len(packets)} packet(s) captured", "Low",
            )

    return render_template("packet_sniffer.html", active_page="tools", capture_result=capture_result)


# ---------------------------------------------------------------------------
# Website Security Checker
# ---------------------------------------------------------------------------
@app.route("/tools/website-checker", methods=["GET", "POST"])
@login_required
def website_checker_page():
    result = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if url_input:
            result = check_website(url_input)
            risk = calculate_risk(result)
            summary = "Reachable" if result["reachable"] else "Unreachable"
            add_scan_history(session["user_id"], "Website Security Check", url_input, summary, risk)
    return render_template("website_checker.html", active_page="tools", result=result, url_input=url_input)


# ---------------------------------------------------------------------------
# SSL Certificate Checker
# ---------------------------------------------------------------------------
@app.route("/tools/ssl-checker", methods=["GET", "POST"])
@login_required
def ssl_checker_page():
    result = None
    hostname = ""
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()
        if hostname:
            result = check_ssl_certificate(hostname)
            if result["error"]:
                risk, summary = "High", "Unreachable"
            elif not result["valid"]:
                risk, summary = "High", "Expired"
            elif result["days_remaining"] < 30:
                risk, summary = "Medium", f"Expires in {result['days_remaining']} days"
            else:
                risk, summary = "Low", f"Valid, {result['days_remaining']} days remaining"
            add_scan_history(session["user_id"], "SSL Certificate Check", hostname, summary, risk)
    return render_template("ssl_checker.html", active_page="tools", result=result, hostname=hostname)


# ---------------------------------------------------------------------------
# Subdomain Scanner
# ---------------------------------------------------------------------------
@app.route("/tools/subdomain-scanner", methods=["GET", "POST"])
@login_required
def subdomain_scanner_page():
    results = None
    domain = ""
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        if domain:
            results = scan_subdomains(domain)
            add_scan_history(
                session["user_id"], "Subdomain Scan", domain,
                f"{len(results)} subdomain(s) found", "Low" if results else "Low",
            )
    return render_template("subdomain_scanner.html", active_page="tools", results=results, domain=domain)


# ---------------------------------------------------------------------------
# Directory Scanner
# ---------------------------------------------------------------------------
@app.route("/tools/directory-scanner", methods=["GET", "POST"])
@login_required
def directory_scanner_page():
    results = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if url_input:
            results = scan_directories(url_input)
            accessible = [r for r in results if r["accessible"]]
            risk = "High" if any(r["path"] in ("admin", "backup", "config") and r["accessible"] for r in results) else (
                "Medium" if accessible else "Low"
            )
            add_scan_history(
                session["user_id"], "Directory Scan", url_input,
                f"{len(accessible)} accessible path(s)", risk,
            )
    return render_template("directory_scanner.html", active_page="tools", results=results, url_input=url_input)


# ---------------------------------------------------------------------------
# SQL Injection Detector
# ---------------------------------------------------------------------------
@app.route("/tools/sql-injection-detector", methods=["GET", "POST"])
@login_required
def sql_injection_detector_page():
    result = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if url_input:
            result = detect_sql_injection(url_input)
            summary = f"{len(result['findings'])} finding(s)"
            add_scan_history(session["user_id"], "SQL Injection Scan", url_input, summary, result["risk_level"])
    return render_template("sql_injection_detector.html", active_page="tools", result=result, url_input=url_input)


# ---------------------------------------------------------------------------
# XSS Scanner
# ---------------------------------------------------------------------------
@app.route("/tools/xss-scanner", methods=["GET", "POST"])
@login_required
def xss_scanner_page():
    result = None
    url_input = ""
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if url_input:
            result = detect_xss(url_input)
            summary = f"{len(result['findings'])} finding(s)"
            add_scan_history(session["user_id"], "XSS Scan", url_input, summary, result["risk_level"])
    return render_template("xss_scanner.html", active_page="tools", result=result, url_input=url_input)


# ---------------------------------------------------------------------------
# AI Security Analysis
# ---------------------------------------------------------------------------
@app.route("/history/analyze/<int:scan_id>")
@login_required
def analyze_scan(scan_id):
    conn = get_db()
    scan = conn.execute(
        "SELECT * FROM scan_history WHERE scan_id = ? AND user_id = ?",
        (scan_id, session["user_id"]),
    ).fetchone()
    conn.close()

    if not scan:
        flash("Scan not found.", "danger")
        return redirect(url_for("history"))

    analysis = generate_ai_analysis(scan["scan_type"], scan["target"], scan["result"], scan["risk_level"])
    log_activity(session["user_id"], f"AI analysis generated for scan #{scan_id}")
    return render_template("ai_analysis.html", active_page="history", scan=scan, analysis=analysis)


# ---------------------------------------------------------------------------
# PDF Report Generator
# ---------------------------------------------------------------------------
@app.route("/history/report/<int:scan_id>", methods=["POST"])
@login_required
def generate_report_for_scan(scan_id):
    conn = get_db()
    scan = conn.execute(
        "SELECT * FROM scan_history WHERE scan_id = ? AND user_id = ?",
        (scan_id, session["user_id"]),
    ).fetchone()

    if not scan:
        conn.close()
        flash("Scan not found.", "danger")
        return redirect(url_for("history"))

    analysis = generate_ai_analysis(scan["scan_type"], scan["target"], scan["result"], scan["risk_level"])

    os.makedirs(app.config["REPORTS_FOLDER"], exist_ok=True)
    filename = f"report_scan{scan_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    output_path = os.path.join(app.config["REPORTS_FOLDER"], filename)

    generate_single_scan_report(dict(scan), analysis, session["username"], output_path)

    conn.execute(
        "INSERT INTO reports (user_id, report_name, file_path) VALUES (?, ?, ?)",
        (session["user_id"], f"{scan['scan_type']} Report - {scan['target']}", filename),
    )
    conn.commit()
    conn.close()

    log_activity(session["user_id"], f"PDF report generated for scan #{scan_id}")
    flash("Report generated successfully.", "success")
    return redirect(url_for("reports"))


@app.route("/reports/generate-full", methods=["POST"])
@login_required
def generate_full_report():
    conn = get_db()
    scans = conn.execute(
        "SELECT * FROM scan_history WHERE user_id = ? ORDER BY date DESC", (session["user_id"],)
    ).fetchall()

    if not scans:
        conn.close()
        flash("No scan history to include in a report yet.", "warning")
        return redirect(url_for("reports"))

    os.makedirs(app.config["REPORTS_FOLDER"], exist_ok=True)
    filename = f"full_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    output_path = os.path.join(app.config["REPORTS_FOLDER"], filename)

    generate_full_history_report([dict(s) for s in scans], session["username"], output_path)

    conn.execute(
        "INSERT INTO reports (user_id, report_name, file_path) VALUES (?, ?, ?)",
        (session["user_id"], "Full Scan History Report", filename),
    )
    conn.commit()
    conn.close()

    log_activity(session["user_id"], "Full history PDF report generated")
    flash("Full report generated successfully.", "success")
    return redirect(url_for("reports"))


@app.route("/reports/download/<path:filename>")
@login_required
def download_report(filename):
    conn = get_db()
    owned = conn.execute(
        "SELECT 1 FROM reports WHERE file_path = ? AND user_id = ?",
        (filename, session["user_id"]),
    ).fetchone()
    conn.close()

    if not owned:
        flash("Report not found.", "danger")
        return redirect(url_for("reports"))

    return send_file(os.path.join(app.config["REPORTS_FOLDER"], filename), as_attachment=True)


# ---------------------------------------------------------------------------
# Error handlers (Phase 13: better error messages)
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", active_page=""), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html", active_page=""), 500


if __name__ == "__main__":
    app.run(debug=True)
