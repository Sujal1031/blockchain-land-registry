

import streamlit as st
import sqlite3
import hashlib
import time
import json
import csv
import io
import os
from datetime import datetime
import pyotp

DB_FILE = "bhulekh.db"
SQLITE_TIMEOUT = 30  # seconds

# Compatibility helper

def safe_rerun():
    """
    Cross-version safe rerun:
    - Try st.experimental_rerun() if available.
    - Otherwise toggle a session_state key and update query params to force a refresh,
      then stop execution.
    """
    try:
        st.experimental_rerun()
    except Exception:
        st.session_state["_rerun_toggle"] = not st.session_state.get("_rerun_toggle", False)
        try:
            st.experimental_set_query_params(_ts=int(time.time()))
        except Exception:
            pass
        st.stop()

# ---------------------------
# Database init + WAL mode
# ---------------------------
def init_db(print_totp_on_create=True):
    # Ensure DB file and tables exist, set WAL mode for better concurrency
    with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE,
                password_hash TEXT,
                role TEXT,
                totp_secret TEXT,
                last_login TEXT,
                active INTEGER DEFAULT 1
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS citizens (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE,
                password_hash TEXT,
                name TEXT,
                aadhaar TEXT,
                active INTEGER DEFAULT 1
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS lands (
                id INTEGER PRIMARY KEY,
                citizen_id INTEGER,
                district TEXT,
                taluka TEXT,
                village TEXT,
                survey_no TEXT,
                area_sqft REAL,
                land_type TEXT,
                owner_name TEXT,
                owner_aadhaar TEXT,
                status TEXT DEFAULT 'pending',
                tx_hash TEXT,
                timestamp TEXT,
                FOREIGN KEY (citizen_id) REFERENCES citizens(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS pending_approvals (
                id INTEGER PRIMARY KEY,
                land_id INTEGER,
                type TEXT,
                details TEXT,
                status TEXT DEFAULT 'pending',
                admin_remarks TEXT,
                timestamp TEXT,
                FOREIGN KEY (land_id) REFERENCES lands(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY,
                admin_id INTEGER,
                action TEXT,
                details TEXT,
                timestamp TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS blockchain_tx (
                id INTEGER PRIMARY KEY,
                tx_hash TEXT,
                action TEXT,
                details TEXT,
                timestamp TEXT
            )
        ''')

        # Sample admin
        c.execute("SELECT COUNT(*) FROM admins WHERE email = ?", ('test@admin.com',))
        if c.fetchone()[0] == 0:
            totp_secret = pyotp.random_base32()
            pw_hash = hashlib.sha256('admin123'.encode()).hexdigest()
            c.execute("INSERT INTO admins (email, password_hash, role, totp_secret) VALUES (?, ?, ?, ?)",
                      ('test@admin.com', pw_hash, 'SUPER_ADMIN', totp_secret))
            conn.commit()
            if print_totp_on_create:
                print("\n==============================")
                print("Sample Admin Created")
                print("Email: test@admin.com")
                print("Password: admin123")
                print(f"TOTP Secret Code: {totp_secret}")
                print("Add this secret in your authenticator app (Google Authenticator / Authy).")
                print("==============================\n")

        # Sample citizen
        c.execute("SELECT COUNT(*) FROM citizens WHERE email = ?", ('citizen@example.com',))
        if c.fetchone()[0] == 0:
            pw_hash = hashlib.sha256('citizen123'.encode()).hexdigest()
            c.execute("INSERT INTO citizens (email, password_hash, name, aadhaar) VALUES (?, ?, ?, ?)",
                      ('citizen@example.com', pw_hash, 'John Doe', '123456789012'))
            conn.commit()

# Initialize DB
init_db(print_totp_on_create=True)

# ---------------------------
# Mock blockchain (robust)
# ---------------------------
class MockBlockchain:
    def __init__(self):
        self.transactions = []

    def record_transaction(self, action, details):
        """
        Create a tx hash and write to blockchain_tx table.
        Uses its own short-lived connection with timeout and WAL enabled.
        """
        tx_hash = hashlib.sha256(f"{action}{details}{time.time()}".encode()).hexdigest()
        ts = datetime.now().isoformat()
        self.transactions.append({'hash': tx_hash, 'action': action, 'details': details, 'timestamp': ts})

        # Use separate connection with timeout and WAL (safe to re-run)
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            cur = conn.cursor()
            cur.execute("INSERT INTO blockchain_tx (tx_hash, action, details, timestamp) VALUES (?, ?, ?, ?)",
                        (tx_hash, action, details, ts))
            conn.commit()

        return tx_hash

blockchain = MockBlockchain()

# ---------------------------
# Helpers
# ---------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, stored_hash):
    return hash_password(password) == stored_hash

def log_audit(admin_id, action, details):
    with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO audit_logs (admin_id, action, details, timestamp) VALUES (?, ?, ?, ?)",
                  (admin_id, action, details, datetime.now().isoformat()))
        conn.commit()

def parse_details(details_text):
    if not details_text:
        return None
    try:
        return json.loads(details_text)
    except Exception:
        pass
    try:
        parts = details_text.split("||")
        if len(parts) >= 3:
            return {
                "land_id": int(parts[0]) if parts[0].isdigit() else parts[0],
                "new_owner_name": parts[1],
                "new_owner_aadhaar": parts[2],
                "notes": parts[3] if len(parts) > 3 else ""
            }
    except Exception:
        pass
    return None

# ---------------------------
# Streamlit UI setup
# ---------------------------
st.set_page_config(page_title="Digital Bhulekh India", page_icon="🏡", layout="wide")

st.title("🏡 Digital Bhulekh India — Blockchain Land Registry Portal")

if 'admin_logged_in' not in st.session_state:
    st.session_state.admin_logged_in = False
    st.session_state.admin_id = None
    st.session_state.role = None
if 'citizen_logged_in' not in st.session_state:
    st.session_state.citizen_logged_in = False
    st.session_state.citizen_id = None
    st.session_state.citizen_name = None

# ---------------------------
# Main nav
# ---------------------------
def main():
    menu = [
        "Home",
        "Citizen Sign-Up",
        "Citizen Login",
        "Citizen Registration",
        "Transfer",
        "Verify",
        "Admin Login",
        "Admin: Create New Admin"
    ]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        show_home()
    elif choice == "Citizen Sign-Up":
        citizen_sign_up()
    elif choice == "Citizen Login":
        citizen_login()
    elif choice == "Citizen Registration":
        if st.session_state.citizen_logged_in:
            detailed_land_registration()
        else:
            st.error("Please login as a citizen first.")
    elif choice == "Transfer":
        transfer_ui()
    elif choice == "Verify":
        public_verify_enhanced()
    elif choice == "Admin Login":
        admin_login()
    elif choice == "Admin: Create New Admin":
        create_admin_ui()

# ---------------------------
# Home
# ---------------------------
def show_home():
    """
    Enhanced Home page with quick tips and inline image examples showing
    how citizens/admins can use the app (login, signup, register land, verify).
    """
    st.header("Welcome to Digital Bhulekh India")
    st.markdown(
        "Secure land registry using a mock blockchain for demonstration. "
        "Below are quick tips to help citizens and admins use the app."
    )

    # Top quick action buttons
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Citizen Sign-Up / Login"):
            st.session_state.setdefault("nav_target", "Citizen Sign-Up")
            safe_rerun()
    with col2:
        if st.button("Register Land"):
            st.session_state.setdefault("nav_target", "Citizen Registration")
            safe_rerun()
    with col3:
        if st.button("Public Verify"):
            st.session_state.setdefault("nav_target", "Verify")
            safe_rerun()

    st.markdown("---")

    # Tips grid
    st.subheader("How to use (quick guide)")
    tip_cols = st.columns([1,1,1])

    # Tip 1: Citizen Login / Sign-up
    with tip_cols[0]:
        st.markdown("### 👤 Citizen Sign-Up / Login")
        st.write(
            "1. Go to **Citizen Sign-Up** to create an account (email + password + Aadhaar).\n\n"
            "2. After sign-up, go to **Citizen Login** and enter email/password to access features.\n\n"
            "3. Once logged in you can register lands or request transfers."
        )
        # Small example image (replace path if you have a real screenshot)
        example_img_1 = "/mnt/data/9b9dd930-7d9a-48f0-90ec-1ca28931f8e1.png"
        try:
            st.image(example_img_1, caption="Example: Government portal style header (for visual)", use_container_width=True)
        except Exception:
            st.caption("Put a login screenshot at: " + example_img_1)

    # Tip 2: Register Land
    with tip_cols[1]:
        st.markdown("### 📝 Register Land")
        st.write(
            "1. Login as citizen → go to **Citizen Registration**.\n\n"
            "2. Fill district, taluka, village, survey number and owner details.\n\n"
            "3. Upload land document (PDF/Image) and submit — it will go to admin for approval."
        )
        with st.expander("Why approval?"):
            st.write("Admin verifies submitted details and approves. After approval a transaction (TX) is written to the blockchain table and the land record gets a TX hash.")

    # Tip 3: Transfer requests
    with tip_cols[2]:
        st.markdown("### 🔁 Transfer Ownership")
        st.write(
            "1. Login as citizen, go to **Transfer**.\n\n"
            "2. Select your land, fill new owner details (or choose existing citizen) and submit.\n\n"
            "3. Admin will approve/reject; if approved a blockchain transaction is recorded and land owner is updated."
        )
        with st.expander("Tip"):
            st.write("Use the 'Select existing citizen' option to avoid typos when the new owner already has an account.")

    st.markdown("---")

    # Deep dive section with more images and how to verify TX
    st.subheader("Verifying transactions (for citizens)")
    st.write(
        "You don't need to have a TX hash to verify. Use the **Verify** page to:\n\n"
        "- Search by **Transaction Hash** (full or partial) OR\n"
        "- Search by **Survey Number**, **Owner Name**, **Village**, or **Land ID**.\n\n"
        "If a land has been approved, the land record will include the TX hash — you can click **View TX** to see transaction details."
    )

    # Example two-column: steps + screenshot
    s1, s2 = st.columns([2,1])
    with s1:
        st.markdown("#### Step-by-step: Find your land & verify")
        st.write("""
        1. Go to **Verify** in the sidebar.\n
        2. If you don't have a TX hash, enter the survey number (most reliable) or owner name + village.\n
        3. Click **Search**. The app will list matching land records and show `tx_hash` if present.\n
        4. Click **View TX** to display blockchain transaction details (action, timestamp, and any details).
        """)
    with s2:
        example_img_verify = "/mnt/data/9b9dd930-7d9a-48f0-90ec-1ca28931f8e1.png"
        try:
            st.image(example_img_verify, caption="Example: Search box and public verify area", use_container_width=True)
        except Exception:
            st.caption("Add a verify screenshot at: " + example_img_verify)

    st.markdown("---")

    # Short FAQ
    st.subheader("Quick FAQ")
    st.markdown("""
    - **Q:** Where do I get the TX hash?\n
      **A:** After admin approval the TX hash is shown in the admin success message and appears in the land record. Use the **Verify** page to locate it.\n\n
    - **Q:** Who can approve a registration/transfer?\n
      **A:** Only admins (with 2FA) can approve. Citizens submit requests; admins review and approve.\n\n
    - **Q:** How do I contact admin?\n
      **A:** For now share the screenshot or TX hash with the local admin operator. (Email/SMS feature can be added later.)
    """)

    st.markdown("---")
    st.info("Want me to add on-screen annotated screenshots (arrows/labels) showing the exact buttons? Reply 'annotated images' and I will add them.")

# ---------------------------
# Citizen flows
# ---------------------------
def citizen_sign_up():
    st.header("Citizen Sign-Up")
    with st.form("citizen_sign_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        name = st.text_input("Full Name")
        aadhaar = st.text_input("Aadhaar Number")
        submitted = st.form_submit_button("Create Account")
        if submitted:
            if not (email and password and name and aadhaar):
                st.error("Fill all fields.")
                return
            if len(password) < 6:
                st.error("Password must be at least 6 characters.")
                return
            try:
                with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                    c = conn.cursor()
                    c.execute("INSERT INTO citizens (email, password_hash, name, aadhaar) VALUES (?, ?, ?, ?)",
                              (email, hash_password(password), name, aadhaar))
                    conn.commit()
                st.success("Account created. You can now log in.")
            except sqlite3.IntegrityError:
                st.error("Email already exists.")

def citizen_login():
    st.header("Citizen Login")
    if st.session_state.citizen_logged_in:
        st.success(f"Logged in as {st.session_state.citizen_name}")
        if st.button("Logout"):
            st.session_state.citizen_logged_in = False
            st.session_state.citizen_id = None
            st.session_state.citizen_name = None
            safe_rerun()
        return

    with st.form("citizen_login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log In")
        if submitted:
            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                c = conn.cursor()
                c.execute("SELECT id, password_hash, name FROM citizens WHERE email = ? AND active = 1", (email,))
                row = c.fetchone()
            if row and verify_password(password, row[1]):
                st.session_state.citizen_logged_in = True
                st.session_state.citizen_id = row[0]
                st.session_state.citizen_name = row[2]
                st.success("Logged in.")
                safe_rerun()
            else:
                st.error("Invalid credentials.")

def detailed_land_registration():
    st.header("Detailed Land Registration")
    citizen_id = st.session_state.citizen_id
    with st.form("land_reg_form"):
        district = st.text_input("District")
        taluka = st.text_input("Taluka")
        village = st.text_input("Village")
        survey_no = st.text_input("Survey Number")
        area_sqft = st.number_input("Area (sqft)", min_value=0.0)
        land_type = st.selectbox("Land Type", ["Agricultural", "Residential", "Commercial", "Industrial"])
        owner_name = st.text_input("Owner Name")
        owner_aadhaar = st.text_input("Owner Aadhaar Number")
        uploaded = st.file_uploader("Upload Document (pdf/jpg/png)", type=["pdf", "jpg", "png"])
        submitted = st.form_submit_button("Submit Registration")
        if submitted:
            if not (district and taluka and village and survey_no and owner_name and owner_aadhaar):
                st.error("Fill required fields.")
                return
            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO lands (citizen_id, district, taluka, village, survey_no, area_sqft, land_type, owner_name, owner_aadhaar, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (citizen_id, district, taluka, village, survey_no, area_sqft, land_type, owner_name, owner_aadhaar, datetime.now().isoformat())
                )
                land_id = c.lastrowid
                details = json.dumps({"land_id": land_id, "desc": f"Land in {village}, {taluka}, {district}"})
                c.execute("INSERT INTO pending_approvals (land_id, type, details, timestamp) VALUES (?, ?, ?, ?)",
                          (land_id, 'registration', details, datetime.now().isoformat()))
                conn.commit()
            st.success("Registration submitted for approval.")

# ---------------------------
# Transfer UI (citizen)
# ---------------------------
def transfer_ui():
    st.header("Ownership Transfer")
    if not st.session_state.citizen_logged_in:
        st.error("Please login as a citizen to initiate a transfer.")
        return

    citizen_id = st.session_state.citizen_id
    with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
        c = conn.cursor()
        c.execute("SELECT id, district, taluka, village, survey_no, area_sqft, status, owner_name, owner_aadhaar FROM lands WHERE citizen_id = ?", (citizen_id,))
        lands = c.fetchall()

    if not lands:
        st.info("You have no registered lands to transfer.")
        return

    choices = [f"ID {l[0]} — {l[1]}/{l[2]}/{l[3]} | Survey {l[4]} | Status: {l[6]} | Owner: {l[7]}" for l in lands]
    sel = st.selectbox("Select land to transfer", choices)
    sel_index = choices.index(sel)
    selected_land = lands[sel_index]
    land_id = selected_land[0]

    st.write("Selected land details:")
    st.write({
        "id": selected_land[0],
        "district": selected_land[1],
        "taluka": selected_land[2],
        "village": selected_land[3],
        "survey_no": selected_land[4],
        "area_sqft": selected_land[5],
        "status": selected_land[6],
        "owner_name": selected_land[7],
        "owner_aadhaar": selected_land[8],
    })

    st.markdown("---")
    st.subheader("New Owner Details")

    with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
        c = conn.cursor()
        c.execute("SELECT id, email, name, aadhaar FROM citizens WHERE active = 1")
        all_citizens = c.fetchall()

    existing_emails = ["(enter manually)"] + [f"{row[1]} — {row[2]}" for row in all_citizens]
    email_choice = st.selectbox("Select existing citizen (or enter manually)", existing_emails)

    if email_choice != "(enter manually)":
        selected_email = email_choice.split(" — ")[0]
        rec = next((r for r in all_citizens if r[1] == selected_email), None)
        if rec:
            new_owner_name = rec[2]
            new_owner_aadhaar = rec[3]
        else:
            new_owner_name = ""
            new_owner_aadhaar = ""
    else:
        new_owner_name = st.text_input("New Owner Name")
        new_owner_aadhaar = st.text_input("New Owner Aadhaar Number")

    reason = st.text_area("Reason for transfer / Notes (optional)")

    if st.button("Submit Transfer Request"):
        if not new_owner_name or not new_owner_aadhaar:
            st.error("Please provide new owner's name and Aadhaar number.")
        else:
            details_obj = {
                "land_id": land_id,
                "new_owner_name": new_owner_name,
                "new_owner_aadhaar": new_owner_aadhaar,
                "notes": reason
            }
            details_json = json.dumps(details_obj)
            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO pending_approvals (land_id, type, details, timestamp) VALUES (?, ?, ?, ?)",
                          (land_id, 'transfer', details_json, datetime.now().isoformat()))
                conn.commit()
            st.success("Transfer request submitted for admin approval.")

# ---------------------------
# Public verification
# ---------------------------
def display_public_tx(row):
    tid, thash, taction, tdetails, tts = row
    with st.expander(f"TX ID {tid} — {thash[:16]}... ({taction}) — {tts}"):
        st.write(f"**TX Hash:** `{thash}`")
        parsed = None
        try:
            parsed = json.loads(tdetails) if tdetails else None
        except Exception:
            parsed = None
        if parsed is not None:
            st.json(parsed)
        else:
            st.write("Details (raw):")
            st.code(tdetails or "")
        st.text_area("Copy TX Hash", value=thash, height=40, key=f"copy_{tid}")
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn2:
            c2 = conn2.cursor()
            c2.execute("SELECT id, district, taluka, village, survey_no, owner_name, status FROM lands WHERE tx_hash = ?", (thash,))
            linked = c2.fetchone()
        if linked:
            st.write("Linked Land:")
            st.write({
                "land_id": linked[0],
                "district": linked[1],
                "taluka": linked[2],
                "village": linked[3],
                "survey_no": linked[4],
                "owner_name": linked[5],
                "status": linked[6]
            })
        else:
            st.write("No linked land found for this TX hash.")

def public_verify_enhanced():
    st.header("Public Verification")
    st.write("Search by Transaction Hash OR by land details (Survey Number, Owner Name, Village, or Land ID).")
    search_tx = st.text_input("Enter Transaction Hash (full or partial)")
    col1, col2, col3 = st.columns(3)
    with col1:
        survey_q = st.text_input("Survey Number")
    with col2:
        owner_q = st.text_input("Owner Name")
    with col3:
        village_q = st.text_input("Village")
    land_id_q = st.text_input("Land ID (numeric)")

    col_a, col_b = st.columns([1,1])
    with col_a:
        if st.button("Search"):
            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                c = conn.cursor()
                if search_tx and search_tx.strip():
                    q = f"%{search_tx.strip()}%"
                    c.execute("SELECT id, tx_hash, action, details, timestamp FROM blockchain_tx WHERE tx_hash LIKE ? ORDER BY id DESC", (q,))
                    rows = c.fetchall()
                    if not rows:
                        st.warning("No blockchain transactions found matching that hash.")
                    else:
                        st.success(f"Found {len(rows)} transaction(s).")
                        for r in rows:
                            display_public_tx(r)
                else:
                    conditions = []
                    params = []
                    if survey_q and survey_q.strip():
                        conditions.append("survey_no LIKE ?")
                        params.append(f"%{survey_q.strip()}%")
                    if owner_q and owner_q.strip():
                        conditions.append("owner_name LIKE ?")
                        params.append(f"%{owner_q.strip()}%")
                    if village_q and village_q.strip():
                        conditions.append("village LIKE ?")
                        params.append(f"%{village_q.strip()}%")
                    if land_id_q and land_id_q.strip():
                        if land_id_q.strip().isdigit():
                            conditions.append("id = ?")
                            params.append(int(land_id_q.strip()))
                        else:
                            st.error("Land ID must be numeric.")
                            return
                    if not conditions:
                        st.info("Enter a transaction hash or at least one land search field (survey, owner, village, or land id).")
                        return
                    where_clause = " AND ".join(conditions)
                    sql = f"SELECT id, citizen_id, district, taluka, village, survey_no, area_sqft, land_type, owner_name, owner_aadhaar, status, tx_hash, timestamp FROM lands WHERE {where_clause} ORDER BY id DESC"
                    c.execute(sql, tuple(params))
                    lands = c.fetchall()
                    if not lands:
                        st.warning("No land records found matching the criteria.")
                    else:
                        st.success(f"Found {len(lands)} land record(s).")
                        for land in lands:
                            lid = land[0]
                            district = land[2]
                            taluka = land[3]
                            village = land[4]
                            survey_no = land[5]
                            owner_name = land[8]
                            status = land[10]
                            tx_hash = land[11]
                            with st.expander(f"Land ID {lid} — {district}/{taluka}/{village} | Survey: {survey_no}"):
                                st.write({
                                    "land_id": lid,
                                    "district": district,
                                    "taluka": taluka,
                                    "village": village,
                                    "survey_no": survey_no,
                                    "owner_name": owner_name,
                                    "status": status,
                                    "tx_hash": tx_hash or "None"
                                })
                                if tx_hash:
                                    st.markdown("**Verified on blockchain (mock)**")
                                    if st.button(f"View TX for land {lid}", key=f"viewtx_{lid}"):
                                        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn2:
                                            c2 = conn2.cursor()
                                            c2.execute("SELECT id, tx_hash, action, details, timestamp FROM blockchain_tx WHERE tx_hash = ?", (tx_hash,))
                                            trow = c2.fetchone()
                                        if trow:
                                            display_public_tx(trow)
                                        else:
                                            st.error("TX hash stored on land but not found in blockchain_tx table.")
                                else:
                                    st.info("This land has no transaction hash yet (not approved).")

    with col_b:
        if st.button("Show Recent Transactions"):
            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                c = conn.cursor()
                c.execute("SELECT id, tx_hash, action, details, timestamp FROM blockchain_tx ORDER BY id DESC LIMIT 20")
                recent = c.fetchall()
            if not recent:
                st.info("No transactions recorded yet.")
            else:
                st.write(f"Showing recent {len(recent)} transaction(s):")
                for r in recent:
                    display_public_tx(r)

    st.markdown("---")
    with st.expander("Show All Transactions (public) — Click to expand"):
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute("SELECT id, tx_hash, action, details, timestamp FROM blockchain_tx ORDER BY id DESC")
            all_txs = c.fetchall()
        if not all_txs:
            st.info("No transactions recorded yet.")
        else:
            rows = [
                {
                    "ID": t[0],
                    "TX Hash (truncated)": (t[1][:32] + "..." if len(t[1]) > 32 else t[1]),
                    "Action": t[2],
                    "Timestamp": t[4]
                }
                for t in all_txs
            ]
            st.dataframe(rows, height=300)
            st.markdown("Expand items below for full details:")
            for t in all_txs:
                display_public_tx(t)

# ---------------------------
# Admin flows
# ---------------------------
def admin_login():
    st.header("Admin Login (2FA required)")
    if st.session_state.admin_logged_in:
        admin_dashboard()
        return

    with st.form("admin_login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        totp_code = st.text_input("2FA Code")
        submitted = st.form_submit_button("Sign In")
        if submitted:
            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                c = conn.cursor()
                c.execute("SELECT id, password_hash, totp_secret, role FROM admins WHERE email = ? AND active = 1", (email,))
                row = c.fetchone()
            if not row:
                st.error("Invalid credentials.")
                return
            admin_id, pw_hash, totp_secret, role = row
            if not verify_password(password, pw_hash):
                st.error("Invalid credentials.")
                return
            try:
                totp = pyotp.TOTP(totp_secret)
                if totp.verify(totp_code):
                    st.session_state.admin_logged_in = True
                    st.session_state.admin_id = admin_id
                    st.session_state.role = role
                    log_audit(admin_id, 'login', f'Admin {email} logged in')
                    st.success("Admin logged in.")
                    safe_rerun()
                else:
                    st.error("Invalid 2FA code.")
            except Exception:
                st.error("Error verifying TOTP. Check admin TOTP configuration.")

def admin_dashboard():
    st.header("Admin Dashboard")
    if not st.session_state.admin_logged_in:
        st.error("Please login as admin.")
        return

    admin_id = st.session_state.admin_id
    role = st.session_state.role

    col1, col2 = st.columns([3,1])
    with col1:
        st.subheader("System Health")
        st.write("Blockchain (mock): OK")
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending'")
            pending = c.fetchone()[0]
        st.write(f"Pending Approvals: {pending}")
    with col2:
        if st.button("Logout Admin"):
            log_audit(admin_id, 'logout', f'Admin id {admin_id} logged out')
            st.session_state.admin_logged_in = False
            st.session_state.admin_id = None
            st.session_state.role = None
            safe_rerun()

    tab_pending, tab_users, tab_audit, tab_tx, tab_alltx, tab_sim = st.tabs(
        ["Pending Approvals", "Users", "Audit Logs", "Blockchain Tx", "All Transactions", "Simulate TX"]
    )

    # Pending approvals
    with tab_pending:
        st.subheader("Pending Approvals")
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute("""SELECT p.id, p.type, p.details, p.timestamp, l.id, l.district, l.taluka, l.village
                         FROM pending_approvals p
                         JOIN lands l ON p.land_id = l.id
                         WHERE p.status = 'pending'""")
            approvals = c.fetchall()

        if not approvals:
            st.info("No pending approvals.")
        else:
            for ap in approvals:
                p_id, p_type, p_details, p_ts, land_id, district, taluka, village = ap
                parsed = parse_details(p_details)
                display_details = parsed if parsed is not None else p_details
                with st.expander(f"Approval {p_id}: {p_type} — {district}/{taluka}/{village}"):
                    st.write("Raw details:", p_details)
                    st.write("Parsed details:", display_details)
                    st.write(f"Submitted at: {p_ts}")
                    action = st.selectbox("Action", ["", "Approve", "Reject"], key=f"action_{p_id}")
                    remarks = st.text_area("Remarks", key=f"remarks_{p_id}")
                    if st.button("Submit", key=f"submit_{p_id}"):
                        # Approach: commit minimal changes before calling record_transaction
                        if action == "Approve":
                            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                                c = conn.cursor()
                                c.execute("UPDATE pending_approvals SET status = 'processing' WHERE id = ?", (p_id,))
                                conn.commit()

                            tx_hash = blockchain.record_transaction(p_type, p_details)

                            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn2:
                                c2 = conn2.cursor()
                                if p_type == 'transfer':
                                    details_obj = parse_details(p_details)
                                    if details_obj and "land_id" in details_obj:
                                        t_land_id = details_obj.get("land_id")
                                        new_name = details_obj.get("new_owner_name")
                                        new_aadhaar = details_obj.get("new_owner_aadhaar")
                                        c2.execute("UPDATE lands SET owner_name = ?, owner_aadhaar = ?, status = 'transferred', tx_hash = ? WHERE id = ?",
                                                   (new_name, new_aadhaar, tx_hash, t_land_id))
                                    else:
                                        c2.execute("UPDATE lands SET status = 'approved', tx_hash = ? WHERE id = (SELECT land_id FROM pending_approvals WHERE id = ?)",
                                                   (tx_hash, p_id))
                                else:
                                    c2.execute("UPDATE lands SET status = 'approved', tx_hash = ? WHERE id = (SELECT land_id FROM pending_approvals WHERE id = ?)",
                                               (tx_hash, p_id))

                                c2.execute("UPDATE pending_approvals SET status = 'approved', admin_remarks = ? WHERE id = ?", (remarks, p_id))
                                conn2.commit()
                                log_audit(admin_id, 'approve', f'Approved {p_type} id={p_id} tx={tx_hash}')
                            st.success(f"Approved. TX: {tx_hash}")
                            safe_rerun()

                        elif action == "Reject":
                            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                                c = conn.cursor()
                                c.execute("UPDATE pending_approvals SET status = 'rejected', admin_remarks = ? WHERE id = ?", (remarks, p_id))
                                c.execute("UPDATE lands SET status = 'rejected' WHERE id = (SELECT land_id FROM pending_approvals WHERE id = ?)", (p_id,))
                                conn.commit()
                                log_audit(admin_id, 'reject', f'Rejected id={p_id} remarks={remarks}')
                            st.success("Rejected.")
                            safe_rerun()
                        else:
                            st.error("Select an action first.")

    # Users tab
    with tab_users:
        st.subheader("Citizens & Admins")
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute("SELECT id, email, name, aadhaar, active FROM citizens ORDER BY id DESC")
            citizens = c.fetchall()

        st.markdown("**Citizens**")
        if not citizens:
            st.write("No citizens.")
        else:
            for cit in citizens:
                cid, email, name, aadhaar, active = cit
                cols = st.columns([3,1,1])
                with cols[0]:
                    st.write(f"**{name}** — {email}")
                    st.write(f"Aadhaar: {aadhaar}")
                with cols[1]:
                    if active:
                        if st.button(f"Deactivate {cid}", key=f"deact_{cid}"):
                            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                                c = conn.cursor()
                                c.execute("UPDATE citizens SET active = 0 WHERE id = ?", (cid,))
                                conn.commit()
                                log_audit(admin_id, 'deactivate_citizen', f'citizen_id={cid}')
                            safe_rerun()
                    else:
                        if st.button(f"Activate {cid}", key=f"act_{cid}"):
                            with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                                c = conn.cursor()
                                c.execute("UPDATE citizens SET active = 1 WHERE id = ?", (cid,))
                                conn.commit()
                                log_audit(admin_id, 'activate_citizen', f'citizen_id={cid}')
                            safe_rerun()
                with cols[2]:
                    if st.button(f"ResetPW {cid}", key=f"reset_{cid}"):
                        new_pw = "citizen_reset123"
                        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                            c = conn.cursor()
                            c.execute("UPDATE citizens SET password_hash = ? WHERE id = ?", (hash_password(new_pw), cid))
                            conn.commit()
                            log_audit(admin_id, 'reset_pw', f'citizen_id={cid}')
                        st.success(f"Password reset to {new_pw} (communicate securely).")

        st.markdown("---")
        st.subheader("Admins")
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute("SELECT id, email, role, active FROM admins ORDER BY id DESC")
            admins = c.fetchall()

        for a in admins:
            aid, aemail, arole, aactive = a
            cols = st.columns([3,1])
            with cols[0]:
                st.write(f"**{aemail}** — Role: {arole}")
            with cols[1]:
                if aactive:
                    if st.button(f"Deactivate Admin {aid}", key=f"deact_admin_{aid}"):
                        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                            c = conn.cursor()
                            c.execute("UPDATE admins SET active = 0 WHERE id = ?", (aid,))
                            conn.commit()
                            log_audit(admin_id, 'deactivate_admin', f'admin_id={aid}')
                        safe_rerun()
                else:
                    if st.button(f"Activate Admin {aid}", key=f"act_admin_{aid}"):
                        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                            c = conn.cursor()
                            c.execute("UPDATE admins SET active = 1 WHERE id = ?", (aid,))
                            conn.commit()
                            log_audit(admin_id, 'activate_admin', f'admin_id={aid}')
                        safe_rerun()

    # Audit logs tab
    with tab_audit:
        st.subheader("Audit Logs (last 500)")
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute("SELECT id, admin_id, action, details, timestamp FROM audit_logs ORDER BY id DESC LIMIT 500")
            logs = c.fetchall()
        if not logs:
            st.info("No logs.")
        else:
            for lg in logs:
                lid, ladm, laction, ldetails, lts = lg
                st.write(f"{lts} — Admin:{ladm} — {laction} — {ldetails}")

    # Blockchain tx tab
    with tab_tx:
        st.subheader("Blockchain Transactions (mock)")
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute("SELECT id, tx_hash, action, details, timestamp FROM blockchain_tx ORDER BY id DESC")
            txs = c.fetchall()
        if not txs:
            st.info("No transactions.")
        else:
            for t in txs:
                st.write(f"TX {t[0]} — {t[1]} — {t[2]} — {t[4]}")
                st.caption(t[3])
        if txs:
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["id", "tx_hash", "action", "details", "timestamp"])
            for t in txs:
                writer.writerow(list(t))
            st.download_button("Download TX CSV", buffer.getvalue(), file_name="blockchain_tx.csv", mime="text/csv")

    # All Transactions admin view
    with tab_alltx:
        st.subheader("All Transaction IDs (Admin)")
        with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
            c = conn.cursor()
            c.execute("SELECT id, tx_hash, action, details, timestamp FROM blockchain_tx ORDER BY id DESC")
            all_txs = c.fetchall()
        if not all_txs:
            st.info("No blockchain transactions recorded yet.")
        else:
            rows = [{"ID": t[0], "TX Hash": t[1], "Action": t[2], "Timestamp": t[4]} for t in all_txs]
            st.write("Total transactions:", len(rows))
            st.dataframe(rows, height=300)
            st.markdown("**Click an ID to expand details**")
            for t in all_txs:
                tid, thash, taction, tdetails, tts = t
                with st.expander(f"TX ID {tid} — {thash[:16]}... ({taction}) — {tts}"):
                    st.write(f"**TX Hash:** `{thash}`")
                    parsed = None
                    try:
                        parsed = json.loads(tdetails) if tdetails else None
                    except Exception:
                        parsed = None
                    if parsed is not None:
                        st.json(parsed)
                    else:
                        st.write("Details (raw):")
                        st.code(tdetails or "")
                    st.text_area("Copy TX Hash", value=thash, height=40, key=f"copy_admin_{tid}")
                    with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                        c = conn.cursor()
                        c.execute("SELECT id, district, taluka, village, survey_no FROM lands WHERE tx_hash = ?", (thash,))
                        linked = c.fetchone()
                    if linked:
                        st.write("Linked Land:")
                        st.write({
                            "land_id": linked[0],
                            "district": linked[1],
                            "taluka": linked[2],
                            "village": linked[3],
                            "survey_no": linked[4]
                        })
                    else:
                        st.write("No linked land found for this TX hash.")

    # Simulate TX tab
    with tab_sim:
        st.subheader("Simulate Blockchain TX (Admin)")
        sim_action = st.text_input("Action")
        sim_details = st.text_area("Details")
        if st.button("Record Simulated TX"):
            if not sim_action or not sim_details:
                st.error("Provide action and details.")
            else:
                tx_hash = blockchain.record_transaction(sim_action, sim_details)
                log_audit(admin_id, 'simulate_tx', f'tx={tx_hash} action={sim_action}')
                st.success(f"Recorded TX: {tx_hash}")
                safe_rerun()

# ---------------------------
# Create admin UI
# ---------------------------
def create_admin_ui():
    st.header("Create New Admin (TOTP printed to terminal)")
    with st.form("create_admin_form"):
        email = st.text_input("Admin Email")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["ADMIN", "SUPER_ADMIN"])
        submit = st.form_submit_button("Create Admin")
        if submit:
            if not (email and password):
                st.error("Fill email and password.")
                return
            totp_secret = pyotp.random_base32()
            pw_hash = hash_password(password)
            try:
                with sqlite3.connect(DB_FILE, timeout=SQLITE_TIMEOUT) as conn:
                    c = conn.cursor()
                    c.execute("INSERT INTO admins (email, password_hash, role, totp_secret) VALUES (?, ?, ?, ?)",
                              (email, pw_hash, role, totp_secret))
                    conn.commit()
                st.success("Admin created. TOTP secret printed in terminal where Streamlit is running.")
                print("\n==============================")
                print("New Admin Created")
                print(f"Email: {email}")
                print(f"Password: {password}")
                print(f"TOTP Secret Code: {totp_secret}")
                print("Add this secret in your authenticator app (Google Authenticator / Authy).")
                print("==============================\n")
            except sqlite3.IntegrityError:
                st.error("Email already exists.")

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    main()
