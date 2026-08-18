"""
Chama Manager — Multi-Tenant MVP
Python + Streamlit + SQLAlchemy (SQLite locally, Postgres in production)

Each Chama (savings group) signs up for its own account and only ever
sees its own members, contributions, and payouts.

Run locally (uses a local SQLite file automatically):
    pip install streamlit pandas sqlalchemy bcrypt requests
    streamlit run app.py

Run against a hosted Postgres database (e.g. Supabase / Neon / Railway):
    Add this to .streamlit/secrets.toml (or your host's "Secrets" settings):
        DATABASE_URL = "postgresql://user:password@host:5432/dbname"
    (Also: pip install psycopg2-binary)

Optional M-Pesa Daraja integration (STK Push):
    Add these secrets once you have a Safaricom Daraja app (sandbox or production):
        MPESA_CONSUMER_KEY = "..."
        MPESA_CONSUMER_SECRET = "..."
        MPESA_SHORTCODE = "174379"          # Paybill/Till number (sandbox default shown)
        MPESA_PASSKEY = "..."
        MPESA_ENV = "sandbox"                # or "production"
    Without these secrets, the M-Pesa section simply stays hidden/disabled —
    every other part of the app works exactly the same.
"""

import base64
import hashlib
import hmac
import os
from datetime import date, datetime

import pandas as pd
import requests
import streamlit as st
from sqlalchemy import create_engine, text

LATE_FINE = 200

# ----------------------------------------------------------------------------
# Database engine — Postgres if DATABASE_URL is configured, SQLite otherwise
# ----------------------------------------------------------------------------

@st.cache_resource
def get_engine():
    db_url = None
    try:
        db_url = st.secrets["DATABASE_URL"]
    except Exception:
        db_url = os.environ.get("DATABASE_URL")

    if db_url:
        return create_engine(db_url, pool_pre_ping=True, pool_recycle=300, pool_size=5, max_overflow=5)
    return create_engine("sqlite:///chama.db", connect_args={"check_same_thread": False})


engine = get_engine()
IS_SQLITE = engine.url.get_backend_name() == "sqlite"

AUTOINCREMENT_PK = "INTEGER PRIMARY KEY AUTOINCREMENT" if IS_SQLITE else "SERIAL PRIMARY KEY"


def _try_alter(table, column, coltype):
    """Add a column if it doesn't exist yet. Isolated transaction per attempt
    so a 'column already exists' failure never rolls back other migrations."""
    try:
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))
    except Exception:
        pass


def init_db():
    with engine.begin() as conn:
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS chamas (
                id {AUTOINCREMENT_PK},
                chama_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """))
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS members (
                id {AUTOINCREMENT_PK},
                chama_id INTEGER NOT NULL,
                full_name TEXT NOT NULL,
                phone_number TEXT,
                monthly_target REAL NOT NULL DEFAULT 2000
            )
        """))
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS contributions (
                id {AUTOINCREMENT_PK},
                chama_id INTEGER NOT NULL,
                member_id INTEGER NOT NULL,
                amount_paid REAL NOT NULL,
                payment_date TEXT NOT NULL,
                month_year TEXT NOT NULL,
                fine_paid REAL NOT NULL DEFAULT 0,
                payment_method TEXT DEFAULT 'Cash'
            )
        """))
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS payouts (
                id {AUTOINCREMENT_PK},
                chama_id INTEGER NOT NULL,
                member_id INTEGER NOT NULL,
                payout_date TEXT NOT NULL,
                amount REAL NOT NULL,
                month_year TEXT NOT NULL
            )
        """))
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS meetings (
                id {AUTOINCREMENT_PK},
                chama_id INTEGER NOT NULL,
                meeting_date TEXT NOT NULL,
                location TEXT,
                note TEXT,
                created_at TEXT NOT NULL
            )
        """))
        conn.execute(text(f"""
            CREATE TABLE IF NOT EXISTS mpesa_transactions (
                id {AUTOINCREMENT_PK},
                chama_id INTEGER NOT NULL,
                member_id INTEGER NOT NULL,
                checkout_request_id TEXT,
                merchant_request_id TEXT,
                amount REAL NOT NULL,
                phone_number TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            )
        """))

    # Columns added after the first release — safe to run every startup.
    _try_alter("contributions", "fine_waived", "INTEGER DEFAULT 0")
    _try_alter("contributions", "waiver_reason", "TEXT")


# ----------------------------------------------------------------------------
# Auth helpers — salted SHA-256. Good enough for an MVP; swap for bcrypt
# (already installed) via passlib or `bcrypt.hashpw` before real launch.
# ----------------------------------------------------------------------------

def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()


def create_chama_account(chama_name, username, password):
    salt = os.urandom(16).hex()
    pw_hash = hash_password(password, salt)
    with engine.begin() as conn:
        existing = conn.execute(
            text("SELECT id FROM chamas WHERE username = :u"), {"u": username}
        ).fetchone()
        if existing:
            return None, "That username is already taken. Try another."
        result = conn.execute(
            text("""
                INSERT INTO chamas (chama_name, username, password_hash, password_salt, created_at)
                VALUES (:name, :user, :hash, :salt, :created)
            """ + ("" if IS_SQLITE else " RETURNING id")),
            {
                "name": chama_name,
                "user": username,
                "hash": pw_hash,
                "salt": salt,
                "created": date.today().isoformat(),
            },
        )
        if IS_SQLITE:
            new_id = conn.execute(text("SELECT last_insert_rowid()")).scalar()
        else:
            new_id = result.fetchone()[0]
    return new_id, None


def verify_login(username, password):
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id, chama_name, password_hash, password_salt FROM chamas WHERE username = :u"),
            {"u": username},
        ).fetchone()
    if not row:
        return None, "No account found with that username."
    chama_id, chama_name, pw_hash, salt = row
    candidate_hash = hash_password(password, salt)
    if hmac.compare_digest(candidate_hash, pw_hash):
        return {"id": chama_id, "name": chama_name}, None
    return None, "Incorrect password."


# ----------------------------------------------------------------------------
# Data access — every query is scoped to the logged-in chama_id.
# Reads are cached briefly (15s); every write clears the cache.
# ----------------------------------------------------------------------------

def _run_read(query, params=None):
    with engine.begin() as conn:
        return pd.read_sql_query(text(query), conn, params=params or {})


@st.cache_data(ttl=15)
def fetch_df_cached(query, params_tuple):
    return _run_read(query, dict(params_tuple))


def fetch_df(query, params=None):
    params = params or {}
    return fetch_df_cached(query, tuple(sorted(params.items())))


def run_write(query, params):
    with engine.begin() as conn:
        conn.execute(text(query), params)
    st.cache_data.clear()


def get_members_df(chama_id):
    return fetch_df("SELECT * FROM members WHERE chama_id = :cid ORDER BY id", {"cid": chama_id})


def current_month_year():
    return date.today().strftime("%Y-%m")


def add_member(chama_id, full_name, phone_number, monthly_target):
    run_write(
        "INSERT INTO members (chama_id, full_name, phone_number, monthly_target) "
        "VALUES (:cid, :name, :phone, :target)",
        {"cid": chama_id, "name": full_name, "phone": phone_number, "target": monthly_target},
    )


def update_member(chama_id, member_id, full_name, phone_number, monthly_target):
    run_write(
        """
        UPDATE members SET full_name = :name, phone_number = :phone, monthly_target = :target
        WHERE id = :mid AND chama_id = :cid
        """,
        {"name": full_name, "phone": phone_number, "target": monthly_target, "mid": member_id, "cid": chama_id},
    )


def delete_member(chama_id, member_id):
    run_write("DELETE FROM contributions WHERE member_id = :mid AND chama_id = :cid", {"mid": member_id, "cid": chama_id})
    run_write("DELETE FROM payouts WHERE member_id = :mid AND chama_id = :cid", {"mid": member_id, "cid": chama_id})
    run_write("DELETE FROM mpesa_transactions WHERE member_id = :mid AND chama_id = :cid", {"mid": member_id, "cid": chama_id})
    run_write("DELETE FROM members WHERE id = :mid AND chama_id = :cid", {"mid": member_id, "cid": chama_id})


def add_contribution(chama_id, member_id, amount_paid, payment_date, month_year, is_late, payment_method):
    fine = LATE_FINE if is_late else 0
    run_write(
        """
        INSERT INTO contributions
            (chama_id, member_id, amount_paid, payment_date, month_year, fine_paid, payment_method, fine_waived)
        VALUES (:cid, :mid, :amount, :pdate, :myear, :fine, :method, 0)
        """,
        {
            "cid": chama_id, "mid": member_id, "amount": amount_paid, "pdate": payment_date,
            "myear": month_year, "fine": fine, "method": payment_method,
        },
    )


def waive_fine(chama_id, contribution_id, reason):
    run_write(
        "UPDATE contributions SET fine_waived = 1, waiver_reason = :reason "
        "WHERE id = :cid_row AND chama_id = :cid",
        {"reason": reason, "cid_row": contribution_id, "cid": chama_id},
    )


def add_payout(chama_id, member_id, payout_date, amount, month_year):
    run_write(
        "INSERT INTO payouts (chama_id, member_id, payout_date, amount, month_year) "
        "VALUES (:cid, :mid, :pdate, :amount, :myear)",
        {"cid": chama_id, "mid": member_id, "pdate": payout_date, "amount": amount, "myear": month_year},
    )


def set_meeting(chama_id, meeting_date, location, note):
    run_write(
        "INSERT INTO meetings (chama_id, meeting_date, location, note, created_at) "
        "VALUES (:cid, :mdate, :loc, :note, :created)",
        {"cid": chama_id, "mdate": meeting_date, "loc": location, "note": note, "created": date.today().isoformat()},
    )


def get_latest_meeting(chama_id):
    df = fetch_df("SELECT * FROM meetings WHERE chama_id = :cid ORDER BY id DESC LIMIT 1", {"cid": chama_id})
    return None if df.empty else df.iloc[0]


# ----------------------------------------------------------------------------
# M-Pesa Daraja (STK Push) — optional, only active if secrets are configured.
# Uses polling via the STK Push Query API instead of a webhook callback,
# since Streamlit apps don't expose a public endpoint to receive callbacks on.
# ----------------------------------------------------------------------------

def get_mpesa_config():
    try:
        secrets = st.secrets
    except Exception:
        return None
    required = ["MPESA_CONSUMER_KEY", "MPESA_CONSUMER_SECRET", "MPESA_SHORTCODE", "MPESA_PASSKEY"]
    if not all(k in secrets for k in required):
        return None
    return {
        "consumer_key": secrets["MPESA_CONSUMER_KEY"],
        "consumer_secret": secrets["MPESA_CONSUMER_SECRET"],
        "shortcode": secrets["MPESA_SHORTCODE"],
        "passkey": secrets["MPESA_PASSKEY"],
        "env": secrets.get("MPESA_ENV", "sandbox"),
    }


def _mpesa_base_url(env):
    return "https://api.safaricom.co.ke" if env == "production" else "https://sandbox.safaricom.co.ke"


def get_mpesa_access_token(config):
    url = f"{_mpesa_base_url(config['env'])}/oauth/v1/generate?grant_type=client_credentials"
    resp = requests.get(url, auth=(config["consumer_key"], config["consumer_secret"]), timeout=15)
    resp.raise_for_status()
    return resp.json()["access_token"]


def _normalize_phone(phone):
    phone = phone.strip().replace(" ", "").replace("+", "")
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    return phone


def initiate_stk_push(config, phone_number, amount, account_reference, description):
    token = get_mpesa_access_token(config)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password = base64.b64encode(
        f"{config['shortcode']}{config['passkey']}{timestamp}".encode()
    ).decode()

    payload = {
        "BusinessShortCode": config["shortcode"],
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(amount),
        "PartyA": _normalize_phone(phone_number),
        "PartyB": config["shortcode"],
        "PhoneNumber": _normalize_phone(phone_number),
        "CallBackURL": "https://example.com/mpesa/callback",  # not used — we poll instead
        "AccountReference": account_reference[:12],
        "TransactionDesc": description[:13],
    }
    url = f"{_mpesa_base_url(config['env'])}/mpesa/stkpush/v1/processrequest"
    resp = requests.post(
        url, json=payload, headers={"Authorization": f"Bearer {token}"}, timeout=15
    )
    resp.raise_for_status()
    return resp.json()


def query_stk_status(config, checkout_request_id):
    token = get_mpesa_access_token(config)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password = base64.b64encode(
        f"{config['shortcode']}{config['passkey']}{timestamp}".encode()
    ).decode()
    payload = {
        "BusinessShortCode": config["shortcode"],
        "Password": password,
        "Timestamp": timestamp,
        "CheckoutRequestID": checkout_request_id,
    }
    url = f"{_mpesa_base_url(config['env'])}/mpesa/stkpushquery/v1/query"
    resp = requests.post(
        url, json=payload, headers={"Authorization": f"Bearer {token}"}, timeout=15
    )
    resp.raise_for_status()
    return resp.json()


def record_mpesa_request(chama_id, member_id, checkout_request_id, merchant_request_id, amount, phone_number):
    run_write(
        """
        INSERT INTO mpesa_transactions
            (chama_id, member_id, checkout_request_id, merchant_request_id, amount, phone_number, status, created_at)
        VALUES (:cid, :mid, :checkout, :merchant, :amount, :phone, 'pending', :created)
        """,
        {
            "cid": chama_id, "mid": member_id, "checkout": checkout_request_id, "merchant": merchant_request_id,
            "amount": amount, "phone": phone_number, "created": datetime.now().isoformat(),
        },
    )


def update_mpesa_status(chama_id, transaction_id, status):
    run_write(
        "UPDATE mpesa_transactions SET status = :status WHERE id = :tid AND chama_id = :cid",
        {"status": status, "tid": transaction_id, "cid": chama_id},
    )


def get_pending_mpesa(chama_id):
    return fetch_df(
        """
        SELECT t.*, m.full_name FROM mpesa_transactions t
        JOIN members m ON m.id = t.member_id
        WHERE t.chama_id = :cid AND t.status = 'pending'
        ORDER BY t.id DESC
        """,
        {"cid": chama_id},
    )


# ----------------------------------------------------------------------------
# App shell
# ----------------------------------------------------------------------------

st.set_page_config(page_title="Chama Manager", page_icon="💰", layout="wide")
init_db()

if "chama" not in st.session_state:
    st.session_state.chama = None

if st.session_state.chama is None:
    st.title("💰 Chama Manager")
    st.caption("Sign in to your Chama's account, or create a new one.")

    login_tab, signup_tab = st.tabs(["Sign In", "Create a New Chama Account"])

    with login_tab:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Sign In"):
                chama, error = verify_login(username.strip(), password)
                if error:
                    st.error(error)
                else:
                    st.session_state.chama = chama
                    st.rerun()

    with signup_tab:
        with st.form("signup_form"):
            new_chama_name = st.text_input("Chama Name")
            new_username = st.text_input("Choose a Username")
            new_password = st.text_input("Choose a Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            if st.form_submit_button("Create Account"):
                if not (new_chama_name and new_username and new_password):
                    st.error("All fields are required.")
                elif new_password != confirm_password:
                    st.error("Passwords don't match.")
                elif len(new_password) < 6:
                    st.error("Password should be at least 6 characters.")
                else:
                    new_id, error = create_chama_account(
                        new_chama_name.strip(), new_username.strip(), new_password
                    )
                    if error:
                        st.error(error)
                    else:
                        st.success("Account created! Please sign in on the 'Sign In' tab.")

    st.stop()

chama_id = st.session_state.chama["id"]
chama_name = st.session_state.chama["name"]
mpesa_config = get_mpesa_config()

top_left, top_right = st.columns([5, 1])
with top_left:
    st.title(f"💰 {chama_name}")
    st.caption("Member tracking, contributions, merry-go-round payouts and fines.")
with top_right:
    st.write("")
    if st.button("Log Out"):
        st.session_state.chama = None
        st.rerun()

tab_overview, tab_payment, tab_payout, tab_member, tab_reminders = st.tabs(
    ["📊 Dashboard Overview", "💵 Record Payment", "🔄 Merry-Go-Round Payouts", "👤 Members", "📢 Reminders & Meetings"]
)

# --------------------------------------------------------------------------
# TAB 1 — Dashboard Overview
# --------------------------------------------------------------------------
with tab_overview:
    members_df = get_members_df(chama_id)
    contributions_df = fetch_df("SELECT * FROM contributions WHERE chama_id = :cid", {"cid": chama_id})
    payouts_df = fetch_df("SELECT * FROM payouts WHERE chama_id = :cid", {"cid": chama_id})

    this_month = current_month_year()
    active_months = contributions_df["month_year"].nunique() if not contributions_df.empty else 0

    effective_fines = (
        contributions_df.loc[contributions_df["fine_waived"] != 1, "fine_paid"].sum()
        if not contributions_df.empty else 0
    )
    total_savings = contributions_df["amount_paid"].sum() if not contributions_df.empty else 0
    total_paid_out = payouts_df["amount"].sum() if not payouts_df.empty else 0
    net_pot = total_savings - total_paid_out

    if not members_df.empty:
        paid_this_month_ids = set()
        if not contributions_df.empty:
            paid_this_month_ids = set(
                contributions_df.loc[contributions_df["month_year"] == this_month, "member_id"]
            )
        pending_count = len(members_df) - len(paid_this_month_ids & set(members_df["id"]))
    else:
        pending_count = 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Group Savings", f"KES {total_savings:,.0f}")
    col2.metric("Total Fines Collected", f"KES {effective_fines:,.0f}")
    col3.metric(f"Pending — {this_month}", f"{pending_count} member(s)")
    col4.metric("Net Pot (after payouts)", f"KES {net_pot:,.0f}")

    st.divider()
    st.subheader("Member Status & Balances")
    st.caption(
        "Balance compares each member's total contributions against their target × "
        f"{active_months} active month(s) recorded so far. Negative = still owing, positive = credit / overpaid."
    )

    if members_df.empty:
        st.info("No members yet. Add members in the 'Members' tab to get started.")
    else:
        status_rows = []
        for _, m in members_df.iterrows():
            member_all = contributions_df[contributions_df["member_id"] == m["id"]] if not contributions_df.empty else pd.DataFrame()
            member_this_month = member_all[member_all["month_year"] == this_month] if not member_all.empty else pd.DataFrame()

            paid_this_month = member_this_month["amount_paid"].sum() if not member_this_month.empty else 0
            fine_this_month = (
                member_this_month.loc[member_this_month["fine_waived"] != 1, "fine_paid"].sum()
                if not member_this_month.empty else 0
            )
            total_paid_alltime = member_all["amount_paid"].sum() if not member_all.empty else 0
            expected_alltime = m["monthly_target"] * active_months
            balance = total_paid_alltime - expected_alltime

            status = "✅ Paid" if paid_this_month >= m["monthly_target"] else (
                "🟡 Partial" if paid_this_month > 0 else "🔴 Pending"
            )
            balance_label = (
                f"+{balance:,.0f} credit" if balance > 0 else
                (f"{balance:,.0f} owing" if balance < 0 else "Settled")
            )
            status_rows.append(
                {
                    "Member": m["full_name"], "This Month Paid": paid_this_month, "Target": m["monthly_target"],
                    "Status": status, "Fine (This Month)": fine_this_month, "Overall Balance": balance_label,
                }
            )
        status_df = pd.DataFrame(status_rows)
        st.dataframe(status_df, use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Download this table as CSV", status_df.to_csv(index=False).encode("utf-8"),
            file_name=f"{chama_name}_status_{this_month}.csv", mime="text/csv",
        )

# --------------------------------------------------------------------------
# TAB 2 — Record Payment
# --------------------------------------------------------------------------
with tab_payment:
    st.subheader("Record a Contribution")
    members_df = get_members_df(chama_id)

    if members_df.empty:
        st.warning("Add at least one member first (see the 'Members' tab).")
    else:
        with st.form("payment_form", clear_on_submit=True):
            member_map = dict(zip(members_df["full_name"], members_df["id"]))
            selected_name = st.selectbox("Member", options=list(member_map.keys()))
            amount = st.number_input("Amount Paid (KES)", min_value=0.0, step=100.0, value=2000.0)
            payment_date = st.date_input("Payment Date", value=date.today())
            month_year = st.text_input("Month/Year (YYYY-MM)", value=current_month_year())
            payment_method = st.selectbox("Payment Method", ["M-Pesa", "Cash", "Bank"])
            is_late = st.checkbox(f"Is payment late? (Applies KES {LATE_FINE} fine)")

            submitted = st.form_submit_button("💾 Save Payment")

            if submitted:
                member_id = member_map[selected_name]
                add_contribution(chama_id, member_id, amount, payment_date.isoformat(), month_year, is_late, payment_method)
                fine_note = f" (+ KES {LATE_FINE} late fine)" if is_late else ""
                st.toast(f"Payment of KES {amount:,.0f} recorded for {selected_name}{fine_note} ✅", icon="✅")
                st.success(f"Saved: {selected_name} — KES {amount:,.0f} for {month_year}{fine_note}")

    # ------------------------------------------------------------------
    # M-Pesa STK Push — only shows up once MPESA_* secrets are configured
    # ------------------------------------------------------------------
    st.divider()
    st.subheader("📱 Request Payment via M-Pesa")
    if mpesa_config is None:
        st.info(
            "M-Pesa isn't configured yet. Add `MPESA_CONSUMER_KEY`, `MPESA_CONSUMER_SECRET`, "
            "`MPESA_SHORTCODE`, and `MPESA_PASSKEY` to your app's Secrets to enable this — "
            "see the top of app.py for the exact format."
        )
    elif members_df.empty:
        st.warning("Add at least one member first.")
    else:
        with st.form("mpesa_form"):
            member_map = dict(zip(members_df["full_name"], members_df["id"]))
            phone_map = dict(zip(members_df["full_name"], members_df["phone_number"]))
            mpesa_name = st.selectbox("Member", options=list(member_map.keys()), key="mpesa_member")
            mpesa_phone = st.text_input("Phone Number (M-Pesa)", value=phone_map.get(mpesa_name) or "")
            mpesa_amount = st.number_input("Amount (KES)", min_value=1.0, step=100.0, value=2000.0, key="mpesa_amount")
            send_clicked = st.form_submit_button("📲 Send Payment Prompt")

            if send_clicked:
                try:
                    result = initiate_stk_push(
                        mpesa_config, mpesa_phone, mpesa_amount,
                        account_reference=mpesa_name, description="Chama contribution",
                    )
                    checkout_id = result.get("CheckoutRequestID")
                    merchant_id = result.get("MerchantRequestID")
                    if checkout_id:
                        record_mpesa_request(chama_id, member_map[mpesa_name], checkout_id, merchant_id, mpesa_amount, mpesa_phone)
                        st.success(f"Payment prompt sent to {mpesa_name}'s phone. Ask them to enter their M-Pesa PIN.")
                    else:
                        st.error(f"Safaricom didn't return a request ID. Response: {result}")
                except requests.exceptions.RequestException as e:
                    st.error(f"Couldn't reach M-Pesa: {e}")
                except Exception as e:
                    st.error(f"Something went wrong sending the prompt: {e}")

        pending_df = get_pending_mpesa(chama_id)
        if not pending_df.empty:
            st.caption("**Pending M-Pesa requests** — click 'Check Status' after the member has entered their PIN.")
            for _, row in pending_df.iterrows():
                pcol1, pcol2 = st.columns([4, 1])
                pcol1.write(f"{row['full_name']} — KES {row['amount']:,.0f} ({row['phone_number']}) · sent {row['created_at'][:16]}")
                if pcol2.button("Check Status", key=f"check_{row['id']}"):
                    try:
                        status_result = query_stk_status(mpesa_config, row["checkout_request_id"])
                        result_code = str(status_result.get("ResultCode", ""))
                        if result_code == "0":
                            add_contribution(
                                chama_id, int(row["member_id"]), row["amount"], date.today().isoformat(),
                                current_month_year(), False, "M-Pesa",
                            )
                            update_mpesa_status(chama_id, int(row["id"]), "completed")
                            st.success(f"Confirmed! KES {row['amount']:,.0f} recorded for {row['full_name']}.")
                            st.rerun()
                        elif result_code in ("1032", "1"):
                            update_mpesa_status(chama_id, int(row["id"]), "cancelled")
                            st.warning("Payment was cancelled by the member.")
                            st.rerun()
                        else:
                            st.info(f"Still pending — {status_result.get('ResultDesc', 'no confirmation yet')}.")
                    except requests.exceptions.RequestException as e:
                        st.error(f"Couldn't reach M-Pesa: {e}")

    st.divider()
    st.subheader("Recent Contributions")
    contrib_view = fetch_df(
        """
        SELECT c.id, m.full_name AS member, c.amount_paid, c.fine_paid, c.fine_waived, c.waiver_reason,
               c.payment_method, c.payment_date, c.month_year
        FROM contributions c
        JOIN members m ON m.id = c.member_id
        WHERE c.chama_id = :cid
        ORDER BY c.id DESC
        LIMIT 50
        """,
        {"cid": chama_id},
    )
    if contrib_view.empty:
        st.info("No contributions recorded yet.")
    else:
        display_view = contrib_view.copy()
        display_view["fine_paid"] = display_view.apply(
            lambda r: "Waived" if r["fine_waived"] == 1 else r["fine_paid"], axis=1
        )
        st.dataframe(
            display_view.drop(columns=["fine_waived", "waiver_reason"]),
            use_container_width=True, hide_index=True,
        )
        st.download_button(
            "⬇️ Download contributions as CSV", contrib_view.to_csv(index=False).encode("utf-8"),
            file_name=f"{chama_name}_contributions.csv", mime="text/csv",
        )

        st.caption("**Waive a fine**")
        finable = contrib_view[(contrib_view["fine_paid"] > 0) & (contrib_view["fine_waived"] != 1)]
        if finable.empty:
            st.caption("No outstanding fines to waive.")
        else:
            fine_options = {
                f"#{r['id']} — {r['member']} — KES {r['fine_paid']:,.0f} ({r['month_year']})": r["id"]
                for _, r in finable.iterrows()
            }
            with st.form("waive_form"):
                fine_choice = st.selectbox("Contribution", options=list(fine_options.keys()))
                waiver_reason = st.text_input("Reason for waiving", placeholder="e.g. Was hospitalized, group agreed to waive")
                if st.form_submit_button("✅ Waive This Fine"):
                    waive_fine(chama_id, fine_options[fine_choice], waiver_reason.strip())
                    st.success("Fine waived.")
                    st.rerun()

# --------------------------------------------------------------------------
# TAB 3 — Merry-Go-Round Payouts
# --------------------------------------------------------------------------
with tab_payout:
    st.subheader("Rotation Queue")
    members_df = get_members_df(chama_id)
    payout_view = fetch_df(
        """
        SELECT p.id, p.member_id, m.full_name AS member, p.amount, p.payout_date, p.month_year
        FROM payouts p
        JOIN members m ON m.id = p.member_id
        WHERE p.chama_id = :cid
        ORDER BY p.id DESC
        """,
        {"cid": chama_id},
    )

    if members_df.empty:
        st.info("Add members first — the rotation queue follows the order they were added in.")
    else:
        paid_member_ids = set(payout_view["member_id"]) if not payout_view.empty else set()
        queue = members_df[~members_df["id"].isin(paid_member_ids)]
        if queue.empty:
            st.success("✅ Everyone has received a payout — the rotation is complete. Recording a new round starts it fresh.")
        else:
            queue_lines = [f"{i+1}. {row['full_name']}" + ("  ← next up" if i == 0 else "") for i, (_, row) in enumerate(queue.iterrows())]
            st.markdown("  \n".join(queue_lines))

    st.divider()
    st.subheader("Record a Payout")
    if members_df.empty:
        st.warning("Add at least one member first (see the 'Members' tab).")
    else:
        with st.form("payout_form", clear_on_submit=True):
            member_map = dict(zip(members_df["full_name"], members_df["id"]))
            selected_name = st.selectbox("Member to Pay Out", options=list(member_map.keys()), key="payout_member")
            payout_amount = st.number_input("Payout Amount (KES)", min_value=0.0, step=500.0, value=0.0)
            payout_date = st.date_input("Payout Date", value=date.today(), key="payout_date")
            month_year = st.text_input("Payout Month/Year (YYYY-MM)", value=current_month_year(), key="payout_month")

            submitted = st.form_submit_button("🎉 Mark as Paid Out")

            if submitted:
                member_id = member_map[selected_name]
                add_payout(chama_id, member_id, payout_date.isoformat(), payout_amount, month_year)
                st.toast(f"{selected_name} paid out KES {payout_amount:,.0f} for {month_year} 🎉", icon="🎉")
                st.success(f"Recorded payout: {selected_name} — KES {payout_amount:,.0f} ({month_year})")
                st.rerun()

    st.divider()
    st.subheader("Payout History")
    if payout_view.empty:
        st.info("No payouts recorded yet.")
    else:
        st.dataframe(payout_view.drop(columns=["member_id"]), use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Download payout history as CSV", payout_view.to_csv(index=False).encode("utf-8"),
            file_name=f"{chama_name}_payouts.csv", mime="text/csv",
        )

# --------------------------------------------------------------------------
# TAB 4 — Members (add, edit, delete)
# --------------------------------------------------------------------------
with tab_member:
    st.subheader("Add a New Member")

    with st.form("member_form", clear_on_submit=True):
        full_name = st.text_input("Full Name")
        phone_number = st.text_input("Phone Number (e.g. 0712345678)")
        monthly_target = st.number_input("Monthly Target (KES)", min_value=0.0, step=100.0, value=2000.0)

        submitted = st.form_submit_button("➕ Add Member")

        if submitted:
            if not full_name.strip():
                st.error("Full name is required.")
            else:
                add_member(chama_id, full_name.strip(), phone_number.strip(), monthly_target)
                st.toast(f"{full_name} added to the Chama ✅", icon="✅")
                st.success(f"Member added: {full_name}")

    st.divider()
    st.subheader("All Members — Edit or Remove")
    members_view = get_members_df(chama_id)

    if members_view.empty:
        st.info("No members yet.")
    else:
        st.download_button(
            "⬇️ Download member list as CSV", members_view.to_csv(index=False).encode("utf-8"),
            file_name=f"{chama_name}_members.csv", mime="text/csv",
        )
        for _, m in members_view.iterrows():
            with st.expander(f"{m['full_name']}  ·  KES {m['monthly_target']:,.0f}/month"):
                with st.form(f"edit_member_{m['id']}"):
                    edit_name = st.text_input("Full Name", value=m["full_name"], key=f"name_{m['id']}")
                    edit_phone = st.text_input("Phone Number", value=m["phone_number"] or "", key=f"phone_{m['id']}")
                    edit_target = st.number_input(
                        "Monthly Target (KES)", min_value=0.0, step=100.0,
                        value=float(m["monthly_target"]), key=f"target_{m['id']}"
                    )
                    save_col, delete_col = st.columns(2)
                    with save_col:
                        save_clicked = st.form_submit_button("💾 Save Changes")
                    with delete_col:
                        confirm_delete = st.checkbox("Confirm delete", key=f"confirm_{m['id']}")
                        delete_clicked = st.form_submit_button("🗑️ Remove Member")

                    if save_clicked:
                        if not edit_name.strip():
                            st.error("Full name is required.")
                        else:
                            update_member(chama_id, int(m["id"]), edit_name.strip(), edit_phone.strip(), edit_target)
                            st.success("Member updated.")
                            st.rerun()

                    if delete_clicked:
                        if not confirm_delete:
                            st.error("Tick 'Confirm delete' to remove this member. This also deletes their contribution and payout history.")
                        else:
                            delete_member(chama_id, int(m["id"]))
                            st.success(f"{m['full_name']} removed.")
                            st.rerun()

# --------------------------------------------------------------------------
# TAB 5 — Reminders & Meetings
# --------------------------------------------------------------------------
with tab_reminders:
    st.subheader("Set Next Meeting")
    st.caption("Set the next meeting date, location, and any note — this feeds the reminder messages below.")

    with st.form("meeting_form", clear_on_submit=True):
        meeting_date = st.date_input("Next Meeting Date", value=date.today())
        location = st.text_input("Location", placeholder="e.g. Members' WhatsApp group / Community Hall, Room 3")
        note = st.text_area("Note (optional)", placeholder="e.g. Bring your merry-go-round contribution in cash.")
        if st.form_submit_button("📌 Save Meeting"):
            set_meeting(chama_id, meeting_date.isoformat(), location.strip(), note.strip())
            st.success("Meeting saved.")
            st.rerun()

    latest_meeting = get_latest_meeting(chama_id)

    st.divider()
    st.subheader("Reminder Messages")
    st.caption(
        "Copy-paste these into WhatsApp, SMS, or your group's chat. "
        "Full automated sending needs an SMS/WhatsApp provider — see the note below."
    )

    members_df = get_members_df(chama_id)
    contributions_df = fetch_df("SELECT * FROM contributions WHERE chama_id = :cid", {"cid": chama_id})
    this_month = current_month_year()
    active_months = contributions_df["month_year"].nunique() if not contributions_df.empty else 0

    if members_df.empty:
        st.info("Add members first to generate personalized reminders.")
    else:
        meeting_line = ""
        if latest_meeting is not None:
            meeting_line = f"\nNext meeting: {latest_meeting['meeting_date']}"
            if latest_meeting["location"]:
                meeting_line += f" at {latest_meeting['location']}"
            if latest_meeting["note"]:
                meeting_line += f"\nNote: {latest_meeting['note']}"

        messages = []
        for _, m in members_df.iterrows():
            member_all = contributions_df[contributions_df["member_id"] == m["id"]] if not contributions_df.empty else pd.DataFrame()
            total_paid_alltime = member_all["amount_paid"].sum() if not member_all.empty else 0
            expected_alltime = m["monthly_target"] * active_months
            balance = total_paid_alltime - expected_alltime
            balance_line = (
                "You're all settled up. Thank you!" if balance >= 0
                else f"You currently owe KES {abs(balance):,.0f}."
            )
            msg = f"Hi {m['full_name']}, this is a reminder from {chama_name}.\n{balance_line}{meeting_line}"
            messages.append((m["full_name"], msg))

        for name, msg in messages:
            st.text_area(f"Message for {name}", value=msg, height=100, key=f"msg_{name}")

        st.divider()
        st.markdown("**Send them all at once:**")
        combined = "\n\n---\n\n".join(f"{name}:\n{msg}" for name, msg in messages)
        st.text_area("All reminders (copy this into your group chat)", value=combined, height=200)

    with st.expander("💡 Want these sent automatically?"):
        st.markdown(
            "Automated SMS/WhatsApp sending needs a messaging provider account — "
            "in Kenya, **Africa's Talking** (SMS) or the **WhatsApp Business API** are the "
            "usual choices. Once you have an account and API key there, this reminder "
            "text can be sent automatically instead of copy-pasted — ask and it can be wired in."
        )