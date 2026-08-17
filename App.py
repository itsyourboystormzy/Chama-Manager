"""
Chama Manager — Multi-Tenant MVP
Python + Streamlit + SQLAlchemy (SQLite locally, Postgres in production)

Each Chama (savings group) signs up for its own account and only ever
sees its own members, contributions, and payouts.

Run locally (uses a local SQLite file automatically):
    pip install streamlit pandas sqlalchemy bcrypt
    streamlit run app.py

Run against a hosted Postgres database (e.g. Supabase / Neon / Railway):
    Add this to .streamlit/secrets.toml (or your host's "Secrets" settings):
        DATABASE_URL = "postgresql://user:password@host:5432/dbname"
    (Also: pip install psycopg2-binary)
"""

from datetime import date
import hashlib
import hmac
import os

import pandas as pd
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
        return create_engine(db_url, pool_pre_ping=True)
    # Local fallback — one file, fine for solo testing, not for production.
    return create_engine("sqlite:///chama.db", connect_args={"check_same_thread": False})


engine = get_engine()
IS_SQLITE = engine.url.get_backend_name() == "sqlite"

# SQLite doesn't support SERIAL/IDENTITY the same way Postgres does,
# so the schema below uses the portable AUTOINCREMENT-equivalent for each.
AUTOINCREMENT_PK = "INTEGER PRIMARY KEY AUTOINCREMENT" if IS_SQLITE else "SERIAL PRIMARY KEY"


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
# Data access — every query is scoped to the logged-in chama_id
# ----------------------------------------------------------------------------

def fetch_df(query, params=None):
    with engine.begin() as conn:
        return pd.read_sql_query(text(query), conn, params=params or {})


def run_write(query, params):
    with engine.begin() as conn:
        conn.execute(text(query), params)


def get_members_df(chama_id):
    return fetch_df("SELECT * FROM members WHERE chama_id = :cid ORDER BY full_name", {"cid": chama_id})


def current_month_year():
    return date.today().strftime("%Y-%m")


def add_member(chama_id, full_name, phone_number, monthly_target):
    run_write(
        "INSERT INTO members (chama_id, full_name, phone_number, monthly_target) "
        "VALUES (:cid, :name, :phone, :target)",
        {"cid": chama_id, "name": full_name, "phone": phone_number, "target": monthly_target},
    )


def add_contribution(chama_id, member_id, amount_paid, payment_date, month_year, is_late, payment_method):
    fine = LATE_FINE if is_late else 0
    run_write(
        """
        INSERT INTO contributions
            (chama_id, member_id, amount_paid, payment_date, month_year, fine_paid, payment_method)
        VALUES (:cid, :mid, :amount, :pdate, :myear, :fine, :method)
        """,
        {
            "cid": chama_id,
            "mid": member_id,
            "amount": amount_paid,
            "pdate": payment_date,
            "myear": month_year,
            "fine": fine,
            "method": payment_method,
        },
    )


def add_payout(chama_id, member_id, payout_date, amount, month_year):
    run_write(
        "INSERT INTO payouts (chama_id, member_id, payout_date, amount, month_year) "
        "VALUES (:cid, :mid, :pdate, :amount, :myear)",
        {"cid": chama_id, "mid": member_id, "pdate": payout_date, "amount": amount, "myear": month_year},
    )


# ----------------------------------------------------------------------------
# App shell
# ----------------------------------------------------------------------------

st.set_page_config(page_title="Chama Manager", page_icon="💰", layout="wide")
init_db()

if "chama" not in st.session_state:
    st.session_state.chama = None

# --------------------------------------------------------------------------
# Login / Sign-up gate — nothing below renders until a chama is logged in
# --------------------------------------------------------------------------
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

# --------------------------------------------------------------------------
# Logged in — everything from here is scoped to this chama_id
# --------------------------------------------------------------------------
chama_id = st.session_state.chama["id"]
chama_name = st.session_state.chama["name"]

top_left, top_right = st.columns([5, 1])
with top_left:
    st.title(f"💰 {chama_name}")
    st.caption("Member tracking, contributions, merry-go-round payouts and fines.")
with top_right:
    st.write("")
    if st.button("Log Out"):
        st.session_state.chama = None
        st.rerun()

tab_overview, tab_payment, tab_payout, tab_member = st.tabs(
    ["📊 Dashboard Overview", "💵 Record Payment", "🔄 Merry-Go-Round Payouts", "👤 Add Member"]
)

# --------------------------------------------------------------------------
# TAB 1 — Dashboard Overview
# --------------------------------------------------------------------------
with tab_overview:
    members_df = get_members_df(chama_id)
    contributions_df = fetch_df("SELECT * FROM contributions WHERE chama_id = :cid", {"cid": chama_id})
    payouts_df = fetch_df("SELECT * FROM payouts WHERE chama_id = :cid", {"cid": chama_id})

    this_month = current_month_year()

    total_savings = contributions_df["amount_paid"].sum() if not contributions_df.empty else 0
    total_fines = contributions_df["fine_paid"].sum() if not contributions_df.empty else 0
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
    col2.metric("Total Fines Collected", f"KES {total_fines:,.0f}")
    col3.metric(f"Pending — {this_month}", f"{pending_count} member(s)")
    col4.metric("Net Pot (after payouts)", f"KES {net_pot:,.0f}")

    st.divider()
    st.subheader(f"Current Month Status ({this_month})")

    if members_df.empty:
        st.info("No members yet. Add members in the 'Add Member' tab to get started.")
    else:
        status_rows = []
        for _, m in members_df.iterrows():
            member_contribs = (
                contributions_df[
                    (contributions_df["member_id"] == m["id"])
                    & (contributions_df["month_year"] == this_month)
                ]
                if not contributions_df.empty
                else pd.DataFrame()
            )
            paid_amount = member_contribs["amount_paid"].sum() if not member_contribs.empty else 0
            fine_amount = member_contribs["fine_paid"].sum() if not member_contribs.empty else 0
            status = "✅ Paid" if paid_amount >= m["monthly_target"] else (
                "🟡 Partial" if paid_amount > 0 else "🔴 Pending"
            )
            status_rows.append(
                {
                    "Member": m["full_name"],
                    "Target (KES)": m["monthly_target"],
                    "Paid (KES)": paid_amount,
                    "Fine (KES)": fine_amount,
                    "Status": status,
                }
            )
        st.dataframe(pd.DataFrame(status_rows), use_container_width=True, hide_index=True)

# --------------------------------------------------------------------------
# TAB 2 — Record Payment
# --------------------------------------------------------------------------
with tab_payment:
    st.subheader("Record a Contribution")
    members_df = get_members_df(chama_id)

    if members_df.empty:
        st.warning("Add at least one member first (see the 'Add Member' tab).")
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
                add_contribution(
                    chama_id,
                    member_id,
                    amount,
                    payment_date.isoformat(),
                    month_year,
                    is_late,
                    payment_method,
                )
                fine_note = f" (+ KES {LATE_FINE} late fine)" if is_late else ""
                st.toast(f"Payment of KES {amount:,.0f} recorded for {selected_name}{fine_note} ✅", icon="✅")
                st.success(f"Saved: {selected_name} — KES {amount:,.0f} for {month_year}{fine_note}")

    st.divider()
    st.subheader("Recent Contributions")
    contrib_view = fetch_df(
        """
        SELECT c.id, m.full_name AS member, c.amount_paid, c.fine_paid,
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
        st.dataframe(contrib_view, use_container_width=True, hide_index=True)

# --------------------------------------------------------------------------
# TAB 3 — Merry-Go-Round Payouts
# --------------------------------------------------------------------------
with tab_payout:
    st.subheader("Record a Payout")
    members_df = get_members_df(chama_id)

    if members_df.empty:
        st.warning("Add at least one member first (see the 'Add Member' tab).")
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

    st.divider()
    st.subheader("Payout History")
    payout_view = fetch_df(
        """
        SELECT p.id, m.full_name AS member, p.amount, p.payout_date, p.month_year
        FROM payouts p
        JOIN members m ON m.id = p.member_id
        WHERE p.chama_id = :cid
        ORDER BY p.id DESC
        """,
        {"cid": chama_id},
    )
    if payout_view.empty:
        st.info("No payouts recorded yet.")
    else:
        st.dataframe(payout_view, use_container_width=True, hide_index=True)

        already_paid = set(payout_view["member"])
        all_members = set(get_members_df(chama_id)["full_name"])
        remaining = all_members - already_paid
        if remaining:
            st.caption("⏳ Still waiting in the rotation: " + ", ".join(sorted(remaining)))
        else:
            st.caption("✅ Every member has received at least one payout so far.")

# --------------------------------------------------------------------------
# TAB 4 — Add Member
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
    st.subheader("All Members")
    members_view = get_members_df(chama_id)
    if members_view.empty:
        st.info("No members yet.")
    else:
        st.dataframe(
            members_view.rename(
                columns={
                    "full_name": "Full Name",
                    "phone_number": "Phone",
                    "monthly_target": "Monthly Target (KES)",
                }
            )[["Full Name", "Phone", "Monthly Target (KES)"]],
            use_container_width=True,
            hide_index=True,
        )