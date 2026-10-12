import calendar
import hashlib
import hmac
import html
import re
import secrets
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="RetailPulse", page_icon="📊", layout="wide")

DATA = Path(__file__).parent / "app_data"                               # small summary files
DB_FILE = Path(tempfile.gettempdir()) / "retailpulse_users.db"          # user accounts (never committed to GitHub)

ACCENT = ["#4F8BF9", "#9b6bff", "#2dd4bf", "#f59e0b", "#f472b6", "#f87171"]
px.defaults.template = "plotly_dark"
px.defaults.color_discrete_sequence = ACCENT

# ======================================================================
# THEME (the same colours are used on the login page and inside the app)
# ======================================================================
THEME_CSS = """
<style>
.stApp { background: linear-gradient(135deg, #0b1220 0%, #121b34 60%, #172445 100%); }
[data-testid="stSidebar"] { background: linear-gradient(180deg, #101a35 0%, #0b1220 100%);
                            border-right: 1px solid rgba(255,255,255,0.08); }
[data-testid="stMetric"] { background: linear-gradient(145deg, rgba(79,139,249,0.14), rgba(155,107,255,0.08));
                           border: 1px solid rgba(255,255,255,0.10); border-radius: 14px; padding: 14px 18px; }
[data-testid="stMetricLabel"] { color: #aeb9d1; }
.banner { background: linear-gradient(90deg, rgba(79,139,249,0.40), rgba(155,107,255,0.28));
          border: 1px solid rgba(255,255,255,0.14); border-radius: 16px; padding: 22px 28px; margin-bottom: 20px; }
.banner h1 { margin: 0; font-size: 2rem; padding: 0; }
.banner p { margin: 6px 0 0 0; color: #d3dcf1; }
.feature { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);
           border-radius: 14px; padding: 12px 16px; margin-bottom: 10px; }
.feature b { color: #ffffff; }
.feature span { color: #aeb9d1; font-size: 0.9rem; }
.usercard { display: flex; align-items: center; gap: 12px; background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.12); border-radius: 14px; padding: 10px 14px; margin-bottom: 10px; }
.avatar { width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center;
          font-weight: 700; color: #fff; background: linear-gradient(135deg, #4F8BF9, #9b6bff); }
.badge { background: rgba(79,139,249,0.25); color: #9ec1ff; border-radius: 8px; padding: 1px 8px; font-size: 0.75rem; }
.hero-title { .hero-title { font-size: 3.2rem; font-weight: 800; margin-bottom: 0;
              background: linear-gradient(90deg, #4F8BF9, #9b6bff);
              -webkit-background-clip: text; -webkit-text-fill-color: transparent; } }
.hero-sub { color: #b8c4dc; font-size: 1.15rem; margin-top: 0.2rem; margin-bottom: 1.5rem; }
.stats { display: flex; gap: 22px; margin-top: 18px; }
.stats div { color: #7f8bab; font-size: 0.8rem; }
.stats strong { display: block; color: #4F8BF9; font-size: 1.4rem; }
.footer { color: #7f8bab; font-size: 0.8rem; text-align: center; margin-top: 2.5rem; }
</style>
"""
st.markdown(THEME_CSS, unsafe_allow_html=True)


# ======================================================================
# SMALL HELPERS
# ======================================================================
@st.cache_data
def load(name):
    return pd.read_csv(DATA / name)                     # read each file once, then reuse it


def human(n):
    """Show big numbers as 1.25B, 340.20M, 12.50K."""
    for unit, size in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if abs(n) >= size:
            return f"{n / size:,.2f}{unit}"
    return f"{n:,.0f}"


def banner(title, subtitle):
    st.markdown(f'<div class="banner"><h1>{title}</h1><p>{subtitle}</p></div>', unsafe_allow_html=True)


def show(fig, where=st):
    """Draw a chart with the same transparent, dark style everywhere."""
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      margin=dict(l=10, r=10, t=50, b=10), title_font_size=16)
    where.plotly_chart(fig)


def download(df, label, filename):
    """Only admin users can download data (role-based access)."""
    if st.session_state.role == "admin":
        st.download_button(label, df.to_csv(index=False), filename, "text/csv")
    else:
        st.caption("🔒 Downloads are for admin users only.")


# ======================================================================
# USER ACCOUNTS (SQLite + hashed passwords)
# ======================================================================
def run(sql, params=(), fetch=False):
    con = sqlite3.connect(DB_FILE)
    try:
        cursor = con.execute(sql, params)
        rows = cursor.fetchall() if fetch else None      # fetch=True when we want rows back
        con.commit()
        return rows
    finally:
        con.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_password(pwd):
    salt = secrets.token_bytes(16)                                       # a random salt for every user
    digest = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 120_000)  # slow on purpose, hard to crack
    return salt.hex() + ":" + digest.hex()


def check_password(pwd, stored):
    salt_hex, digest_hex = stored.split(":")
    digest = hashlib.pbkdf2_hmac("sha256", pwd.encode(), bytes.fromhex(salt_hex), 120_000)
    return hmac.compare_digest(digest.hex(), digest_hex)


@st.cache_resource
def init_db():
    """Create the tables once, and add the two built-in demo accounts."""
    run("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, full_name TEXT, email TEXT, "
        "role TEXT, pw TEXT, created TEXT)")
    run("CREATE TABLE IF NOT EXISTS audit (ts TEXT, username TEXT, event TEXT)")
    for username, name, role, pwd in [("demo", "Demo User", "viewer", "demo123"),
                                      ("admin", "Administrator", "admin", "admin123")]:
        if not run("SELECT 1 FROM users WHERE username=?", (username,), fetch=True):
            run("INSERT INTO users VALUES (?,?,?,?,?,?)",
                (username, name, "", role, hash_password(pwd), now()))
    return True


def log_event(username, event):
    run("INSERT INTO audit VALUES (?,?,?)", (now(), username, event))      # audit log of sensitive actions


def register_user(name, email, username, pwd, pwd2):
    """Return (ok, message). New accounts always get the 'viewer' role."""
    username = username.strip().lower()
    if not 2 <= len(name.strip()) <= 40:
        return False, "Please enter your full name (2 to 40 characters)."
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()):
        return False, "Please enter a valid email address."
    if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
        return False, "Username: 3 to 20 letters, numbers or underscores."
    if len(pwd) < 6:
        return False, "Password must be at least 6 characters."
    if pwd != pwd2:
        return False, "The two passwords do not match."
    if run("SELECT 1 FROM users WHERE username=?", (username,), fetch=True):
        return False, "That username is already taken."
    run("INSERT INTO users VALUES (?,?,?,?,?,?)",
        (username, name.strip(), email.strip(), "viewer", hash_password(pwd), now()))
    log_event(username, "registered")
    return True, "Account created! Open the **Log in** tab and sign in."


def try_login(username, pwd):
    row = run("SELECT full_name, role, pw FROM users WHERE username=?", (username.strip().lower(),), fetch=True)
    if row and check_password(pwd, row[0][2]):
        st.session_state.logged_in = True
        st.session_state.user = username.strip().lower()
        st.session_state.name = row[0][0]
        st.session_state.role = row[0][1]
        log_event(st.session_state.user, "login")
        return True
    log_event(username.strip().lower() or "(blank)", "failed login")
    return False


# ======================================================================
# LOGIN / REGISTER PAGE
# ======================================================================
FEATURES = [
    ("📈", "Sales", "Filter by year, category, channel and city"),
    ("👥", "Customers", "RFM segments, 6 KMeans groups and churn risk"),
    ("🔮", "Forecast", "Prophet and LSTM, 30-day outlook with what-if"),
    ("📦", "Inventory", "Reorder points, safety stock and overstock"),
]


def login_page():
    left, right = st.columns([1.2, 1], gap="large")

    with left:
        st.markdown("<div style='height:2rem'></div>", unsafe_allow_html=True)
        st.markdown('<div class="hero-title"><span>📊</span> RetailPulse</div>', unsafe_allow_html=True)
        st.markdown('<p class="hero-sub">AI-powered customer analytics and demand forecasting</p>',
                    unsafe_allow_html=True)
        for icon, title, text in FEATURES:
            st.markdown(f'<div class="feature">{icon} <b>{title}</b><br><span>{text}</span></div>',
                        unsafe_allow_html=True)
        st.markdown("""<div class="stats">
            <div><strong>9.9M</strong>transactions</div>
            <div><strong>10,000</strong>customers</div>
            <div><strong>5,000</strong>products</div>
            <div><strong>7.66%</strong>forecast error</div></div>""", unsafe_allow_html=True)

    with right:
        st.markdown("<div style='height:3rem'></div>", unsafe_allow_html=True)
        with st.container(border=True):
            tab_in, tab_new = st.tabs(["🔐 Log in", "📝 Create account"])

            with tab_in:
                st.subheader("Welcome back 👋")
                with st.form("login"):
                    user = st.text_input("Username")
                    pwd = st.text_input("Password", type="password")
                    go_in = st.form_submit_button("Log in")
                st.info("Demo access: username **demo**, password **demo123**")
                if go_in:
                    if try_login(user, pwd):
                        st.rerun()
                    else:
                        st.error("Wrong username or password.")

            with tab_new:
                st.subheader("Join RetailPulse")
                with st.form("register"):
                    name = st.text_input("Full name")
                    email = st.text_input("Email")
                    new_user = st.text_input("Choose a username")
                    new_pwd = st.text_input("Choose a password", type="password")
                    new_pwd2 = st.text_input("Repeat the password", type="password")
                    go_new = st.form_submit_button("Create account")
                if go_new:
                    ok, msg = register_user(name, email, new_user, new_pwd, new_pwd2)
                    (st.success if ok else st.error)(msg)

    st.markdown('<p class="footer">Zidio Development · Data Science & Analytics internship project</p>',
                unsafe_allow_html=True)


# ======================================================================
# START: database and login check
# ======================================================================
init_db()
for key, default in {"logged_in": False, "user": "", "name": "", "role": ""}.items():
    st.session_state.setdefault(key, default)

if not st.session_state.logged_in:
    login_page()
    st.stop()                                           # nothing below runs until the user logs in


# ======================================================================
# PAGE: HOME
# ======================================================================
def home_page():
    first = html.escape((st.session_state.name.split() or ["there"])[0])
    banner(f"Welcome back, {first} 👋", "Here is a quick look at the business. Use the menu on the left to explore.")

    cube, cust = load("sales_cube.csv"), load("customer_table.csv")
    comp, inv = load("model_comparison.csv"), load("inventory_actions.csv")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total sales", human(cube["sales"].sum()))
    k2.metric("Customers", f"{len(cust):,}")
    k3.metric("Forecast error (best model)", f"{comp['MAPE_percent'].min():.2f}%")
    k4.metric("Items to reorder", f"{int(inv['needs_reorder'].sum()):,}")

    by_month = cube.assign(m=cube["year_month"].str[5:7].astype(int)).groupby("m")["sales"].sum()
    busiest = calendar.month_name[int(by_month.idxmax())]
    online = cube.loc[cube["channel"] == "Online", "sales"].sum() / cube["sales"].sum() * 100
    high = None
    if (DATA / "churn_scores.csv").exists():
        high = int((load("churn_scores.csv")["risk_band"] == "High").sum())

    st.subheader("Key findings")
    a, b, c = st.columns(3)
    a.markdown(f'<div class="feature">📅 <b>Busiest month: {busiest}</b><br>'
               f'<span>Sales peak in the same months every year.</span></div>', unsafe_allow_html=True)
    b.markdown(f'<div class="feature">🛒 <b>Online share: {online:.1f}%</b><br>'
               f'<span>Share of all sales made through the Online channel.</span></div>', unsafe_allow_html=True)
    if high is not None:
        c.markdown(f'<div class="feature">⚠️ <b>{high:,} customers at high churn risk</b><br>'
                   f'<span>Predicted to slow down by the XGBoost model.</span></div>', unsafe_allow_html=True)

    st.subheader("Explore")
    cols = st.columns(4)
    for col, (icon, title, text) in zip(cols, FEATURES):
        col.markdown(f'<div class="feature">{icon} <b>{title}</b><br><span>{text}</span></div>',
                     unsafe_allow_html=True)


# ======================================================================
# PAGE: SALES
# ======================================================================
def sales_page():
    banner("📈 Sales overview", "Use the filters on the left to explore sales by year, category, channel and city.")
    cube = load("sales_cube.csv")

    st.sidebar.subheader("Filters")
    years = st.sidebar.multiselect("Year", sorted(cube["year"].unique().tolist()),
                                   default=sorted(cube["year"].unique().tolist()))
    cats = st.sidebar.multiselect("Category", sorted(cube["category"].unique()),
                                  default=sorted(cube["category"].unique()))
    chans = st.sidebar.multiselect("Channel", sorted(cube["channel"].unique()),
                                   default=sorted(cube["channel"].unique()))
    cities = st.sidebar.multiselect("Store city", sorted(cube["store_city"].unique()),
                                    default=sorted(cube["store_city"].unique()))

    f = cube[cube["year"].isin(years) & cube["category"].isin(cats)
             & cube["channel"].isin(chans) & cube["store_city"].isin(cities)]
    if f.empty:
        st.warning("No data for these filters.")
        return

    promo_share = f.loc[f["has_promo"], "sales"].sum() / f["sales"].sum() * 100
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Net sales", human(f["sales"].sum()))
    k2.metric("Profit (30% margin)", human(f["profit_30"].sum()))
    k3.metric("Units sold", human(f["units"].sum()))
    k4.metric("Sales with a promotion", f"{promo_share:.1f}%")

    monthly = f.groupby("year_month")["sales"].sum().reset_index()
    show(px.line(monthly, x="year_month", y="sales", title="Monthly sales"))

    left, right = st.columns(2)
    by_cat = f.groupby("category")["sales"].sum().sort_values().reset_index()
    show(px.bar(by_cat, x="sales", y="category", orientation="h", title="Sales by category"), left)
    by_ch = f.groupby("channel")["sales"].sum().reset_index()
    show(px.pie(by_ch, names="channel", values="sales", title="Sales by channel"), right)

    left, right = st.columns(2)
    by_city = f.groupby("store_city")["sales"].sum().sort_values().reset_index()
    show(px.bar(by_city, x="sales", y="store_city", orientation="h", title="Sales by store city"), left)
    by_season = f.groupby("season")["sales"].sum().reset_index()
    show(px.bar(by_season, x="season", y="sales", title="Sales by season"), right)

    download(monthly, "Download monthly sales (CSV)", "monthly_sales.csv")


# ======================================================================
# PAGE: CUSTOMERS
# ======================================================================
def customers_page():
    banner("👥 Customers", "Who our customers are, how they group together, and who may slow down.")
    cust = load("customer_table.csv")

    groups = sorted(cust["cluster_name"].unique())
    pick = st.sidebar.multiselect("Customer group", groups, default=groups)
    c = cust[cust["cluster_name"].isin(pick)]
    if c.empty:
        st.warning("Pick at least one customer group.")
        return

    k1, k2, k3 = st.columns(3)
    k1.metric("Customers", f"{len(c):,}")
    k2.metric("Average purchases per customer", f"{c['frequency'].mean():,.0f}")
    k3.metric("High churn risk (rule-based)", f"{(c['churn_risk'] == 'High Risk').sum():,}")

    left, right = st.columns(2)
    sizes = c["cluster_name"].value_counts().reset_index()
    sizes.columns = ["group", "customers"]
    show(px.bar(sizes, x="customers", y="group", orientation="h", title="Customers per KMeans group"), left)
    seg = c["segment"].value_counts().reset_index()
    seg.columns = ["segment", "customers"]
    show(px.pie(seg, names="segment", values="customers", title="Rule-based segments"), right)

    sample = c.sample(min(3000, len(c)), random_state=1)
    show(px.scatter(sample, x="frequency", y="monetary", color="cluster_name",
                    title="Purchases vs total spend (sample of customers)"))

    st.subheader("What each group looks like (averages)")
    profile = c.groupby("cluster_name")[["recency_days", "frequency", "monetary", "avg_order_value"]].mean().round(1)
    st.dataframe(profile)

    st.subheader("Churn prediction (XGBoost)")
    if (DATA / "churn_scores.csv").exists():
        scores = load("churn_scores.csv").merge(cust[["customer_id", "cluster_name"]], on="customer_id")
        scores = scores[scores["cluster_name"].isin(pick)]
        bands = scores["risk_band"].value_counts().reindex(["High", "Medium", "Low"]).fillna(0).reset_index()
        bands.columns = ["risk band", "customers"]
        a, b = st.columns(2)
        show(px.bar(bands, x="risk band", y="customers", title="Customers by predicted risk"), a)
        top = scores.sort_values("churn_probability", ascending=False).head(20)
        b.write("20 customers most likely to slow down")
        b.dataframe(top[["customer_id", "cluster_name", "churn_probability"]])
        download(scores[scores["risk_band"] == "High"], "Download high-risk customers (CSV)", "high_risk_customers.csv")
    else:
        st.info("Churn scores file not found.")

    with st.expander("Which factors drive churn? (SHAP)"):
        if (DATA / "shap_summary.png").exists():
            st.image(str(DATA / "shap_summary.png"))
            st.caption("Red dots are high values of a column, and dots to the right push a customer towards churn.")


# ======================================================================
# PAGE: FORECAST
# ======================================================================
def forecast_page():
    banner("🔮 Demand forecast", "Prophet and LSTM predictions, with a what-if slider to test different demand levels.")
    daily = load("daily_sales.csv")
    daily["date"] = pd.to_datetime(daily["date"])
    fc = load("prophet_forecast.csv")
    fc["ds"] = pd.to_datetime(fc["ds"])
    test = load("forecast_test_results.csv")
    comp = load("model_comparison.csv")

    last_day = daily["date"].max()
    future = fc[fc["ds"] > last_day].copy()              # the 30 days after the data ends

    change = st.sidebar.slider("What-if: change in demand (%)", -30, 30, 0)
    base_total = future["yhat"].sum()
    future[["yhat", "yhat_lower", "yhat_upper"]] *= 1 + change / 100
    total = future["yhat"].sum()
    diff = total - base_total
    best = comp.sort_values("MAPE_percent").iloc[0]

    k1, k2, k3 = st.columns(3)
    k1.metric("Forecast, next 30 days", human(total),
              delta=(("+" if diff > 0 else "") + human(diff)) if change else None)
    k2.metric("Best model", best["model"], delta=f"MAPE {best['MAPE_percent']:.2f}% (target 12%)", delta_color="off")
    k3.metric("Average per day", human(future["yhat"].mean()))

    hist = daily[daily["date"] > last_day - pd.Timedelta(days=180)]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=hist["date"], y=hist["sales"], name="Actual sales", line=dict(color=ACCENT[0])))
    fig.add_trace(go.Scatter(x=future["ds"], y=future["yhat"], name="Forecast", line=dict(color=ACCENT[1])))
    fig.add_trace(go.Scatter(x=list(future["ds"]) + list(future["ds"][::-1]),
                             y=list(future["yhat_upper"]) + list(future["yhat_lower"][::-1]),
                             fill="toself", fillcolor="rgba(155,107,255,0.25)", line=dict(width=0),
                             name="Uncertainty range", hoverinfo="skip"))
    fig.update_layout(title="Last 6 months and the next 30 days")
    show(fig)

    left, right = st.columns(2)
    bar = px.bar(comp, x="model", y="MAPE_percent", title="Model error (MAPE, lower is better)")
    bar.add_hline(y=12, line_dash="dash", annotation_text="target 12%")
    show(bar, left)
    show(px.line(test, x="date", y=["actual", "prophet", "lstm", "ensemble"],
                 title="Test: last 30 days, actual vs models"), right)

    download(future[["ds", "yhat", "yhat_lower", "yhat_upper"]], "Download forecast (CSV)", "forecast_30_days.csv")


# ======================================================================
# PAGE: INVENTORY
# ======================================================================
def inventory_page():
    banner("📦 Inventory", "Which products to reorder, how much to order, and where stock is piling up.")
    inv = load("inventory_actions.csv")

    cats = st.sidebar.multiselect("Category", sorted(inv["category"].unique()),
                                  default=sorted(inv["category"].unique()))
    flags = st.sidebar.multiselect("Product group", sorted(inv["flag"].unique()),
                                   default=sorted(inv["flag"].unique()))
    only = st.sidebar.checkbox("Only items that need reordering")
    f = inv[inv["category"].isin(cats) & inv["flag"].isin(flags)]
    if only:
        f = f[f["needs_reorder"]]
    if f.empty:
        st.warning("No items for these filters.")
        return

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Items to reorder", f"{int(f['needs_reorder'].sum()):,}")
    k2.metric("Units to order", human(f["order_qty"].sum()))
    k3.metric("Order cost", human(f["order_cost"].sum()))
    k4.metric("Excess stock (units)", human(f["excess_units"].sum()))

    left, right = st.columns(2)
    by_cat = f.groupby("category")["order_cost"].sum().sort_values().reset_index()
    show(px.bar(by_cat, x="order_cost", y="category", orientation="h", title="Order cost by category"), left)
    by_flag = f.groupby(["flag", "needs_reorder"]).size().reset_index(name="items")
    show(px.bar(by_flag, x="flag", y="items", color="needs_reorder", title="Reorder alerts by product group"), right)

    cols = ["store_id", "sku_name", "category", "stock_on_hand", "reorder_point_calc", "order_qty", "order_cost"]
    st.subheader("Top 20 items to reorder")
    st.dataframe(f.sort_values("order_cost", ascending=False).head(20)[cols])
    st.subheader("Top 20 overstocked items")
    st.dataframe(f.sort_values("excess_units", ascending=False).head(20)
                 [["store_id", "sku_name", "category", "stock_on_hand", "excess_units"]])

    download(f[f["needs_reorder"]], "Download reorder list (CSV)", "reorder_list.csv")


# ======================================================================
# PAGE: ADMIN (only admins can see it)
# ======================================================================
def admin_page():
    banner("🛡️ Admin", "Registered users and recent activity (audit log).")
    users = pd.DataFrame(run("SELECT username, full_name, email, role, created FROM users ORDER BY created DESC",
                             fetch=True), columns=["username", "full name", "email", "role", "created"])
    logs = pd.DataFrame(run("SELECT ts, username, event FROM audit ORDER BY ts DESC LIMIT 200", fetch=True),
                        columns=["time", "user", "event"])

    k1, k2, k3 = st.columns(3)
    k1.metric("Registered users", f"{len(users):,}")
    k2.metric("Logins", f"{(logs['event'] == 'login').sum():,}")
    k3.metric("Failed logins", f"{(logs['event'] == 'failed login').sum():,}")

    st.subheader("Users")
    st.dataframe(users)
    st.subheader("Recent activity")
    st.dataframe(logs)
    download(users, "Download user list (CSV)", "users.csv")


# ======================================================================
# MENU AND PAGE SWITCH
# ======================================================================
PAGES = {"🏠 Home": home_page, "📈 Sales": sales_page, "👥 Customers": customers_page,
         "🔮 Forecast": forecast_page, "📦 Inventory": inventory_page}
if st.session_state.role == "admin":
    PAGES["🛡️ Admin"] = admin_page

st.sidebar.markdown("### 📊 RetailPulse")
st.sidebar.markdown(
    f'<div class="usercard"><div class="avatar">{html.escape(st.session_state.name[:1].upper())}</div>'
    f'<div><b>{html.escape(st.session_state.name)}</b><br>'
    f'<span class="badge">{html.escape(st.session_state.role)}</span></div></div>', unsafe_allow_html=True)
page = st.sidebar.radio("Go to", list(PAGES))
if st.sidebar.button("Log out"):
    log_event(st.session_state.user, "logout")
    for key in ["logged_in", "user", "name", "role"]:
        st.session_state.pop(key, None)
    st.rerun()

PAGES[page]()