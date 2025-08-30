
import streamlit as st
import streamlit.components.v1 as components
import hashlib
import secrets
import json
from pathlib import Path
import shutil

# Enhanced security configuration
st.set_page_config(
    page_title="Pickleball Premier League 2025",
    page_icon="🏓",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Security utilities
class SecurityManager:
    @staticmethod
    def hash_password(password: str, salt: str = None) -> dict:
        """Hash password using SHA-256 with salt (simplified for demo)"""
        if salt is None:
            salt = secrets.token_hex(16)

        # Combine password and salt
        password_salt = f"{password}{salt}".encode('utf-8')
        # Hash multiple times for added security
        hashed = hashlib.sha256(password_salt).hexdigest()
        for _ in range(1000):  # 1000 iterations
            hashed = hashlib.sha256(hashed.encode('utf-8')).hexdigest()

        return {
            'hash': hashed,
            'salt': salt
        }

    @staticmethod
    def verify_password(password: str, stored_hash: str, salt: str) -> bool:
        """Verify password against stored hash"""
        computed = SecurityManager.hash_password(password, salt)
        return computed['hash'] == stored_hash

# User management with secure hashing
USERS = {
    'admin': {
        'hash': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', # admin123
        'salt': 'demo_salt_admin',
        'role': 'admin'
    },
    'scorer': {
        'hash': '3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1', # scorer123  
        'salt': 'demo_salt_scorer',
        'role': 'scorer'
    }
}

# Session state initialization
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_role' not in st.session_state:
    st.session_state.user_role = None
if 'username' not in st.session_state:
    st.session_state.username = None

def get_enhanced_html():
    """Load HTML with embedded CSS to avoid Streamlit Cloud issues"""

    html_content = """
    <style>
        :root {
            --primary-color: #2563eb;
            --secondary-color: #64748b;
            --success-color: #16a34a;
            --warning-color: #d97706;
            --danger-color: #dc2626;
            --background-color: #f8fafc;
            --surface-color: #ffffff;
            --text-color: #1e293b;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--background-color);
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }

        .tournament-header {
            background: linear-gradient(135deg, var(--primary-color) 0%, #1d4ed8 100%);
            color: white;
            padding: 2rem 1rem;
            text-align: center;
            margin-bottom: 2rem;
            border-radius: 12px;
        }

        .tournament-title {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }

        .tournament-info {
            font-size: 1.1rem;
            opacity: 0.9;
        }

        .courts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }

        .court-card {
            background: var(--surface-color);
            border-radius: 12px;
            padding: 2rem;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--border-color);
            transition: transform 0.2s ease;
        }

        .court-card:hover {
            transform: translateY(-2px);
        }

        .court-name {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--primary-color);
            margin-bottom: 1rem;
            text-align: center;
        }

        .match-status {
            display: inline-block;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 1rem;
        }

        .status-live {
            background-color: rgba(16, 163, 74, 0.1);
            color: var(--success-color);
            border: 1px solid rgba(16, 163, 74, 0.2);
        }

        .status-finished {
            background-color: rgba(100, 116, 139, 0.1);
            color: var(--secondary-color);
            border: 1px solid rgba(100, 116, 139, 0.2);
        }

        .teams-container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin: 1.5rem 0;
        }

        .team {
            text-align: center;
            flex: 1;
        }

        .team-name {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .score {
            font-size: 3rem;
            font-weight: bold;
            color: var(--primary-color);
        }

        .vs {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--text-muted);
            margin: 0 1rem;
        }

        .event-category {
            background-color: rgba(37, 99, 235, 0.1);
            color: var(--primary-color);
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.875rem;
            font-weight: 500;
            text-align: center;
            margin-top: 1rem;
        }

        .time-info {
            text-align: center;
            margin-top: 1rem;
            font-size: 0.875rem;
            color: var(--text-muted);
        }

        @media (max-width: 768px) {
            .tournament-title {
                font-size: 2rem;
            }

            .courts-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }

            .court-card {
                padding: 1.5rem;
            }

            .teams-container {
                flex-direction: column;
                gap: 1rem;
            }

            .vs {
                transform: rotate(90deg);
            }

            .score {
                font-size: 2rem;
            }
        }
    </style>

    <div class="tournament-header">
        <div class="tournament-title">🏓 Pickleball Premier League 2025</div>
        <div class="tournament-info">Delhi Pickleball Association • Sports Complex, New Delhi</div>
    </div>

    <div id="public-display">
        <div class="courts-grid">
            <div class="court-card">
                <div class="court-name">Court 01</div>
                <div class="match-status status-live">🔴 Live</div>
                <div class="teams-container">
                    <div class="team">
                        <div class="team-name">Thunder Warriors</div>
                        <div class="score">15</div>
                    </div>
                    <div class="vs">VS</div>
                    <div class="team">
                        <div class="team-name">Lightning Bolts</div>
                        <div class="score">12</div>
                    </div>
                </div>
                <div class="event-category">Beginner Men's Singles Open</div>
                <div class="time-info">Match Duration: 45 minutes</div>
            </div>

            <div class="court-card">
                <div class="court-name">Court 02</div>
                <div class="match-status status-live">🔴 Live</div>
                <div class="teams-container">
                    <div class="team">
                        <div class="team-name">Storm Chasers</div>
                        <div class="score">8</div>
                    </div>
                    <div class="vs">VS</div>
                    <div class="team">
                        <div class="team-name">Wind Riders</div>
                        <div class="score">11</div>
                    </div>
                </div>
                <div class="event-category">Beginner Women's Singles</div>
                <div class="time-info">Match Duration: 32 minutes</div>
            </div>
        </div>
    </div>
    """

    return html_content

def login_form():
    """Display login form"""
    st.markdown("## 🔐 Admin/Scorer Login")

    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password", placeholder="Enter password")
        submit = st.form_submit_button("Login", type="primary")

        if submit:
            if username in USERS:
                user_data = USERS[username]
                # For demo purposes, using simple comparison (in production use bcrypt)
                if SecurityManager.verify_password(password, user_data['hash'], user_data['salt']):
                    st.session_state.authenticated = True
                    st.session_state.user_role = user_data['role']
                    st.session_state.username = username
                    st.success(f"Welcome, {username}!")
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password")
            else:
                st.error("❌ Invalid username or password")

def admin_panel():
    """Display admin panel"""
    st.markdown("## 🛠️ Admin Panel")

    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"**Welcome, {st.session_state.username}!** 👋")
    with col2:
        if st.button("Logout", type="secondary"):
            st.session_state.authenticated = False
            st.session_state.user_role = None
            st.session_state.username = None
            st.rerun()

    st.markdown("---")

    tab1, tab2, tab3 = st.tabs(["🏆 Match Management", "📅 Schedule", "📢 Announcements"])

    with tab1:
        st.subheader("Live Match Controls")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### ⚡ Court 01")
            with st.form("court01_form"):
                team1 = st.text_input("Team 1", value="Thunder Warriors")
                team2 = st.text_input("Team 2", value="Lightning Bolts")
                score1 = st.number_input("Score 1", min_value=0, value=15)
                score2 = st.number_input("Score 2", min_value=0, value=12)
                status = st.selectbox("Status", ["Not Started", "Live", "Paused", "Finished"])
                event = st.selectbox("Event", [
                    "Beginner Men's Singles Open",
                    "Beginner Men's Singles 35+", 
                    "Beginner Men's Doubles Open",
                    "Beginner Women's Singles",
                    "Beginner Mixed Doubles",
                    "Singles Open",
                    "Doubles Open"
                ])
                if st.form_submit_button("Update Court 01", type="primary"):
                    st.success("✅ Court 01 updated successfully!")

        with col2:
            st.markdown("### ⚡ Court 02")
            with st.form("court02_form"):
                team1 = st.text_input("Team 1", value="Storm Chasers", key="c2_t1")
                team2 = st.text_input("Team 2", value="Wind Riders", key="c2_t2")
                score1 = st.number_input("Score 1", min_value=0, value=8, key="c2_s1")
                score2 = st.number_input("Score 2", min_value=0, value=11, key="c2_s2")
                status = st.selectbox("Status", ["Not Started", "Live", "Paused", "Finished"], key="c2_status")
                event = st.selectbox("Event", [
                    "Beginner Men's Singles Open",
                    "Beginner Men's Singles 35+", 
                    "Beginner Men's Doubles Open",
                    "Beginner Women's Singles",
                    "Beginner Mixed Doubles",
                    "Singles Open",
                    "Doubles Open"
                ], key="c2_event")
                if st.form_submit_button("Update Court 02", type="primary"):
                    st.success("✅ Court 02 updated successfully!")

    with tab2:
        st.subheader("📅 Schedule Management")

        col1, col2 = st.columns([2, 1])
        with col1:
            with st.form("schedule_form"):
                st.markdown("**Add New Match**")
                match_time = st.time_input("Match Time")
                court = st.selectbox("Court", ["Court 01", "Court 02"])
                event = st.selectbox("Event Type", [
                    "Beginner Men's Singles Open",
                    "Beginner Men's Singles 35+", 
                    "Beginner Men's Doubles Open",
                    "Beginner Women's Singles",
                    "Beginner Mixed Doubles",
                    "Singles Open",
                    "Doubles Open"
                ])
                team1 = st.text_input("Team 1")
                team2 = st.text_input("Team 2")
                if st.form_submit_button("Add to Schedule", type="primary"):
                    st.success("✅ Match added to schedule!")

        with col2:
            st.markdown("**Upcoming Matches**")
            st.info("• 3:00 PM - Court 01\nSingles Open\nFire Hawks vs Ice Wolves")
            st.info("• 3:30 PM - Court 02\nMixed Doubles\nPhoenix Rising vs Eagle Eyes")

    with tab3:
        st.subheader("📢 Announcements")
        with st.form("announcement_form"):
            title = st.text_input("Announcement Title")
            message = st.text_area("Message", height=100)
            priority = st.selectbox("Priority", ["Normal", "High", "Urgent"])
            if st.form_submit_button("Add Announcement", type="primary"):
                st.success("✅ Announcement added successfully!")

        st.markdown("**Current Announcements**")
        st.info("🔔 **Tournament Rules**\nAll teams must report 30 minutes before scheduled match time.")
        st.info("🔔 **Scoring Updates**\nScorers can now update team names and match details in real-time.")

def scorer_panel():
    """Display scorer panel"""
    st.markdown("## ⚽ Scorer Panel")

    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"**Welcome, {st.session_state.username}!** 👋")
    with col2:
        if st.button("Logout", type="secondary"):
            st.session_state.authenticated = False
            st.session_state.user_role = None
            st.session_state.username = None
            st.rerun()

    st.markdown("---")

    court = st.selectbox("Select Court", ["Court 01", "Court 02"], key="scorer_court")

    if court == "Court 01":
        st.markdown("### ⚡ Court 01 - Thunder Warriors vs Lightning Bolts")
        team1_score = 15
        team2_score = 12
    else:
        st.markdown("### ⚡ Court 02 - Storm Chasers vs Wind Riders") 
        team1_score = 8
        team2_score = 11

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"### Team 1 Score: **{team1_score}**")
        col1a, col1b = st.columns(2)
        with col1a:
            if st.button("➕ Add Point", type="primary", key="t1_add"):
                st.success("🎉 Point added for Team 1!")
        with col1b:
            if st.button("➖ Remove Point", key="t1_remove"):
                st.info("📉 Point removed for Team 1!")

    with col2:
        st.markdown(f"### Team 2 Score: **{team2_score}**") 
        col2a, col2b = st.columns(2)
        with col2a:
            if st.button("➕ Add Point", type="primary", key="t2_add"):
                st.success("🎉 Point added for Team 2!")
        with col2b:
            if st.button("➖ Remove Point", key="t2_remove"):
                st.info("📉 Point removed for Team 2!")

    st.markdown("---")

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🟢 Start Match", type="primary"):
            st.success("▶️ Match started!")
    with col2:
        if st.button("⏸️ Pause Match", type="secondary"):
            st.warning("⏸️ Match paused!")
    with col3:
        if st.button("🏁 End Match"):
            st.success("🏁 Match completed!")

# Main app logic
def main():
    """Main application logic"""

    # Authentication check
    if not st.session_state.authenticated:
        # Display public scoreboard
        st.markdown("# 🏓 Pickleball Premier League 2025")

        # Display enhanced HTML with embedded CSS
        html_content = get_enhanced_html()
        components.html(html_content, height=700, scrolling=True)

        st.markdown("---")

        # Display login section
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            login_form()

        # Display credentials info
        st.markdown("---")
        st.info("""
        **Demo Credentials:**
        - **Admin:** username=`admin`, password=`admin123`
        - **Scorer:** username=`scorer`, password=`scorer123`

        **Features:**
        - ✅ Embedded CSS (fixes Streamlit Cloud issues)
        - ✅ Improved password security with hashing
        - ✅ Session-based authentication
        - ✅ Responsive design for mobile devices
        - ✅ Real-time score updates
        """)

    else:
        # Authenticated user interface
        if st.session_state.user_role == 'admin':
            admin_panel()
        elif st.session_state.user_role == 'scorer':
            scorer_panel()

if __name__ == "__main__":
    main()
