import streamlit as st
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
import json
import os

# --- Constants ---
DATA_FILE = "data_store.json"
MAX_FAILED_ATTEMPTS = 3
DEFAULT_SALT = "studifinity_salt"
BACKGROUND_IMAGE = "https://images.unsplash.com/photo-1633613286848-e6f43bbafb8d?auto=format&fit=crop&w=1920&q=80"

# --- VIP UI Styling ---
st.markdown(
    f"""
    <style>
    /* Main app background */
    .stApp {{
        background: linear-gradient(rgba(0, 0, 0, 0.85), rgba(0, 0, 0, 0.85)), url('{BACKGROUND_IMAGE}') no-repeat center center fixed;
        background-size: cover;
        color: #ffffff;
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    }}
    /* Sidebar - Futuristic Glow */
    [data-testid="stSidebar"] {{
        background: linear-gradient(180deg, rgba(20, 20, 30, 0.95), rgba(10, 10, 20, 0.95)) !important;
        border-right: 2px solid rgba(0, 255, 255, 0.2) !important;
        box-shadow: 0 0 20px rgba(0, 255, 255, 0.1) !important;
        padding: 2rem 1rem !important;
    }}
    .stSidebar .stButton>button {{
        background: linear-gradient(45deg, #00b7eb, #007bff) !important;
        color: white !important;
        border-radius: 12px !important;
        border: 1px solid rgba(0, 255, 255, 0.3) !important;
        font-weight: 600 !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 0 10px rgba(0, 255, 255, 0.2) !important;
    }}
    .stSidebar .stButton>button:hover {{
        transform: scale(1.05) !important;
        box-shadow: 0 0 20px rgba(0, 255, 255, 0.5) !important;
        border-color: rgba(0, 255, 255, 0.8) !important;
    }}
    /* Headings - Neon Glow */
    h1, h2, h3, h4, h5, h6 {{
        color: #ffffff !important;
        text -webkit-text-stroke: 0.5px #00b7eb;
        text-shadow: 0 0 10px rgba(0, 255, 255, 0.5), 0 0 20px rgba(0, 255, 255, 0.3) !important;
    }}
    .dashboard-title {{
        font-size: 2.8rem !important;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(45deg, #00b7eb, #ff007f);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: pulse 2s infinite;
    }}
    /* Input Fields - Sleek White */
    .stTextInput>div>div>input,
    .stTextArea>div>div>textarea {{
        background-color: rgba(255, 255, 255, 0.95) !important;
        color: #000000 !important;
        border-radius: 10px !important;
        border: 1px solid rgba(0, 255, 255, 0.3) !important;
        box-shadow: 0 0 10px rgba(0, 255, 255, 0.1) !important;
        transition: all 0.3s ease !important;
    }}
    .stTextInput input:focus,
    .stTextArea textarea:focus {{
        border-color: rgba(0, 255, 255, 0.8) !important;
        box-shadow: 0 0 15px rgba(0, 255, 255, 0.4) !important;
    }}
    .stTextInput input::placeholder,
    .stTextArea textarea::placeholder {{
        color: #999999 !important;
        opacity: 0.8 !important;
    }}
    /* Buttons - Animated Gradient */
    .stButton>button {{
        background: linear-gradient(45deg, #00b7eb, #007bff) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        font-weight: 600 !important;
        padding: 0.75rem 1.5rem !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 0 15px rgba(0, 255, 255, 0.3) !important;
    }}
    .stButton>button:hover {{
        transform: translateY(-3px) !important;
        box-shadow: 0 0 25px rgba(0, 255, 255, 0.6) !important;
        background: linear-gradient(45deg, #007bff, #00b7eb) !important;
    }}
    /* Cards - Premium Glassmorphism */
    .card {{
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0.05)) !important;
        backdrop-filter: blur(15px) !important;
        border-radius: 15px !important;
        padding: 25px !important;
        margin-bottom: 25px !important;
        border: 1px solid rgba(0, 255, 255, 0.2) !important;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2), 0 0 20px rgba(0, 255, 255, 0.1) !important;
        transition: transform 0.3s ease !important;
    }}
    .card:hover {{
        transform: translateY(-5px) !important;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3), 0 0 30px rgba(0, 255, 255, 0.2) !important;
    }}
    /* Labels */
    [data-testid="stTextInput"] label p,
    [data-testid="stPasswordInput"] label p {{
        color: #ffffff !important;
        font-weight: 500 !important;
        text-shadow: 0 0 5px rgba(0, 255, 255, 0.3) !important;
    }}
    /* Separator */
    .separator {{
        margin: 2.5rem 0;
        border-top: 1px solid rgba(0, 255, 255, 0.3);
        text-align: center;
        position: relative;
    }}
    .separator-text {{
        position: absolute;
        top: -12px;
        left: 50%;
        transform: translateX(-50%);
        background: linear-gradient(180deg, rgba(20, 20, 30, 0.95), rgba(10, 10, 20, 0.95));
        padding: 0 1.5rem;
        color: #00b7eb;
        font-weight: 600;
    }}
    /* Animations */
    @keyframes pulse {{
        0% {{ opacity: 1; }}
        50% {{ opacity: 0.7; }}
        100% {{ opacity: 1; }}
    }}
    /* Responsive Design */
    @media (max-width: 768px) {{
        .dashboard-title {{
            font-size: 2.2rem !important;
        }}
        .card {{
            padding: 15px !important;
        }}
        .stButton>button {{
            padding: 0.5rem 1rem !important;
        }}
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Key Management ---
@st.cache_resource
def load_cipher():
    key = Fernet.generate_key()
    return Fernet(key)

cipher = load_cipher()

# --- Data Handling ---
def load_data():
    if os.path.exists(DATA_FILE) and os.path.getsize(DATA_FILE) > 0:
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            st.error("Corrupted data file. Starting fresh.")
            return {}
    return {}

def save_data(data):
    try:
        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        st.error(f"Error saving data: {str(e)}")

# --- Security Functions ---
def hash_passkey(passkey, salt=DEFAULT_SALT):
    key = pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return urlsafe_b64encode(key).decode()

def encrypt_data(text):
    try:
        return cipher.encrypt(text.encode()).decode()
    except Exception as e:
        st.error(f"Encryption failed: {str(e)}")
        return None

def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        st.error(f"Decryption failed: {str(e)}")
        return None

# --- Session Management ---
if "data_store" not in st.session_state:
    st.session_state.data_store = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = False

if "current_user" not in st.session_state:
    st.session_state.current_user = ""

if "page" not in st.session_state:
    st.session_state.page = "login"

# --- Login Page ---
def login_page():
    st.markdown('<h1 class="dashboard-title">🔐 CyberVault Access</h1>', unsafe_allow_html=True)
    
    with st.container():
        # Registration Section
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("Create New Account")
        
        reg_user = st.text_input("Choose Username", key="reg_user", placeholder="e.g., taha123")
        reg_pass = st.text_input("Create Password", type="password", key="reg_pass", placeholder="Strong password")
        reg_pass_confirm = st.text_input("Confirm Password", type="password", key="reg_pass_confirm", placeholder="Re-enter password")
        
        if st.button("Register Account"):
            if not reg_user or not reg_pass:
                st.error("Username and password required")
                return
            if reg_pass != reg_pass_confirm:
                st.error("Passwords do not match")
                return
                
            hashed_pass = hash_passkey(reg_pass)
            users = st.session_state.data_store
            
            if reg_user in users:
                st.error("Username already exists")
                return
                
            users[reg_user] = {"password": hashed_pass, "entries": {}}
            save_data(users)
            st.success("Registration successful! Please login")
            
        st.markdown('</div>', unsafe_allow_html=True)

        # Login Section
        st.markdown('<div class="separator"><span class="separator-text">OR</span></div>', unsafe_allow_html=True)
        
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("Login to Your Vault")
        
        login_user = st.text_input("Username", key="login_user", placeholder="e.g., taha123")
        login_pass = st.text_input("Password", type="password", key="login_pass", placeholder="Enter password")
        
        if st.button("Access Vault"):
            if not login_user or not login_pass:
                st.error("Username and password required")
                return
                
            users = st.session_state.data_store
            hashed_pass = hash_passkey(login_pass)
            
            if login_user not in users:
                st.error("User not found. Please register first")
                return
                
            if users[login_user]["password"] != hashed_pass:
                st.session_state.failed_attempts += 1
                st.error(f"Invalid credentials. {MAX_FAILED_ATTEMPTS - st.session_state.failed_attempts} attempts left")
                if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    st.error("Account locked. Contact administrator")
                    st.stop()
                return
                
            st.session_state.current_user = login_user
            st.session_state.authorized = True
            st.session_state.page = "home"
            st.rerun()

# --- Dashboard Page ---
def dashboard_page():
    st.markdown('<h1 class="dashboard-title">📊 CyberVault Dashboard</h1>', unsafe_allow_html=True)
    
    # Stats Cards
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""
        <div class="card" style="text-align: center;">
            <h3>🔢</h3>
            <h2>{len(st.session_state.data_store.get(st.session_state.current_user, {}).get("entries", {}))}</h2>
            <p>Total Secrets</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="card" style="text-align: center;">
            <h3>🛡️</h3>
            <h2>AES-256</h2>
            <p>Encryption</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="card" style="text-align: center;">
            <h3>⚡</h3>
            <h2>100%</h2>
            <p>Secure</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Security Tips
    st.subheader("🔒 Vault Security Tips")
    tips = [
        "Use unique passkeys for each secret",
        "Never share your encryption keys",
        "Update passwords every 3 months",
        "Enable 2FA for extra security",
        "Stay alert for phishing attempts"
    ]
    
    for tip in tips:
        st.markdown(f"""
        <div class="card" style="padding: 12px 15px; margin-bottom: 8px;">
            <p>✓ {tip}</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Quick Actions
    st.markdown("---")
    st.subheader("🚀 Quick Actions")
    action_col1, action_col2 = st.columns(2)
    with action_col1:
        if st.button("🔒 Secure New Data", use_container_width=True):
            st.session_state.page = "store"
            st.rerun()
    with action_col2:
        if st.button("🔓 Access Data", use_container_width=True):
            st.session_state.page = "retrieve"
            st.rerun()

# --- Store Data Page ---
def store_data_page():
    st.markdown('<h1 class="dashboard-title">🔒 Secure Data</h1>', unsafe_allow_html=True)
    
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        
        data = st.text_area("Your Secret", placeholder="Enter text to secure", height=150)
        passkey = st.text_input("Encryption Passkey", type="password", placeholder="Set a strong passkey")
        
        if st.button("Secure & Save"):
            if not data or not passkey:
                st.error("All fields required")
                return
                
            encrypted = encrypt_data(data)
            if encrypted:
                hashed_key = hash_passkey(passkey)
                st.session_state.data_store.setdefault(st.session_state.current_user, {"entries": {}})["entries"][encrypted] = hashed_key
                save_data(st.session_state.data_store)
                st.success("Secret secured successfully!")
                st.code(encrypted, language="text")
            
        st.markdown('</div>', unsafe_allow_html=True)

# --- Retrieve Data Page ---
def retrieve_data_page():
    st.markdown('<h1 class="dashboard-title">🔓 Access Data</h1>', unsafe_allow_html=True)
    
    with st.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        
        encrypted = st.text_area("Encrypted Secret", placeholder="Paste encrypted data", height=100)
        passkey = st.text_input("Decryption Passkey", type="password", placeholder="Enter your passkey")
        
        if st.button("Unlock Secret"):
            if not encrypted or not passkey:
                st.error("All fields required")
                return
                
            entries = st.session_state.data_store.get(st.session_state.current_user, {}).get("entries", {})
            hashed_input = hash_passkey(passkey)
            
            if encrypted in entries and entries[encrypted] == hashed_input:
                decrypted = decrypt_data(encrypted)
                if decrypted:
                    st.success("Secret unlocked successfully!")
                    st.text_area("Unlocked Secret", decrypted, height=150)
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Invalid passkey or data. {MAX_FAILED_ATTEMPTS - st.session_state.failed_attempts} attempts left")
                if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    st.error("Too many failed attempts. Vault locked.")
                    st.session_state.authorized = False
                    st.session_state.current_user = ""
                    st.session_state.page = "login"
                    st.rerun()
                
        st.markdown('</div>', unsafe_allow_html=True)

# --- Main App ---
if st.session_state.authorized:
    st.sidebar.title(f"Welcome, {st.session_state.current_user}!")
    st.sidebar.markdown("---")
    
    if st.sidebar.button("🏠 CyberVault"):
        st.session_state.page = "home"
    if st.sidebar.button("💾 Secure Data"):
        st.session_state.page = "store"
    if st.sidebar.button("📂 Access Data"):
        st.session_state.page = "retrieve"
    if st.sidebar.button("🚪 Exit Vault"):
        st.session_state.authorized = False
        st.session_state.current_user = ""
        st.session_state.page = "login"
        st.rerun()

if not st.session_state.authorized:
    login_page()
else:
    if st.session_state.page == "home":
        dashboard_page()
    elif st.session_state.page == "store":
        store_data_page()
    elif st.session_state.page == "retrieve":
        retrieve_data_page()