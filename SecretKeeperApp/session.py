import streamlit as st
import logging
import time

# Import the logout_user function from a separate module if necessary
# For now, we assume it’s defined in this file


def initialize_session():
    """Initialize the session state for user login."""
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = None


def logout_user():
    """Log out the user and reset session state."""
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.last_activity = None
    st.success("You have been logged out.")


# Set the timeout period in seconds
SESSION_TIMEOUT = 600  # 5 minutes


def check_session_timeout():
    """Check if the session has timed out due to inactivity."""
    # Initialize last_activity if not already set
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = time.time()

    if st.session_state.last_activity:
        elapsed_time = time.time() - st.session_state.last_activity
        if elapsed_time > SESSION_TIMEOUT:
            st.warning("Your session has timed out due to inactivity.")
            logout_user()  # Call the logout function
            logging.info("User session timed out.")

    # Update last activity time
    st.session_state.last_activity = time.time()
