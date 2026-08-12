import streamlit as st
from pathlib import Path


def load_theme():
    """
    Load and inject the shared CyberLens industrial theme.

    Call this once, right after st.set_page_config(), on every
    page. It reads assets/theme.css (one level above /pages and
    /utils) and injects it with unsafe_allow_html=True — without
    that flag Streamlit escapes the <style> tag and prints it as
    plain text instead of applying it.
    """

    css_path = (
        Path(__file__).parent.parent
        / "assets"
        / "theme.css"
    )

    if css_path.exists():

        st.markdown(
            f"<style>{css_path.read_text()}</style>",
            unsafe_allow_html=True
        )