import streamlit as st
from pathlib import Path


def load_theme2():
    """
    Load and inject the Organization Dashboard's own CSS.

    This is intentionally separate from utils/theme.py — it
    only reads assets/theme2.css and only applies to whatever
    page calls it, so this stylesheet can be edited without
    touching the shared theme used by the other pages.

    Call this once, right after st.set_page_config().
    """

    css_path = (
        Path(__file__).parent.parent
        / "assets"
        / "theme2.css"
    )

    if css_path.exists():

        st.markdown(
            f"<style>{css_path.read_text()}</style>",
            unsafe_allow_html=True
        )