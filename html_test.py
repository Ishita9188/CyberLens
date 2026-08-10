import streamlit as st

st.set_page_config(
    page_title="HTML Test",
    layout="wide"
)

st.markdown(
    """
    <div style="
        background: #0b1a2b;
        border: 3px solid #38bdf8;
        border-radius: 15px;
        padding: 40px;
        text-align: center;
        color: white;
        font-size: 30px;
        font-weight: bold;
    ">
        CYBERLENS HTML TEST
    </div>
    """,
    unsafe_allow_html=True
)