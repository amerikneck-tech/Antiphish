"""Streamlit UI for AntiPhish MVP.

Run locally:  pip install streamlit  ->  streamlit run app.py
"""
import streamlit as st

from antiphish.detector import analyze_email

st.set_page_config(page_title="AntiPhish MVP", page_icon="🛡️")
st.title("🛡️ AntiPhish — Email Risk Analyzer")
st.caption("MVP: heuristics + ML text classifier. For demo use.")

with st.form("email_form"):
    subject = st.text_input("Subject", "")
    body = st.text_area("Body", "", height=160)
    sender = st.text_input("From (sender)", "")
    c1, c2, c3 = st.columns(3)
    spf = c1.selectbox("SPF", ["pass", "fail", "none", ""], index=3)
    dkim = c2.selectbox("DKIM", ["pass", "fail", "none", ""], index=3)
    dmarc = c3.selectbox("DMARC", ["pass", "fail", "none", ""], index=3)
    files = st.file_uploader("Attachments (zip, pdf, docx, html, svg, ics, png...)",
                             accept_multiple_files=True)
    use_llm = st.checkbox("Use Qwen AI judge", value=False)
    submitted = st.form_submit_button("Analyze", type="primary")

if submitted and (subject or body or files):
    email = {"subject": subject, "body": body, "sender": sender,
             "spf": spf or None, "dkim": dkim or None, "dmarc": dmarc or None,
             "attachments": [f.name for f in files or []],
             "attachment_data": {f.name: f.getvalue() for f in files or []}}
    r = analyze_email(email, use_llm=use_llm)

    colors = {"LOW": "green", "SUSPICIOUS": "orange", "HIGH": "red", "CRITICAL": "darkred"}
    st.markdown(f"## Risk score: **{r['score']} / 100** — :{colors[r['level']]}[**{r['level']}**]")
    st.progress(int(r["score"]))
    st.info(r["verdict"])
    st.metric("ML phishing probability", f"{r['ml_phishing_probability']*100:.1f}%")

    if r["urls_found"]:
        st.subheader("URLs found")
        for u in r["urls_found"]:
            st.code(u)
    if r["signals"]:
        st.subheader("Detected signals")
        for sig in r["signals"]:
            st.write(f"**{sig['weight']} pts** · `{sig['signal']}` — {sig['detail']}")
    if r.get("attachment_findings"):
        with st.expander("Attachment analysis details"):
            for line in r["attachment_findings"]:
                st.text(line)
