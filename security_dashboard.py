import streamlit as st
from security_pipeline import ScopeConfig, SecurityTask, SecurityPipeline
import os
import json

st.title("Real-Time Cybersecurity Pipeline")

st.header("Configure Scope")
domains = st.text_area("Allowed Domains (one per line)", "google.com")
ips = st.text_area("Allowed IPs/CIDRs (one per line)", "142.251.42.0/24")

if 'tasks' not in st.session_state:
    st.session_state.tasks = []

st.header("Add Tasks")
with st.form(key='task_form'):
    task_type = st.selectbox("Task Type", ["nmap", "gobuster", "ffuf", "sqlmap"])
    target = st.text_input("Target", "google.com")
    parameters = {}
    if task_type == "nmap":
        ports = st.text_input("Ports (e.g., 80,443 or 1-65535)", "1-65535")
        parameters["-p"] = ports
    elif task_type in ["gobuster", "ffuf"]:
        wordlist = st.text_input("Wordlist Path", r"C:\wordlists\common.txt")
        parameters["wordlist"] = wordlist
    elif task_type == "sqlmap":
        level = st.text_input("Level (1-5)", "1")
        parameters["level"] = level
    submit = st.form_submit_button(label="Add Task")
    if submit and target:
        task = SecurityTask(task_type=task_type, target=target, parameters=parameters)
        st.session_state.tasks.append(task)
        st.success(f"Added {task_type} task for {target}")

st.header("Tasks")
if st.session_state.tasks:
    for task in st.session_state.tasks:
        st.write(f"- {task.task_type} on {task.target} (Status: {task.status})")
else:
    st.write("No tasks added yet.")

if st.button("Run Pipeline"):
    if not st.session_state.tasks:
        st.warning("Please add at least one task before running the pipeline.")
    else:
        scope = ScopeConfig(allowed_domains=domains.splitlines(), allowed_ips=ips.splitlines())
        pipeline = SecurityPipeline(scope, st.session_state.tasks)
        with st.spinner("Running pipeline..."):
            state = pipeline.run()
        st.success("Pipeline completed!")

        st.header("Findings")
        if state.findings:
            for target, data in state.findings.items():
                st.subheader(target)
                st.json(data)
        else:
            st.write("No findings yet.")

        st.header("Execution Logs")
        log_file = os.path.join(os.getcwd(), 'Logs', 'security_pipeline.log')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                st.text_area("Logs", f.read(), height=300)

        st.header("Audit Report")
        report_file = os.path.join(os.getcwd(), 'audit_report.json')
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                st.json(json.load(f))