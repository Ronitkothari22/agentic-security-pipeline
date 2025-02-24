import streamlit as st
from security_pipeline import ScopeConfig, SecurityTask, SecurityPipeline
import os
import json

st.title("Real-Time Cybersecurity Pipeline")

st.header("Configure Scope")
domains = st.text_area("Allowed Domains (one per line)", "localhost")
ips = st.text_area("Allowed IPs/CIDRs (one per line)", "127.0.0.0/24")

if 'initial_tasks' not in st.session_state:
    st.session_state.initial_tasks = []

st.header("Create Initial Tasks")
with st.form(key='task_form'):
    task_type = st.selectbox("Task Type", ["nmap", "gobuster", "ffuf", "sqlmap"])
    target = st.text_input("Target", "127.0.0.1")
    parameters = {}
    if task_type == "nmap":
        ports = st.text_input("Ports", "80")
        parameters["-p"] = ports
    elif task_type in ["gobuster", "ffuf"]:
        wordlist = st.text_input("Wordlist", r"C:\wordlists\common.txt")
        parameters["wordlist"] = wordlist
    elif task_type == "sqlmap":
        parameters["level"] = st.text_input("Level", "1")
    submit = st.form_submit_button(label="Add Task")
    if submit:
        task = SecurityTask(task_type=task_type, target=target, parameters=parameters)
        st.session_state.initial_tasks.append(task)
        st.success(f"Task {task_type} added for {target}")

st.write("Initial Tasks:")
if st.session_state.initial_tasks:
    for task in st.session_state.initial_tasks:
        st.write(f"- {task.task_type} on {task.target} (Status: {task.status})")
else:
    st.write("No tasks added yet.")

if st.button("Run Pipeline"):
    if not st.session_state.initial_tasks:
        st.warning("Please add at least one task before running the pipeline.")
    else:
        scope = ScopeConfig(allowed_domains=domains.splitlines(), allowed_ips=ips.splitlines())
        pipeline = SecurityPipeline(scope, st.session_state.initial_tasks)
        with st.spinner("Running security pipeline..."):
            state = pipeline.run()
        st.success("Pipeline completed! Report saved as audit_report.json")

        st.header("Findings")
        if state['findings']:
            for target, data in state['findings'].items():
                st.subheader(target)
                st.json(data)
        else:
            st.write("No findings yet.")

        st.header("Execution Logs")
        log_file = os.path.join(os.getcwd(), 'Logs', 'security_pipeline.log')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = f.read()
            st.text_area("Logs", logs, height=300)
        else:
            st.write("No logs available yet.")

        st.header("Final Audit Report")
        report_file = os.path.join(os.getcwd(), 'audit_report.json')
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                report = json.load(f)
            st.json(report)
        else:
            st.write("Report not generated yet.")