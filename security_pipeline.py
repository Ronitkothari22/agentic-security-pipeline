import subprocess
import logging
import os
import json
from typing import List, Dict, Optional, Any
from pydantic import BaseModel
import ipaddress
from langgraph.graph import StateGraph, END
from langchain_core.pydantic_v1 import BaseModel as LangChainBaseModel

# Set up logging
log_dir = os.path.join(os.getcwd(), 'Logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
log_file = os.path.join(log_dir, 'security_pipeline.log')
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ScopeConfig(BaseModel):
    allowed_domains: List[str]
    allowed_ips: List[str] = []

    def __init__(self, **data):
        super().__init__(**data)
        self.allowed_domains = [d.lower() for d in self.allowed_domains]
        self.allowed_ips = [ipaddress.ip_network(ip, strict=False) for ip in self.allowed_ips]

    def is_in_scope(self, target: str) -> bool:
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in net for net in self.allowed_ips)
        except ValueError:
            target = target.lower()
            return any(target == d or target.endswith('.' + d) for d in self.allowed_domains)

class SecurityTask(BaseModel):
    task_type: str
    target: str
    parameters: Dict[str, str]
    status: str = 'pending'
    result: Optional[str] = None
    error: Optional[str] = None
    retries: int = 0

def run_security_tool(task: SecurityTask) -> str:
    logging.info(f"Starting {task.task_type} on {task.target}")
    wordlist_path = r"C:\wordlists\common.txt"
    sqlmap_path = r"C:\Tools\sqlmap\sqlmap.py"
    
    cmd_map = {
        'nmap': ['nmap', '-Pn', task.target, '-p', task.parameters.get('-p', '1-65535')],
        'gobuster': ['gobuster', 'dir', '-u', f"http://{task.target}", '-w', task.parameters.get('wordlist', wordlist_path), '-b', '400'],
        'ffuf': ['ffuf', '-u', f"http://{task.target}/FUZZ", '-w', task.parameters.get('wordlist', wordlist_path)],
        'sqlmap': ['python', sqlmap_path, '-u', task.target, '--batch', f"--level={task.parameters.get('level', '1')}"]
    }
    
    if task.task_type not in cmd_map:
        raise ValueError(f"Unknown task type: {task.task_type}")
    
    cmd = cmd_map[task.task_type]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        logging.info(f"Completed {task.task_type} on {task.target}")
        return result.stdout
    except subprocess.TimeoutExpired as e:
        logging.error(f"{task.task_type} on {task.target} timed out")
        return e.stdout or "Timed out"
    except subprocess.CalledProcessError as e:
        logging.error(f"{task.task_type} failed: {e.stderr}")
        return e.stdout or f"Failed: {e.stderr}"
    except FileNotFoundError:
        logging.error(f"Tool {task.task_type} not found.")
        raise RuntimeError(f"Tool {task.task_type} not found")

def parse_tool_output(task_type: str, output: str) -> Any:
    if task_type == 'nmap':
        return [int(line.split('/')[0].strip()) for line in output.splitlines() if '/tcp' in line and 'open' in line]
    elif task_type == 'gobuster':
        return [line.split()[0] for line in output.splitlines() if line.startswith('/')]
    elif task_type == 'ffuf':
        return [line.split()[1] for line in output.splitlines() if '[Status:' in line]
    elif task_type == 'sqlmap':
        return {'vulnerable': 'is vulnerable' in output.lower()}
    return output

class PipelineState(LangChainBaseModel):
    scope: ScopeConfig
    tasks: List[SecurityTask]
    findings: Dict[str, Any] = {}

    class Config:
        arbitrary_types_allowed = True

def execute_task(state: PipelineState) -> PipelineState:
    for task in state.tasks:
        if task.status != 'pending':
            continue
        if not state.scope.is_in_scope(task.target):
            task.status = 'failed'
            task.error = 'Target out of scope'
            continue
        task.status = 'running'
        try:
            task.result = run_security_tool(task)
            task.status = 'completed'
            findings = state.findings.setdefault(task.target, {})
            findings[task.task_type] = parse_tool_output(task.task_type, task.result)
        except Exception as e:
            task.retries += 1
            if task.retries < 3:
                task.status = 'pending'
                logging.info(f"Retrying {task.task_type} on {task.target} ({task.retries}/3)")
            else:
                task.status = 'failed'
                task.error = str(e)
    return state

def save_report(state: PipelineState) -> PipelineState:
    report = {
        "tasks": [task.dict() for task in state.tasks],
        "findings": state.findings,
        "scope": {"domains": state.scope.allowed_domains, "ips": [str(ip) for ip in state.scope.allowed_ips]}
    }
    report_path = os.path.join(os.getcwd(), 'audit_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    logging.info("Report saved: audit_report.json")
    return state

class SecurityPipeline:
    def __init__(self, scope: ScopeConfig, initial_tasks: List[SecurityTask] = []):
        self.state = PipelineState(scope=scope, tasks=initial_tasks)
        self.graph = StateGraph(PipelineState)
        self.graph.add_node("execute_task", execute_task)
        self.graph.add_node("save_report", save_report)
        self.graph.add_edge("execute_task", "save_report")
        self.graph.add_edge("save_report", END)
        self.graph.set_entry_point("execute_task")
        self.compiled = self.graph.compile()

    def run(self) -> PipelineState:
        # Run the graph and ensure the final state is returned as PipelineState
        final_state = self.compiled.invoke(self.state)
        # If final_state is a dict, convert it back to PipelineState
        if isinstance(final_state, dict):
            return PipelineState(
                scope=self.state.scope,  # Preserve original scope
                tasks=final_state.get("execute_task", {}).get("tasks", self.state.tasks),
                findings=final_state.get("save_report", {}).get("findings", self.state.findings)
            )
        return final_state  # Return as PipelineState if already correct