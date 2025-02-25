import pytest
from security_pipeline import ScopeConfig, SecurityTask, SecurityPipeline, run_security_tool, parse_tool_output
from unittest.mock import patch, Mock
import subprocess

def test_scope_config():
    scope = ScopeConfig(allowed_domains=["example.com"], allowed_ips=["192.168.1.0/24"])
    assert scope.is_in_scope("example.com") == True, "Exact domain should be in scope"
    assert scope.is_in_scope("sub.example.com") == True, "Subdomain should be in scope"
    assert scope.is_in_scope("other.com") == False, "Unrelated domain should be out of scope"
    assert scope.is_in_scope("192.168.1.10") == True, "IP in range should be in scope"
    assert scope.is_in_scope("10.0.0.1") == False, "IP out of range should be out of scope"

@patch('subprocess.run')
def test_run_security_tool_nmap(mock_run):
    mock_run.return_value = Mock(stdout="PORT     STATE SERVICE\n80/tcp   open  http", returncode=0)
    task = SecurityTask(task_type="nmap", target="example.com", parameters={"-p": "80"})
    result = run_security_tool(task)
    assert "80/tcp   open  http" in result, "Nmap output should contain expected port info"
    mock_run.assert_called_once_with(
        ['nmap', '-Pn', 'example.com', '-p', '80'],
        capture_output=True,
        text=True,
        check=True,
        timeout=300
    )

@patch('subprocess.run')
def test_run_security_tool_gobuster(mock_run):
    mock_run.return_value = Mock(stdout="/test (Status: 200)", returncode=0)
    task = SecurityTask(task_type="gobuster", target="example.com", parameters={"wordlist": r"C:\wordlists\common.txt"})
    result = run_security_tool(task)
    assert "/test" in result, "Gobuster output should contain discovered path"
    mock_run.assert_called_once_with(
        ['gobuster', 'dir', '-u', 'http://example.com', '-w', r"C:\wordlists\common.txt", '-b', '400'],
        capture_output=True,
        text=True,
        check=True,
        timeout=300
    )

@patch('subprocess.run')
def test_failure_retry(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(1, "cmd", stderr="Execution failed")
    scope = ScopeConfig(allowed_domains=["example.com"], allowed_ips=[])
    task = SecurityTask(task_type="nmap", target="example.com", parameters={"-p": "80"})
    pipeline = SecurityPipeline(scope, [task])
    state = pipeline.run()
    assert state.tasks[0].retries == 3, "Task should retry 3 times"
    assert state.tasks[0].status == 'failed', "Task should fail after max retries"
    assert "Execution failed" in state.tasks[0].error, "Error message should be captured"
    assert mock_run.call_count == 3, "Subprocess should be called 3 times due to retries"

def test_parse_nmap_output():
    sample_output = """
    Starting Nmap 7.95
    Nmap scan report for example.com (93.184.216.34)
    PORT     STATE SERVICE
    80/tcp   open  http
    443/tcp  open  https
    Nmap done: 1 IP address scanned
    """
    ports = parse_tool_output("nmap", sample_output)
    assert ports == [80, 443], "Should extract open ports 80 and 443"

def test_parse_gobuster_output():
    sample_output = """
    /admin (Status: 200)
    /test (Status: 301)
    """
    dirs = parse_tool_output("gobuster", sample_output)
    assert dirs == ["/admin", "/test"], "Should extract discovered directories"

def test_parse_ffuf_output():
    sample_output = """
    [Status: 200, Size: 123] /index
    [Status: 404, Size: 456] /notfound
    """
    statuses = parse_tool_output("ffuf", sample_output)
    assert statuses == ["200", "404"], "Should extract status codes"

def test_parse_sqlmap_output():
    sample_output = """
    [INFO] the back-end DBMS is MySQL
    [INFO] URL is vulnerable to SQL injection
    """
    result = parse_tool_output("sqlmap", sample_output)
    assert result == {'vulnerable': True}, "Should detect SQL injection vulnerability"

@patch('subprocess.run')
def test_pipeline_execution(mock_run):
    mock_run.return_value = Mock(stdout="PORT     STATE SERVICE\n80/tcp   open  http", returncode=0)
    scope = ScopeConfig(allowed_domains=["example.com"], allowed_ips=[])
    task = SecurityTask(task_type="nmap", target="example.com", parameters={"-p": "80"})
    pipeline = SecurityPipeline(scope, [task])
    state = pipeline.run()
    assert state.tasks[0].status == "completed", "Task should complete successfully"
    assert state.findings["example.com"]["nmap"] == [80], "Findings should contain parsed nmap output"
    assert mock_run.called, "Subprocess should be called"

@patch('subprocess.run')
def test_pipeline_out_of_scope(mock_run):
    mock_run.return_value = Mock(stdout="PORT     STATE SERVICE\n80/tcp   open  http", returncode=0)
    scope = ScopeConfig(allowed_domains=["example.com"], allowed_ips=[])
    task = SecurityTask(task_type="nmap", target="other.com", parameters={"-p": "80"})
    pipeline = SecurityPipeline(scope, [task])
    state = pipeline.run()
    assert state.tasks[0].status == "failed", "Out-of-scope task should fail"
    assert state.tasks[0].error == "Target out of scope", "Error should indicate scope violation"
    assert not mock_run.called, "Subprocess should not be called for out-of-scope target"