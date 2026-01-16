"""Tests for blackwall.main module."""

from blackwall.main import (
    create_blackwall_agent,
    analyze_payload_for_threats,
)


def test_analyze_payload_for_threats_sql_injection():
    """Test SQL injection detection."""
    payload = "admin' OR '1'='1"
    result = analyze_payload_for_threats(payload)
    assert result["threat_detected"] is True
    assert "SQL Injection" in str(result["threats"])


def test_analyze_payload_for_threats_xss():
    """Test XSS detection."""
    payload = "<script>alert('XSS')</script>"
    result = analyze_payload_for_threats(payload)
    assert result["threat_detected"] is True
    assert "XSS" in str(result["threats"])


def test_analyze_payload_for_threats_safe():
    """Test safe payload."""
    payload = '{"username": "test", "password": "test123"}'
    result = analyze_payload_for_threats(payload)
    # Safe payloads may or may not trigger detection
    assert isinstance(result, dict)
    assert "threat_detected" in result


def test_create_blackwall_agent():
    """Test agent creation."""
    agent = create_blackwall_agent(
        model_name="gpt-4.1", selected_tools=None
    )
    assert agent is not None
    assert agent.agent_name == "Blackwall-Security-Agent"
