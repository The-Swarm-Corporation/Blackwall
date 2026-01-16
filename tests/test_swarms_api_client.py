"""Tests for blackwall.swarms_api_client module."""

import pytest
from blackwall.swarms_api_client import SwarmsAPIClient, SwarmsAgent


def test_swarms_api_client_initialization():
    """Test SwarmsAPIClient initialization."""
    with pytest.raises(ValueError):
        # Should raise error if no API key provided
        client = SwarmsAPIClient(api_key=None)
        # This won't be reached, but included for clarity


def test_swarms_agent_initialization():
    """Test SwarmsAgent initialization."""
    # This will fail without API key, but we can test structure
    with pytest.raises(ValueError):
        agent = SwarmsAgent(
            agent_name="test-agent",
            agent_description="Test agent",
            api_key=None,
        )
