"""
Swarms API Client using httpx for agent completions.

This module provides a client for interacting with the Swarms API
(api.swarms.world) to execute agent completions.
"""

import os
from typing import Any, Dict, List, Optional, Union

import httpx
from loguru import logger


class SwarmsAPIClient:
    """Client for Swarms API agent completions."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.swarms.world",
    ):
        """
        Initialize the Swarms API client.

        Args:
            api_key: API key for authentication. If not provided, will try
                     to get from SWARMS_API_KEY environment variable.
            base_url: Base URL for the API (default: https://api.swarms.world)
        """
        self.api_key = api_key or os.getenv("SWARMS_API_KEY")
        if not self.api_key:
            raise ValueError(
                "API key is required. Provide it as parameter or set "
                "SWARMS_API_KEY environment variable."
            )

        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "x-api-key": self.api_key,
                "Content-Type": "application/json",
            },
            timeout=60.0,
        )

    async def agent_completion(
        self,
        agent_config: Dict[str, Any],
        task: str,
        history: Optional[Union[Dict, List[Dict]]] = None,
        img: Optional[str] = None,
        imgs: Optional[List[str]] = None,
        stream: bool = False,
        search_enabled: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute an agent completion request.

        Args:
            agent_config: AgentSpec configuration object
            task: The task or instruction for the agent to execute
            history: Conversation history or context (optional)
            img: Single image URL for vision-enabled models (optional)
            imgs: Multiple image URLs for vision-enabled models (optional)
            stream: Enable streaming output (default: False)
            search_enabled: Enable search capabilities (default: False)

        Returns:
            AgentCompletionOutput object with job_id, success, outputs, etc.
        """
        payload = {
            "agent_config": agent_config,
            "task": task,
        }

        if history is not None:
            payload["history"] = history
        if img is not None:
            payload["img"] = img
        if imgs is not None:
            payload["imgs"] = imgs
        if stream:
            payload["stream"] = stream
        if search_enabled:
            payload["search_enabled"] = search_enabled

        logger.info(
            f"Making agent completion request to {self.base_url}/v1/agent/completions"
        )
        logger.debug(f"Request payload: {payload}")

        response = await self.client.post(
            "/v1/agent/completions", json=payload
        )
        response.raise_for_status()

        result = response.json()
        logger.info(
            f"Agent completion response received: success={result.get('success')}, job_id={result.get('job_id')}"
        )
        logger.debug(f"Full response: {result}")

        return result

    async def agent_completion_sync(
        self,
        agent_config: Dict[str, Any],
        task: str,
        history: Optional[Union[Dict, List[Dict]]] = None,
        img: Optional[str] = None,
        imgs: Optional[List[str]] = None,
        stream: bool = False,
        search_enabled: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute an agent completion request synchronously.

        This is a convenience method that uses httpx in sync mode.
        Use this when you need synchronous execution.

        Args:
            agent_config: AgentSpec configuration object
            task: The task or instruction for the agent to execute
            history: Conversation history or context (optional)
            img: Single image URL for vision-enabled models (optional)
            imgs: Multiple image URLs for vision-enabled models (optional)
            stream: Enable streaming output (default: False)
            search_enabled: Enable search capabilities (default: False)

        Returns:
            AgentCompletionOutput object with job_id, success, outputs, etc.
        """
        payload = {
            "agent_config": agent_config,
            "task": task,
        }

        if history is not None:
            payload["history"] = history
        if img is not None:
            payload["img"] = img
        if imgs is not None:
            payload["imgs"] = imgs
        if stream:
            payload["stream"] = stream
        if search_enabled:
            payload["search_enabled"] = search_enabled

        logger.info(
            f"Making agent completion request (sync) to {self.base_url}/v1/agent/completions"
        )
        logger.debug(f"Request payload: {payload}")

        with httpx.Client(
            base_url=self.base_url,
            headers={
                "x-api-key": self.api_key,
                "Content-Type": "application/json",
            },
            timeout=60.0,
        ) as client:
            response = client.post(
                "/v1/agent/completions", json=payload
            )
            response.raise_for_status()

            result = response.json()
            logger.info(
                f"Agent completion response received (sync): success={result.get('success')}, job_id={result.get('job_id')}"
            )
            logger.debug(f"Full response: {result}")

            return result

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        # For sync usage, we don't need to close async client here
        pass


class SwarmsAgent:
    """
    Agent wrapper that mimics the swarms.Agent interface
    but uses the Swarms API instead.
    """

    def __init__(
        self,
        agent_name: str,
        agent_description: str = "",
        system_prompt: str = "",
        model_name: str = "gpt-4.1",
        max_loops: int = 1,
        max_tokens: int = 8192,
        temperature: float = 0.5,
        tools: Optional[List] = None,
        tools_list_dictionary: Optional[List[Dict]] = None,
        verbose: bool = False,
        tool_call_summary: bool = True,
        dynamic_temperature_enabled: bool = True,
        api_key: Optional[str] = None,
        base_url: str = "https://api.swarms.world",
        **kwargs,
    ):
        """
        Initialize a SwarmsAgent.

        Args:
            agent_name: Unique identifier for the agent
            agent_description: Detailed explanation of agent's purpose
            system_prompt: Initial instructions guiding agent behavior
            model_name: AI model to use (default: "gpt-4.1")
            max_loops: Maximum execution iterations (default: 1)
            max_tokens: Maximum tokens for agent responses (default: 8192)
            temperature: Controls response randomness 0.0-2.0 (default: 0.5)
            tools: List of tools (not directly supported in API, but kept
                   for compatibility)
            tools_list_dictionary: List of tool schemas (dict format) to pass
                                  to the API
            verbose: Enable verbose output (default: False)
            tool_call_summary: Enable tool call summarization (default: True)
            dynamic_temperature_enabled: Dynamic temperature adjustment
                                         (default: True)
            api_key: API key for authentication
            base_url: Base URL for the API
            **kwargs: Additional arguments (ignored for compatibility)
        """
        self.agent_name = agent_name
        self.agent_description = agent_description
        self.system_prompt = system_prompt
        self.model_name = model_name
        self.max_loops = max_loops
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.tools = tools or []
        self.tools_list_dictionary = tools_list_dictionary
        self.verbose = verbose
        self.tool_call_summary = tool_call_summary
        self.dynamic_temperature_enabled = dynamic_temperature_enabled

        # Initialize API client
        self.api_client = SwarmsAPIClient(
            api_key=api_key, base_url=base_url
        )

    def run(self, task: str) -> str:
        """
        Run the agent with a given task (synchronous).

        Args:
            task: The task or instruction for the agent to execute

        Returns:
            Agent output as string
        """
        agent_config = {
            "agent_name": self.agent_name,
            "description": self.agent_description,
            "system_prompt": self.system_prompt,
            "model_name": self.model_name,
            "max_loops": self.max_loops,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "tool_call_summary": self.tool_call_summary,
            "dynamic_temperature_enabled": self.dynamic_temperature_enabled,
        }

        # Add tools_list_dictionary if provided
        if self.tools_list_dictionary:
            agent_config["tools_list_dictionary"] = (
                self.tools_list_dictionary
            )

        try:
            logger.info(
                f"Running agent '{self.agent_name}' with task: {task[:100]}..."
                if len(task) > 100
                else f"Running agent '{self.agent_name}' with task: {task}"
            )

            result = self.api_client.agent_completion_sync(
                agent_config=agent_config, task=task
            )

            if self.verbose:
                logger.info(f"Agent Response: {result}")
                print(f"Agent Response: {result}")

            # Extract output from response
            if result.get("success"):
                outputs = result.get("outputs", "")
                if isinstance(outputs, str):
                    return outputs
                elif isinstance(outputs, dict):
                    # If outputs is a dict, try to extract meaningful content
                    return str(outputs)
                else:
                    return str(outputs)
            else:
                error_msg = f"Agent execution failed: {result}"
                if self.verbose:
                    print(error_msg)
                return error_msg

        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP error: {e.response.status_code} - {e.response.text}"
            if self.verbose:
                print(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"Error running agent: {str(e)}"
            if self.verbose:
                print(error_msg)
            return error_msg

    async def arun(self, task: str) -> str:
        """
        Run the agent with a given task (asynchronous).

        Args:
            task: The task or instruction for the agent to execute

        Returns:
            Agent output as string
        """
        agent_config = {
            "agent_name": self.agent_name,
            "description": self.agent_description,
            "system_prompt": self.system_prompt,
            "model_name": self.model_name,
            "max_loops": self.max_loops,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "tool_call_summary": self.tool_call_summary,
            "dynamic_temperature_enabled": self.dynamic_temperature_enabled,
        }

        # Add tools_list_dictionary if provided
        if self.tools_list_dictionary:
            agent_config["tools_list_dictionary"] = (
                self.tools_list_dictionary
            )

        try:
            logger.info(
                f"Running agent '{self.agent_name}' (async) with task: {task[:100]}..."
                if len(task) > 100
                else f"Running agent '{self.agent_name}' (async) with task: {task}"
            )

            result = await self.api_client.agent_completion(
                agent_config=agent_config, task=task
            )

            if self.verbose:
                logger.info(f"Agent Response: {result}")
                print(f"Agent Response: {result}")

            # Extract output from response
            if result.get("success"):
                outputs = result.get("outputs", "")
                if isinstance(outputs, str):
                    return outputs
                elif isinstance(outputs, dict):
                    return str(outputs)
                else:
                    return str(outputs)
            else:
                error_msg = f"Agent execution failed: {result}"
                logger.error(error_msg)
                if self.verbose:
                    print(error_msg)
                return error_msg

        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP error: {e.response.status_code} - {e.response.text}"
            logger.error(
                f"HTTP error in agent execution (async): {error_msg}"
            )
            if self.verbose:
                print(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"Error running agent: {str(e)}"
            logger.exception(
                f"Exception in agent execution (async): {error_msg}"
            )
            if self.verbose:
                print(error_msg)
            return error_msg

    async def close(self):
        """Close the API client."""
        await self.api_client.close()
