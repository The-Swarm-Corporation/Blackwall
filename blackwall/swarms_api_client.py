"""
Swarms API Client using httpx for agent completions.

This module provides a client for interacting with the Swarms API
(api.swarms.world) to execute agent completions.
"""

import json
import os
from typing import Any, Dict, List, Optional, Union

import httpx
from loguru import logger
from dotenv import load_dotenv

load_dotenv()


def get_swarms_api_key() -> str:
    """
    Get the Swarms API key from the environment variable.

    Retrieves the API key from the SWARMS_API_KEY environment variable.
    This function is used as a default value for API key parameters.

    Returns:
        The Swarms API key as a string

    Raises:
        ValueError: If the SWARMS_API_KEY environment variable is not set

    Note:
        The API key is required for all Swarms API requests. Set it in your
        environment or pass it directly to the SwarmsAPIClient constructor.
    """
    api_key = os.getenv("SWARMS_API_KEY")

    if not api_key:
        raise ValueError(
            "Swarms API key is required. Provide it as parameter or set "
            "SWARMS_API_KEY environment variable."
        )
    return api_key


class SwarmsAPIClient:
    """
    Client for interacting with the Swarms API for agent completions.

    This client provides both async and sync methods for executing agent
    completion requests to the Swarms API (api.swarms.world). It handles
    authentication, request formatting, and response parsing.

    The client uses httpx for HTTP requests and supports:
    - Async agent completions (recommended)
    - Sync agent completions (for compatibility)
    - Context manager support
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://api.swarms.world",
    ):
        """
        Initialize the Swarms API client.

        Creates an async HTTP client configured for the Swarms API with
        authentication headers and timeout settings.

        Args:
            api_key: API key for authentication. If not provided or None, will try
                     to get from SWARMS_API_KEY environment variable using
                     get_swarms_api_key().
            base_url: Base URL for the API (default: "https://api.swarms.world")

        Raises:
            ValueError: If api_key is None and SWARMS_API_KEY is not set

        Note:
            The client uses a 60-second timeout for all requests. The API key
            is included in the "x-api-key" header for authentication.
        """

        self.base_url = base_url.rstrip("/")

        # Get API key from parameter or environment
        if api_key is None:
            try:
                self.api_key = get_swarms_api_key()
            except ValueError:
                self.api_key = None
        else:
            self.api_key = api_key

        # Build headers - only include x-api-key if it's not None
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key is not None:
            headers["x-api-key"] = self.api_key

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
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
        Execute an agent completion request asynchronously.

        Sends a POST request to the Swarms API to execute an agent task.
        This is the recommended method for async applications.

        Args:
            agent_config: AgentSpec configuration dictionary containing:
                         - agent_name: Unique identifier for the agent
                         - description: Agent description
                         - system_prompt: System instructions
                         - model_name: AI model to use
                         - max_loops: Maximum execution iterations
                         - max_tokens: Maximum response tokens
                         - temperature: Response randomness (0.0-2.0)
                         - tools_list_dictionary: List of tool schemas
            task: The task or instruction for the agent to execute
            history: Conversation history or context (optional). Can be a dict
                    or list of message dicts for multi-turn conversations
            img: Single image URL for vision-enabled models (optional)
            imgs: Multiple image URLs for vision-enabled models (optional)
            stream: Enable streaming output (default: False)
            search_enabled: Enable web search capabilities (default: False)

        Returns:
            Dictionary containing:
            - job_id: Unique identifier for the completion job
            - success: Boolean indicating if the request succeeded
            - outputs: List of agent outputs (may contain function calls)
            - usage: Token usage statistics
            - timestamp: Request timestamp

        Raises:
            httpx.HTTPStatusError: If the API request fails (non-2xx status)

        Note:
            The response may contain function calls in the outputs that need
            to be executed. The SwarmsAgent class handles this automatically.
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
        Use this when you need synchronous execution (e.g., in non-async contexts).

        Args:
            agent_config: AgentSpec configuration dictionary (same as async method)
            task: The task or instruction for the agent to execute
            history: Conversation history or context (optional)
            img: Single image URL for vision-enabled models (optional)
            imgs: Multiple image URLs for vision-enabled models (optional)
            stream: Enable streaming output (default: False)
            search_enabled: Enable web search capabilities (default: False)

        Returns:
            Dictionary with the same structure as agent_completion()

        Raises:
            httpx.HTTPStatusError: If the API request fails (non-2xx status)

        Note:
            This method creates a new synchronous HTTP client for each request.
            For better performance in async contexts, use agent_completion() instead.
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
        """
        Close the async HTTP client and release resources.

        Should be called when the client is no longer needed to properly
        clean up connections. The client can also be used as a context
        manager which will automatically close it.
        """
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
    Agent wrapper that mimics the swarms.Agent interface but uses the Swarms API.

    This class provides a drop-in replacement for swarms.Agent that executes
    agent tasks via the Swarms API (api.swarms.world) instead of locally.
    It supports both synchronous and asynchronous execution, and automatically
    executes function calls returned by the agent.

    The agent can be configured with:
    - Custom system prompts and agent descriptions
    - Tool schemas for function calling
    - Tools mapping for executing function calls locally
    - Various model and generation parameters

    Key Features:
    - Automatic function call execution from agent responses
    - Support for both sync (run) and async (arun) methods
    - Verbose logging for debugging
    - Error handling and reporting
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
        tools_mapping: Optional[Dict[str, Any]] = None,
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
            tools_mapping: Dictionary mapping tool names to callable functions.
                          Used to execute function calls returned by the agent.
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
        self.tools_mapping = (
            tools_mapping or {}
        )  # Mapping of tool names to functions

        # Initialize API client
        self.api_client = SwarmsAPIClient(
            api_key=api_key, base_url=base_url
        )

    def run(self, task: str) -> str:
        """
        Run the agent with a given task (synchronous).

        Executes the agent task synchronously using the Swarms API. This method
        automatically processes function calls in the agent's response and
        executes them using the tools_mapping.

        Args:
            task: The task or instruction for the agent to execute. This should
                 be a clear, descriptive prompt that tells the agent what to do.

        Returns:
            String containing:
            - If function calls were executed: JSON-formatted summary with
              function_calls and text_outputs
            - If only text outputs: Concatenated text outputs
            - If error occurred: Error message string

        Note:
            Function calls in the agent response are automatically executed
            if the function name exists in tools_mapping. The results are
            included in the return value.

        Example:
            >>> agent = SwarmsAgent(agent_name="test", tools_mapping={"add": lambda x, y: x + y})
            >>> result = agent.run("Add 2 and 3 using the add function")
            >>> # Result will include the function call execution
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

            # Extract output from response and execute function calls
            if result.get("success"):
                outputs = result.get("outputs", [])

                # Process outputs to extract and execute function calls
                function_results = []
                text_outputs = []

                if isinstance(outputs, list):
                    for output in outputs:
                        if isinstance(output, dict):
                            content = output.get("content", [])
                            if isinstance(content, list):
                                for item in content:
                                    if (
                                        isinstance(item, dict)
                                        and item.get("type")
                                        == "function"
                                    ):
                                        # This is a function call
                                        func_data = item.get(
                                            "function", {}
                                        )
                                        func_name = func_data.get(
                                            "name"
                                        )
                                        func_args_str = func_data.get(
                                            "arguments", "{}"
                                        )

                                        if (
                                            func_name
                                            and func_name
                                            in self.tools_mapping
                                        ):
                                            try:
                                                # Parse arguments
                                                func_args = (
                                                    json.loads(
                                                        func_args_str
                                                    )
                                                    if isinstance(
                                                        func_args_str,
                                                        str,
                                                    )
                                                    else func_args_str
                                                )

                                                # Execute the function
                                                func = self.tools_mapping[
                                                    func_name
                                                ]
                                                if self.verbose:
                                                    logger.info(
                                                        f"Executing function: {func_name} with args: {func_args}"
                                                    )

                                                # Call the function
                                                if isinstance(
                                                    func_args, dict
                                                ):
                                                    func_result = func(
                                                        **func_args
                                                    )
                                                else:
                                                    func_result = (
                                                        func(
                                                            func_args
                                                        )
                                                    )

                                                function_results.append(
                                                    {
                                                        "function": func_name,
                                                        "result": func_result,
                                                    }
                                                )

                                                if self.verbose:
                                                    logger.info(
                                                        f"Function {func_name} result: {func_result}"
                                                    )
                                            except Exception as e:
                                                error_msg = f"Error executing function {func_name}: {str(e)}"
                                                logger.error(
                                                    error_msg
                                                )
                                                function_results.append(
                                                    {
                                                        "function": func_name,
                                                        "error": error_msg,
                                                    }
                                                )
                                    elif isinstance(
                                        item, (str, dict)
                                    ):
                                        # Text or other content
                                        text_outputs.append(str(item))
                            else:
                                text_outputs.append(str(output))
                        elif isinstance(output, str):
                            text_outputs.append(output)

                # Combine results
                if function_results:
                    result_summary = {
                        "function_calls": function_results,
                        "text_outputs": (
                            text_outputs if text_outputs else None
                        ),
                    }
                    return (
                        json.dumps(result_summary, indent=2)
                        if self.verbose
                        else str(result_summary)
                    )
                elif text_outputs:
                    return "\n".join(text_outputs)
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

        Executes the agent task asynchronously using the Swarms API. This is
        the recommended method for async applications. Like run(), it automatically
        processes and executes function calls from the agent response.

        Args:
            task: The task or instruction for the agent to execute. This should
                 be a clear, descriptive prompt that tells the agent what to do.

        Returns:
            String containing:
            - If function calls were executed: JSON-formatted summary with
              function_calls and text_outputs
            - If only text outputs: Concatenated text outputs
            - If error occurred: Error message string

        Note:
            Function calls in the agent response are automatically executed
            if the function name exists in tools_mapping. The results are
            included in the return value.

        Example:
            >>> agent = SwarmsAgent(agent_name="test", tools_mapping={"analyze": analyze_func})
            >>> result = await agent.arun("Analyze this payload for threats")
            >>> # Result will include function call execution results
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

            # Extract output from response and execute function calls
            if result.get("success"):
                outputs = result.get("outputs", [])

                # Process outputs to extract and execute function calls
                function_results = []
                text_outputs = []

                if isinstance(outputs, list):
                    for output in outputs:
                        if isinstance(output, dict):
                            content = output.get("content", [])
                            if isinstance(content, list):
                                for item in content:
                                    if (
                                        isinstance(item, dict)
                                        and item.get("type")
                                        == "function"
                                    ):
                                        # This is a function call
                                        func_data = item.get(
                                            "function", {}
                                        )
                                        func_name = func_data.get(
                                            "name"
                                        )
                                        func_args_str = func_data.get(
                                            "arguments", "{}"
                                        )

                                        if (
                                            func_name
                                            and func_name
                                            in self.tools_mapping
                                        ):
                                            try:
                                                # Parse arguments
                                                func_args = (
                                                    json.loads(
                                                        func_args_str
                                                    )
                                                    if isinstance(
                                                        func_args_str,
                                                        str,
                                                    )
                                                    else func_args_str
                                                )

                                                # Execute the function
                                                func = self.tools_mapping[
                                                    func_name
                                                ]
                                                if self.verbose:
                                                    logger.info(
                                                        f"Executing function: {func_name} with args: {func_args}"
                                                    )

                                                # Call the function
                                                if isinstance(
                                                    func_args, dict
                                                ):
                                                    func_result = func(
                                                        **func_args
                                                    )
                                                else:
                                                    func_result = (
                                                        func(
                                                            func_args
                                                        )
                                                    )

                                                function_results.append(
                                                    {
                                                        "function": func_name,
                                                        "result": func_result,
                                                    }
                                                )

                                                if self.verbose:
                                                    logger.info(
                                                        f"Function {func_name} result: {func_result}"
                                                    )
                                            except Exception as e:
                                                error_msg = f"Error executing function {func_name}: {str(e)}"
                                                logger.error(
                                                    error_msg
                                                )
                                                function_results.append(
                                                    {
                                                        "function": func_name,
                                                        "error": error_msg,
                                                    }
                                                )
                                    elif isinstance(
                                        item, (str, dict)
                                    ):
                                        # Text or other content
                                        text_outputs.append(str(item))
                            else:
                                text_outputs.append(str(output))
                        elif isinstance(output, str):
                            text_outputs.append(output)

                # Combine results
                if function_results:
                    result_summary = {
                        "function_calls": function_results,
                        "text_outputs": (
                            text_outputs if text_outputs else None
                        ),
                    }
                    return (
                        json.dumps(result_summary, indent=2)
                        if self.verbose
                        else str(result_summary)
                    )
                elif text_outputs:
                    return "\n".join(text_outputs)
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
