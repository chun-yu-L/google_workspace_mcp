import inspect
import logging
from functools import wraps
from typing import Dict, List, Optional, Any, Callable, Union, Tuple

from google.auth.exceptions import RefreshError
from auth.google_auth import get_authenticated_google_service, GoogleAuthenticationError
from auth.scopes import (
    GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE, GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE, GMAIL_LABELS_SCOPE,
    DRIVE_READONLY_SCOPE, DRIVE_FILE_SCOPE,
    DOCS_READONLY_SCOPE, DOCS_WRITE_SCOPE,
    CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE,
    SHEETS_READONLY_SCOPE, SHEETS_WRITE_SCOPE,
    CHAT_READONLY_SCOPE, CHAT_WRITE_SCOPE, CHAT_SPACES_SCOPE,
    FORMS_BODY_SCOPE, FORMS_BODY_READONLY_SCOPE, FORMS_RESPONSES_READONLY_SCOPE,
    SLIDES_SCOPE, SLIDES_READONLY_SCOPE,
    TASKS_SCOPE, TASKS_READONLY_SCOPE,
    CUSTOM_SEARCH_SCOPE
)

logger = logging.getLogger(__name__)

# Service configuration mapping
SERVICE_CONFIGS = {
    "gmail": {"service": "gmail", "version": "v1"},
    "drive": {"service": "drive", "version": "v3"},
    "calendar": {"service": "calendar", "version": "v3"},
    "docs": {"service": "docs", "version": "v1"},
    "sheets": {"service": "sheets", "version": "v4"},
    "chat": {"service": "chat", "version": "v1"},
    "forms": {"service": "forms", "version": "v1"},
    "slides": {"service": "slides", "version": "v1"},
    "tasks": {"service": "tasks", "version": "v1"},
    "customsearch": {"service": "customsearch", "version": "v1"}
}


# Scope group definitions for easy reference
SCOPE_GROUPS = {
    # Gmail scopes
    "gmail_read": GMAIL_READONLY_SCOPE,
    "gmail_send": GMAIL_SEND_SCOPE,
    "gmail_compose": GMAIL_COMPOSE_SCOPE,
    "gmail_modify": GMAIL_MODIFY_SCOPE,
    "gmail_labels": GMAIL_LABELS_SCOPE,

    # Drive scopes
    "drive_read": DRIVE_READONLY_SCOPE,
    "drive_file": DRIVE_FILE_SCOPE,

    # Docs scopes
    "docs_read": DOCS_READONLY_SCOPE,
    "docs_write": DOCS_WRITE_SCOPE,

    # Calendar scopes
    "calendar_read": CALENDAR_READONLY_SCOPE,
    "calendar_events": CALENDAR_EVENTS_SCOPE,

    # Sheets scopes
    "sheets_read": SHEETS_READONLY_SCOPE,
    "sheets_write": SHEETS_WRITE_SCOPE,

    # Chat scopes
    "chat_read": CHAT_READONLY_SCOPE,
    "chat_write": CHAT_WRITE_SCOPE,
    "chat_spaces": CHAT_SPACES_SCOPE,

    # Forms scopes
    "forms": FORMS_BODY_SCOPE,
    "forms_read": FORMS_BODY_READONLY_SCOPE,
    "forms_responses_read": FORMS_RESPONSES_READONLY_SCOPE,

    # Slides scopes
    "slides": SLIDES_SCOPE,
    "slides_read": SLIDES_READONLY_SCOPE,

    # Tasks scopes
    "tasks": TASKS_SCOPE,
    "tasks_read": TASKS_READONLY_SCOPE,
    
    # Custom Search scope
    "customsearch": CUSTOM_SEARCH_SCOPE,
}


def _resolve_scopes(required_scopes: Union[str, List[str]]) -> List[str]:
    """Resolve scope names to actual scope URLs."""
    if isinstance(required_scopes, str):
        if required_scopes in SCOPE_GROUPS:
            return [SCOPE_GROUPS[required_scopes]]
        else:
            return [required_scopes]

    resolved = []
    for scope in required_scopes:
        if scope in SCOPE_GROUPS:
            resolved.append(SCOPE_GROUPS[scope])
        else:
            resolved.append(scope)
    return resolved


def _validate_auth_parameters(
    access_token: str,
    refresh_token: str,
    token_scopes: List[str],
    service_type: str,
    func_name: str,
) -> Optional[str]:
    """
    Validate authentication parameters and service configuration.

    Args:
        access_token: Google access token
        refresh_token: Google refresh token
        token_scopes: List of token scopes
        service_type: Type of Google service
        func_name: Name of the calling function (for error logging)

    Returns:
        None if validation passes, error message string if validation fails
    """
    # Validate required authentication parameters
    required_params = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_scopes": token_scopes,
    }
    missing = [k for k, v in required_params.items() if not v]
    if missing:
        logger.error(
            f"Missing authentication parameters: {', '.join(missing)} for function {func_name}."
        )
        return "Internal system error. Please contact customer support."

    # Validate service type
    if service_type not in SERVICE_CONFIGS:
        logger.error(f"Unknown service type: {service_type} in function {func_name}")
        return "Internal system error. Please contact customer support."

    return None  # Validation passed


def _handle_token_refresh_error(error: RefreshError, service_name: str) -> str:
    """
    Handle token refresh errors gracefully, particularly expired/revoked tokens.

    Args:
        error: The RefreshError that occurred
        service_name: Name of the Google service

    Returns:
        A user-friendly error message with instructions for reauthentication
    """
    error_str = str(error)

    service_display_name = f"Google {service_name.title()}"

    if 'invalid_grant' in error_str.lower() or 'expired or revoked' in error_str.lower():
        logger.warning(f"Token expired or revoked for accessing {service_name}")

        return (
            f"**Authentication Required: Token Expired/Revoked for {service_display_name}**\n\n"
            f"Your Google authentication token has expired or been revoked. "
            f"This commonly happens when:\n"
            f"- The token has been unused for an extended period\n"
            f"- You've changed your Google account password\n"
            f"- You've revoked access to the application\n\n"
            f"**To fix this, please reauthorize the application by following these steps:**\n"
            f"1. Go to your application's **Personal Settings Page**\n"
            f"2. Find the section for **{service_display_name} Authorization**\n"
            f"3. Follow the instructions there to complete reauthentication\n"
            f"4. Once done, **retry your original command**\n\n"
            f"The application will automatically use the new credentials after successful authorization."
        )
    else:
        # Handle other types of refresh errors
        logger.error(f"Unexpected refresh error for user: {error}")
        return (
            f"An authentication error occurred while accessing {service_display_name}.\n\n"
            f"Please try to reauthenticate in **Personal Settings Page** under the **{service_display_name}** section.\n"
        )


def _prepare_fastmcp_signature(original_sig: inspect.Signature, params: list) -> Tuple[inspect.Signature, set[str]]:
    """
    Creates a new signature that excludes the 'service' parameter and
    includes the access_token and refresh_token parameters.

    This new signature is the one that will be exposed to FastMCP.

    Args:
        original_sig: The original function's signature.
        params: The list of parameters from the original signature.
        scopes: The list of scopes of the refreshed token.

    Returns:
        A tuple containing the new, modified signature and a set of the
        parameter names that were added.
    """
    # Create token parameters to be added to the new signature
    token_params = [
        inspect.Parameter('access_token', inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=str),
        inspect.Parameter('refresh_token', inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=str),
        inspect.Parameter('token_scopes', inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=List[str]),
    ]
    
    # Exclude the original 'service' parameter (the first one) and prepend the token parameters
    wrapper_params = token_params + params[1:]

    added_param_names = {p.name for p in token_params}

    return original_sig.replace(parameters=wrapper_params), added_param_names


def require_google_service(
    service_type: str,
    required_scopes: Union[str, List[str]],
    version: Optional[str] = None,
):
    """
    Decorator that automatically handles Google service authentication and injection.
    The access_token and refresh_token are passed in as arguments to the wrapper.

    Args:
        service_type: Type of Google service ("gmail", "drive", "calendar", etc.)
        required_scopes: Required scopes (can be scope group names or actual URLs)
        version: Service version (defaults to standard version for service type)
        cache_enabled: Whether to use service caching (default: True)

    Usage:
        @require_google_service("gmail", "gmail_read")
        async def search_messages(service, query: str):
            # service parameter is automatically injected
            # Original authentication logic is handled automatically
    """
    def decorator(func: Callable) -> Callable:
        # Inspect the original function signature
        original_sig = inspect.signature(func)
        params = list(original_sig.parameters.values())

        # The decorated function must have 'service' as its first parameter.
        if not params or params[0].name != "service":
            logger.error(
                f"Function '{func.__name__}' decorated with @require_google_service must have 'service' as its first parameter."
            )
            raise Exception("Internal system error. Please contact customer support.")

        wrapper_sig, added_params = _prepare_fastmcp_signature(original_sig, params)

        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Note: `args` and `kwargs` are now the arguments for the *wrapper*,
            # which does not include 'service' and includes access_token and refresh_token

            # Extract access_token, and refresh_token from wrapper arguments
            bound_args = wrapper_sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            access_token = bound_args.arguments.get('access_token')
            refresh_token = bound_args.arguments.get('refresh_token')
            token_scopes = bound_args.arguments.get('token_scopes')

            # Validate all authentication parameters and service configuration
            validation_error = _validate_auth_parameters(
                access_token=access_token,
                refresh_token=refresh_token,
                token_scopes=token_scopes,
                service_type=service_type,
                func_name=func.__name__
            )
            if validation_error:
                raise Exception(validation_error)

            config = SERVICE_CONFIGS[service_type]
            service_name = config["service"]
            service_version = version or config["version"]

            # Resolve scopes
            resolved_scopes = _resolve_scopes(required_scopes)

            # --- Service Caching and Authentication Logic (largely unchanged) ---
            service = None
            try:
                tool_name = func.__name__
                service, actual_user_email = await get_authenticated_google_service(
                    service_name=service_name,
                    version=service_version,
                    tool_name=tool_name,
                    required_scopes=resolved_scopes,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    token_scopes=token_scopes,
                )
                logger.info(f"Get service '{service_name}' for user '{actual_user_email}'")
            except GoogleAuthenticationError as e:
                raise Exception(str(e))

            # --- Call the original function with the service object injected ---
            try:
                # Remove access_token and refresh_token from kwargs before calling original function
                original_kwargs = {k: v for k, v in kwargs.items() 
                                   if k not in added_params}
                
                # Prepend the fetched service object to the original arguments
                return await func(service, *args, **original_kwargs)
            except RefreshError as e:
                error_message = _handle_token_refresh_error(e, service_name)
                raise Exception(error_message)

        # Set the wrapper's signature to the one without 'service'
        wrapper.__signature__ = wrapper_sig
        return wrapper
    return decorator


def require_multiple_services(service_configs: List[Dict[str, Any]]):
    """
    # TODO: This should be modify according to the require_google_service decorator
    Decorator for functions that need multiple Google services.

    Args:
        service_configs: List of service configurations, each containing:
            - service_type: Type of service
            - scopes: Required scopes
            - param_name: Name to inject service as (e.g., 'drive_service', 'docs_service')
            - version: Optional version override

    Usage:
        @require_multiple_services([
            {"service_type": "drive", "scopes": "drive_read", "param_name": "drive_service"},
            {"service_type": "docs", "scopes": "docs_read", "param_name": "docs_service"}
        ])
        async def get_doc_with_metadata(drive_service, docs_service, doc_id: str):
            # Both services are automatically injected
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user_google_email
            sig = inspect.signature(func)
            param_names = list(sig.parameters.keys())

            user_google_email = None
            if 'user_google_email' in kwargs:
                user_google_email = kwargs['user_google_email']
            else:
                try:
                    user_email_index = param_names.index('user_google_email')
                    if user_email_index < len(args):
                        user_google_email = args[user_email_index]
                except ValueError:
                    pass

            if not user_google_email:
                raise Exception("user_google_email parameter is required but not found")

            # Authenticate all services
            for config in service_configs:
                service_type = config["service_type"]
                scopes = config["scopes"]
                param_name = config["param_name"]
                version = config.get("version")

                if service_type not in SERVICE_CONFIGS:
                    raise Exception(f"Unknown service type: {service_type}")

                service_config = SERVICE_CONFIGS[service_type]
                service_name = service_config["service"]
                service_version = version or service_config["version"]
                resolved_scopes = _resolve_scopes(scopes)

                try:
                    tool_name = func.__name__
                    service, _ = await get_authenticated_google_service(
                        service_name=service_name,
                        version=service_version,
                        tool_name=tool_name,
                        user_google_email=user_google_email,
                        required_scopes=resolved_scopes,
                    )

                    # Inject service with specified parameter name
                    kwargs[param_name] = service

                except GoogleAuthenticationError as e:
                    raise Exception(str(e))

            # Call the original function with refresh error handling
            try:
                return await func(*args, **kwargs)
            except RefreshError as e:
                # Handle token refresh errors gracefully
                error_message = _handle_token_refresh_error(e, user_google_email, "Multiple Services")
                raise Exception(error_message)

        return wrapper
    return decorator