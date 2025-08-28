"""
Authentication endpoints for BSN Knowledge API.
Handles login, logout, token refresh, and user management.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from ...auth import (
    LoginRequest,
    Token,
    User,
    UserRole,
    authenticate_user,
    create_auth_tokens,
    get_current_admin,
    get_current_user,
    get_user,
    verify_token,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=Token)
async def login(login_data: LoginRequest) -> Token:
    """
    Authenticate user and return JWT tokens.

    **Parameters:**
    - **username**: User's username
    - **password**: User's password

    **Returns:**
    - **access_token**: JWT access token (expires in 30 minutes)
    - **refresh_token**: JWT refresh token (expires in 7 days)
    - **token_type**: Token type (always "bearer")
    - **expires_in**: Access token expiration time in seconds

    **Example:**
    ```json
    {
        "username": "student1",
        "password": "password123"
    }
    ```

    **Response:**
    ```json
    {
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "token_type": "bearer",
        "expires_in": 1800
    }
    ```
    """
    user = authenticate_user(login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User account is disabled"
        ) from e

    return create_auth_tokens(user)


@router.post("/login/oauth2", response_model=Token)
async def oauth2_login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    """
    OAuth2 compatible token endpoint.

    This endpoint is compatible with OAuth2 password flow and can be used
    with FastAPI's automatic interactive API docs.

    **Form Parameters:**
    - **username**: User's username
    - **password**: User's password
    - **scope**: Optional OAuth2 scopes (not used in current implementation)

    **Returns:** JWT tokens in OAuth2 format
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User account is disabled"
        ) from e

    # Note: form_data.scopes contains requested scopes, can be used for fine-grained access
    return create_auth_tokens(user)


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str) -> Token:
    """
    Refresh access token using refresh token.

    **Parameters:**
    - **refresh_token**: Valid JWT refresh token

    **Returns:** New access and refresh tokens

    **Example Request:**
    ```json
    {
        "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
    }
    ```
    """
    try:
        # Verify refresh token
        token_data = verify_token(refresh_token, token_type="refresh")
        user = get_user(username=token_data.username)

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
            ) from e

        return create_auth_tokens(user)

    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        ) from e


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)) -> dict:
    """
    Logout current user.

    Note: In a production system, you would maintain a token blacklist
    or use Redis to invalidate tokens. For now, this endpoint just
    confirms successful logout.

    **Returns:** Success message
    """
    # In production, add token to blacklist/revoke token
    return {
        "message": f"User {current_user.username} logged out successfully",
        "username": current_user.username,
    }


@router.get("/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_user)) -> User:
    """
    Get current authenticated user information.

    **Returns:** Current user details (without password)

    **Example Response:**
    ```json
    {
        "id": 1,
        "username": "student1",
        "email": "student1@nursing.edu",
        "role": "student",
        "is_active": true,
        "created_at": "2024-08-24T10:00:00Z"
    }
    ```
    """
    return current_user


@router.get("/users", response_model=list[User])
async def list_users(
    admin_user: User = Depends(get_current_admin), skip: int = 0, limit: int = 100
) -> list[User]:
    """
    List all users (Admin only).

    **Parameters:**
    - **skip**: Number of users to skip (for pagination)
    - **limit**: Maximum number of users to return

    **Returns:** List of users

    **Note:** Only administrators can access this endpoint.
    """
    from ...auth import fake_users_db

    users = list(fake_users_db.values())

    # Convert UserInDB to User (remove password)
    user_list = [
        User(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
        )
        for user in users[skip : skip + limit]
    ]

    return user_list


@router.get("/verify-token")
async def verify_user_token(current_user: User = Depends(get_current_user)) -> dict:
    """
    Verify if the current token is valid and return token information.

    **Returns:** Token verification status and user info

    **Example Response:**
    ```json
    {
        "valid": true,
        "user": {
            "id": 1,
            "username": "student1",
            "role": "student"
        },
        "message": "Token is valid"
    }
    ```
    """
    return {
        "valid": True,
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role,
        },
        "message": "Token is valid",
    }


@router.get("/roles", response_model=list[str])
async def get_available_roles() -> list[str]:
    """
    Get list of available user roles in the system.

    **Returns:** List of available roles

    **Example Response:**
    ```json
    ["student", "instructor", "admin"]
    ```
    """
    return [UserRole.STUDENT, UserRole.INSTRUCTOR, UserRole.ADMIN]


@router.get("/health")
async def auth_health_check() -> dict:
    """
    Authentication service health check.

    **Returns:** Health status
    """
    return {
        "service": "authentication",
        "status": "healthy",
        "features": [
            "JWT authentication",
            "Role-based access control",
            "Token refresh",
            "Rate limiting integration",
        ],
    }
