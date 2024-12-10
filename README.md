# Spring Security JWT POC

This project is a Proof of Concept (POC) to demonstrate the implementation of **JWT-based authentication** and authorization in a Spring Boot application. It provides a secure mechanism to validate users and control access to resources based on their roles using Spring Security.

## Features
- **JWT Authentication**: Secure token-based authentication for APIs.
- **Role-based Authorization**: Restricts access to resources based on user roles (`ADMIN`, `USER`).
- **Spring Security Integration**: Leverages Spring Security for authentication and authorization.
- **Custom Filters**: Implements a custom JWT authentication filter for validating tokens.
- **Exception Handling**: Handles various JWT-related exceptions.

## Project Structure
- **`com.rk.security.jwt.filter.JwtAuthenticationFilter`**: Intercepts requests to validate JWT tokens and set the authentication context.
- **`com.rk.security.jwt.utils.JwtUtil`**: Provides utility methods for generating, parsing, and validating JWT tokens.
- **`com.rk.security.model.LoginRequest`**: Represents the login request payload.
- **`com.rk.security.model.LoginResponse`**: Represents the login response payload containing the JWT token and user details.
- **`com.rk.security.controller.WishController`**: Demonstrates secured APIs with role-based access.

## Endpoints

### Public Endpoints
- **`POST /api/v1/auth/login`**: Generates a JWT token for authenticated users.

### Secured Endpoints
- **`GET /api/v1/admin/hello`**: Accessible only to users with the `ADMIN` role.
- **`GET /api/v1/user/hello`**: Accessible only to users with the `USER`/`ADMIN` role.
