# Spring Security JWT POC

This project is a Proof of Concept (POC) to demonstrate the implementation of **JWT-based authentication** and authorization in a Spring Boot application. It provides a secure mechanism to validate users and control access to resources based on their roles using Spring Security.

## Endpoints

### Public Endpoints
- **`POST /api/v1/auth/login`**: Generates a JWT token for authenticated users.

### Secured Endpoints
- **`GET /api/v1/admin/hello`**: Accessible only to users with the `ADMIN` role.
- **`GET /api/v1/user/hello`**: Accessible only to users with the `USER`/`ADMIN` role.
