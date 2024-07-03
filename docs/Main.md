### Main Routes Documentation

- [Overview](#overview)
- [Endpoints](#endpoints)
- [Middleware](#middleware)
- [Rate Limiting](#rate-limiting)
- [Security](#security)
- [Examples](#examples)


## Overview

The `nuc.go` file sets up the primary API server, including CORS configuration, security headers, rate limiting, and route handling. 

## Endpoints

### /login
- **Method:** POST
- **Description:** Handles user login and returns a JWT token.
- **Rate Limiting:** 40 requests per minute.
- **Example Command:**
  ```sh
  curl -X POST http://localhost:5499/login -d '{"username":"your_username","password":"your_password"}' -H "Content-Type: application/json"
  ```
- **Expected Output:**
  ```json
  {
    "message": "Login successful",
    "access_token": "your_jwt_token"
  }
  ```

### /version
- **Method:** GET
- **Description:** Returns the API version and the username of the authenticated user.
- **Rate Limiting:** 60 requests per minute.
- **Example Command:**
  ```sh
  curl -X GET http://localhost:5499/version -H "Authorization: Bearer your_jwt_token"
  ```
- **Expected Output:**
  ```json
  {
    "version": "0.0.3",
    "user": "your_username"
  }
  ```

## Middleware

- **CORS:** Configured to allow all origins and specified methods and headers.
- **Security Headers:** Adds security-related headers to responses.
- **Authentication:** Validates JWT tokens and refreshes their expiration.

## Rate Limiting

- **General Rate Limiting:** Applied to all routes except `/login` and `/version`. Limit: 60 requests per minute.
- **Specific Rate Limiting:** Applied to `/login` route. Limit: 40 requests per minute.

## Security

- **JWT Authentication:** Uses RSA keys to sign and validate JWT tokens.
- **Security Headers:** Adds headers like `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, and `Content-Security-Policy`.

## Examples

### Login Example

```sh
curl -X POST http://localhost:5499/login -d '{"username":"your_username","password":"your_password"}' -H "Content-Type: application/json"
```

### Version Example

```sh
curl -X GET http://localhost:5499/version -H "Authorization: Bearer your_jwt_token"
```

---