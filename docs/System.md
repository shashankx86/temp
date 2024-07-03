### System Routes Documentation

- [Overview](#overview)
- [Endpoints](#endpoints)
- [Examples](#examples)

---

## Overview

The `route_system.go` file defines the `/system` route and its subroutes, which handle various system-related commands, including managing services, reading and writing files, and scheduling tasks.

## Endpoints

### /system/services
- **Method:** GET
- **Description:** Lists all user services and sockets.
- **Example Command:**
  ```sh
  curl -X GET http://localhost:5499/system/services
  ```
- **Expected Output:**
  ```json
  {
    "services": [
      {
        "UNIT": "my_service.service",
        "LOAD": "loaded",
        "ACTIVE": "active",
        "SUB": "running",
        "DESCRIPTION": "My Service"
      },
      // more services...
    ],
    "sockets": [
      {
        "UNIT": "my_socket.socket",
        "LOAD": "loaded",
        "ACTIVE": "active",
        "SUB": "listening",
        "DESCRIPTION": "My Socket"
      },
      // more sockets...
    ]
  }
  ```

### /system/services/start
- **Method:** POST
- **Description:** Starts a specified user service.
- **Query Parameter:** `target` (required) - Name of the service to start.
- **Example Command:**
  ```sh
  curl -X POST "http://localhost:5499/system/services/start?target=my_service.service"
  ```
- **Expected Output:**
  ```json
  {
    "message": "Service my_service.service started successfully"
  }
  ```

### /system/services/stop
- **Method:** POST
- **Description:** Stops a specified user service.
- **Query Parameter:** `target` (required) - Name of the service to stop.
- **Example Command:**
  ```sh
  curl -X POST "http://localhost:5499/system/services/stop?target=my_service.service"
  ```
- **Expected Output:**
  ```json
  {
    "message": "Service my_service.service stopped successfully"
  }
  ```

### /system/services/restart
- **Method:** POST
- **Description:** Restarts a specified user service.
- **Query Parameter:** `target` (required) - Name of the service to restart.
- **Example Command:**
  ```sh
  curl -X POST "http://localhost:5499/system/services/restart?target=my_service.service"
  ```
- **Expected Output:**
  ```json
  {
    "message": "Service my_service.service restarted successfully"
  }
  ```

### /system/write
- **Method:** POST
- **Description:** Writes content to a specified file.
- **Query Parameters:**
  - `filename` (required) - Name of the file.
  - `filepath` (required) - Path to the file.
  - `filecontent` (required) - Content to write to the file.
- **Example Command:**
  ```sh
  curl -X POST "http://localhost:5499/system/write?filename=myfile.txt&filepath=/path/to/directory&filecontent=Hello+World"
  ```
- **Expected Output:**
  ```json
  {
    "message": "File myfile.txt saved successfully at /path/to/directory"
  }
  ```

### /system/read
- **Method:** GET
- **Description:** Reads content from a specified file.
- **Query Parameters:**
  - `filename` (required) - Name of the file.
  - `filepath` (required) - Path to the file.
- **Example Command:**
  ```sh
  curl -X GET "http://localhost:5499/system/read?filename=myfile.txt&filepath=/path/to/directory"
  ```
- **Expected Output:**
  ```json
  {
    "content": "Hello World"
  }
  ```

### /system/at
- **Method:** POST
- **Description:** Schedules a task to run at a specified time.
- **Query Parameters:**
  - `time` (required) - Time to schedule the task (format depends on `at` command syntax).
  - `command` (required) - Command to run.
- **Example Command:**
  ```sh
  curl -X POST "http://localhost:5499/system/at?time=12:00&command=echo+Hello+World"
  ```
- **Expected Output:**
  ```json
  {
    "message": "Task scheduled at 12:00"
  }
  ```

## Examples

### List User Services and Sockets Example

```sh
curl -X GET http://localhost:5499/system/services -H "Authorization: Bearer your_jwt_token"
```

### Start User Service Example

```sh
curl -X POST "http://localhost:5499/system/services/start?target=my_service.service" -H "Authorization: Bearer your_jwt_token"
```

### Stop User Service Example

```sh
curl -X POST "http://localhost:5499/system/services/stop?target=my_service.service" -H "Authorization: Bearer your_jwt_token"
```

### Restart User Service Example

```sh
curl -X POST "http://localhost:5499/system/services/restart?target=my_service.service" -H "Authorization: Bearer your_jwt_token"
```

### Write to File Example

```sh
curl -X POST "http://localhost:5499/system/write?filename=myfile.txt&filepath=/path/to/directory&filecontent=Hello+World" -H "Authorization: Bearer your_jwt_token"
```

### Read from File Example

```sh
curl -X GET "http://localhost:5499/system/read?filename=myfile.txt&filepath=/path/to/directory" -H "Authorization: Bearer your_jwt_token"
```

### Schedule Task Example

```sh
curl -X POST "http://localhost:5499/system/at?time=12:00&command=echo+Hello+World" -H "Authorization: Bearer your_jwt_token"
```