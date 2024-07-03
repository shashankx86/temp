### Docker Routes Documentation

- [Overview](#overview)
- [Endpoints](#endpoints)
- [Examples](#examples)

---

## Overview

The `route_docker.go` file defines the `/docker` route and its subroutes, which handle commands related to Docker containers and images.

## Endpoints

### /docker/running
- **Method:** GET
- **Description:** Lists all currently running Docker containers.
- **Example Command:**
  ```sh
  curl -X GET http://localhost:5499/docker/running
  ```
- **Expected Output:**
  ```json
  {
    "containers": [
      {
        "CONTAINER_ID": "abc123",
        "IMAGE": "my_image",
        "COMMAND": "my_command",
        "CREATED": "2 hours ago",
        "STATUS": "Up 2 hours",
        "PORTS": "0.0.0.0:80->80/tcp",
        "NAMES": "my_container"
      },
      // more containers...
    ]
  }
  ```

### /docker/image/ls
- **Method:** GET
- **Description:** Lists all Docker images.
- **Example Command:**
  ```sh
  curl -X GET http://localhost:5499/docker/image/ls
  ```
- **Expected Output:**
  ```json
  {
    "images": [
      {
        "REPOSITORY": "my_repo",
        "TAG": "latest",
        "IMAGE_ID": "abc123",
        "CREATED": "2 weeks ago",
        "SIZE": "500MB"
      },
      // more images...
    ]
  }
  ```

### /docker/start
- **Method:** POST
- **Description:** Starts a Docker container.
- **Query Parameter:** `target` (required) - ID or name of the container to start.
- **Example Command:**
  ```sh
  curl -X POST "http://localhost:5499/docker/start?target=my_container"
  ```
- **Expected Output:**
  ```json
  {
    "message": "Container started successfully"
  }
  ```

### /docker/stop
- **Method:** POST
- **Description:** Stops a Docker container.
- **Query Parameter:** `target` (required) - ID or name of the container to stop.
- **Example Command:**
  ```sh
  curl -X POST "http://localhost:5499/docker/stop?target=my_container"
  ```
- **Expected Output:**
  ```json
  {
    "message": "Container stopped successfully"
  }
  ```

### /docker/restart
- **Method:** POST
- **Description:** Restarts a Docker container.
- **Query Parameter:** `target` (required) - ID or name of the container to restart.
- **Example Command:**
  ```sh
  curl -X POST "http://localhost:5499/docker/restart?target=my_container"
  ```
- **Expected Output:**
  ```json
  {
    "message": "Container restarted successfully"
  }
  ```

### /docker/image/rm
- **Method:** DELETE
- **Description:** Removes a Docker image.
- **Query Parameter:** `targetid` (required) - ID of the image to remove.
- **Query Parameter:** `toforce` (optional) - Set to `true` to force remove the image.
- **Example Command:**
  ```sh
  curl -X DELETE "http://localhost:5499/docker/image/rm?targetid=abc123&toforce=true"
  ```
- **Expected Output:**
  ```json
  {
    "message": "Image removed successfully"
  }
  ```

## Examples

### List Running Docker Containers Example

```sh
curl -X GET http://localhost:5499/docker/running -H "Authorization: Bearer your_jwt_token"
```

### List Docker Images Example

```sh
curl -X GET http://localhost:5499/docker/image/ls -H "Authorization: Bearer your_jwt_token"
```

### Start Docker Container Example

```sh
curl -X POST "http://localhost:5499/docker/start?target=my_container" -H "Authorization: Bearer your_jwt_token"
```

### Stop Docker Container Example

```sh
curl -X POST "http://localhost:5499/docker/stop?target=my_container" -H "Authorization: Bearer your_jwt_token"
```

### Restart Docker Container Example

```sh
curl -X POST "http://localhost:5499/docker/restart?target=my_container" -H "Authorization: Bearer your_jwt_token"
```

### Remove Docker Image Example

```sh
curl -X DELETE "http://localhost:5499/docker/image/rm?targetid=abc123&toforce=true" -H "Authorization: Bearer your_jwt_token"
```