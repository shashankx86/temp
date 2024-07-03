### Nest Routes Documentation

- [Overview](#overview-1)
- [Endpoints](#endpoints-1)
- [Examples](#examples-1)

---

## Overview

The `route_nest.go` file defines the `/nest` route and its subroutes, which handle commands related to system resource usage.

## Endpoints

### /nest/resources
- **Method:** GET
- **Description:** Retrieves disk and memory usage by executing the `nest resources` command.
- **Example Command:**
  ```sh
  curl -X GET http://localhost:5499/io/nest/resources
  ```
- **Expected Output:**
  ```json
  {
    "usage": {
      "disk": {
        "total": "100G",
        "used": "50G"
      },
      "memory": {
        "total": "16G",
        "used": "8G"
      }
    }
  }
  ```

## Examples

### Get Nest Resources Example

```sh
curl -X GET http://localhost:5499/io/nest/resources -H "Authorization: Bearer your_jwt_token"
```