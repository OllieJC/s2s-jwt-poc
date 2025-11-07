# s2s-jwt-poc
Service to Service Authentication with JWT Bearers (Proof of Concept)

Some work in progress code currently available at `wip/`

## Example

- `ServiceA` - website backend
  - where `iss` would be the client ID metadata document
  - like `https://service-a.example.com/.well-known/cimd-workload-1.json`
- `ServiceB` - API
  - where `aud` might be `https://service-b.example.com/api/get-counter?v=1`
- `Auth Server` - may be required by a service and redirected to via `WWW-Authenticate`

### Diagram

``` mermaid
sequenceDiagram
    participant ServiceA
    participant ServiceB
    participant AuthServer as Auth Server

    %% --- Step 1 ---
    Note over ServiceA,ServiceB: Flow 1) Just JWT
    ServiceA->>ServiceA: Generate JWT with client ID as URI of client ID metadata endpoint
    ServiceA->>ServiceB: GET with Authorization: Bearer JWT
    ServiceB->>ServiceB: Extract client ID from JWT
    ServiceB-->>ServiceA: Fetch client ID metadata
    ServiceB->>ServiceB: Extract JWKS URI / public keys
    ServiceB-->>ServiceA: Fetch JWKS (if URI)
    ServiceB->>ServiceB: Validate JWT
    ServiceB-->>ServiceA: 200 OK Response

    %% --- Step 2 ---
    Note over ServiceA,ServiceB: Flow 2) Initiate with JWT and get Access Token (AT)
    ServiceA->>ServiceA: Generate JWT
    ServiceA->>ServiceB: GET with Authorization: Bearer JWT
    ServiceB->>ServiceB: (like step 1 get metadata and public keys and verify JWT)
    ServiceB-->>ServiceA: 200 OK Response + AT
    ServiceA->>ServiceB: (subsequent) GET with Authorization: Bearer AT
    ServiceB-->>ServiceA: 200 OK Response

    %% --- Step 3 ---
    Note over ServiceA,AuthServer: Flow 3) Attempt JWT, redirect to auth server to get AT
    ServiceA->>ServiceA: Generate JWT
    ServiceA->>ServiceB: GET with Authorization: Bearer JWT
    ServiceB-->>ServiceA: 401 Unauthorized (WWW-Authenticate: Bearer iss="Auth Server")
    ServiceA->>AuthServer: Authentication Request with JWT ("aud" = ServiceB)
    AuthServer->>AuthServer: Extract client ID from JWT
    AuthServer-->>ServiceA: Fetch client ID metadata
    AuthServer->>AuthServer: Extract JWKS URI / public keys
    AuthServer-->>ServiceA: Fetch JWKS (if URI)
    AuthServer->>AuthServer: Validate JWT
    AuthServer-->>ServiceA: Access Token
    ServiceA->>ServiceB: (subsequent) GET with Authorization: Bearer AT
    ServiceB-->>ServiceA: 200 OK Response
```
