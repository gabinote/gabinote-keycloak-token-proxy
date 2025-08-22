# Keycloak Token Proxy Server

## 1. About

Keycloak Identity Broker Token Exchange 수행시, 클라이언트와 Keycloak 사이에서 토큰 교환 처리를 중계하는 프록시 서버입니다.

로그인 수행시 발급되는 refresh token을 httpOnly 쿠키로 저장하며, 이후 클라이언트는 프록시 서버를 통해 토큰 갱신 및 로그아웃 처리를 수행하게 됩니다.

인증 프로세스는 아래와 같습니다.

### 인증 프로세스

1. 클라이언트가 프록시 서버에에 kc_idp_hint를 포함한 로그인 요청을 보냅니다.
2. 프로록시 서버는 kc_idp_hint에 해당하는 Keycloak의 Identity Provider의 인증 URL로 리다이렉트합니다.
3. 클라이언트는 리다이렉트된 URL에서 로그인을 수행하고, 외부 Idp 토큰을 획득합니다.
4. 클라이언트는 외부 Idp 토큰과 pkce를 포함하여 프록시 서버에 POST 요청을 보냅니다.
5. 프록시 서버는 외부 Idp 토큰을 과 pkce를 keycloak 서버에 전달하여 토큰 교환을 요청합니다.
6. keycloak 서버는 토큰 교환을 수행하고, 새로운 access token과 refresh token을 반환합니다.
7. 프록시 서버는 refresh token을 httpOnly 쿠키로 저장하고, access token만 클라이언트에 반환합니다.


---

## 2. API Endpoints

### GET /keycloak/login

#### query parameters
| Name                  | Type   | Required | Description                                                                                      |
|-----------------------|--------|----------|--------------------------------------------------------------------------------------------------|
| redirect_uri          | string | yes      | 클라이언트가 Keycloak 로그인 후 돌아올 콜백 URL. 반드시 Keycloak 클라이언트 설정에 등록된 URI여야 합니다.                          |
| code_challenge        | string | yes      | PKCE (Proof Key for Code Exchange)에서 사용되는 코드 챌린지 값. Authorization Code Flow에서 보안을 강화하기 위해 필요합니다. |
| code_challenge_method | string | yes      | PKCE 코드 챌린지 생성 방법. 일반적으로 `S256` 사용.                                                              |
| idp_hint              | string | yes      | Keycloak 로그인 화면에서 특정 Identity Provider(Google, GitHub 등)를 바로 선택하도록 하는 힌트.                        |



### response
* 302

### POST /keycloak/exchange
Identity Broker Login Flow에서 발급받은 외부 IdP 토큰을 Keycloak Access Token으로 교환하고, Refresh Token은 HTTP-Only Secure 쿠키로 저장합니다.


#### response
* 200 OK
```json
{
    "result": true,
    "message": "OK",
    "access_token": "access_token", // Keycloak Access Token
    "expires_in": 300
}
```

* 400 Bad Request or 401 Unauthorized
```json
{
    "result": false,
    "message": "Invalid request or authentication failed",
    "access_token": "",
    "expires_in": -1
}
```

### POST /keycloak/refresh
쿠키에 저장된 Refresh Token을 사용해 새로운 Access Token을 발급받습니다. 이때 refresh token은 자동으로 갱신되어 httpOnly 쿠키에 저장됩니다.
#### response body
* 200 OK
```json
{
    "result": true,
    "message": "OK",
    "access_token": "new_access_token", // 새로운 Keycloak Access Token
    "expires_in": 300
}
```

* 400 Bad Request or 401 Unauthorized
```json
{
    "result": false,
    "message": "Invalid request or authentication failed",
    "access_token": "",
    "expires_in": -1
}
```

### DELETE /keycloak/logout
쿠키에 저장된 Refresh Token을 삭제하고, Keycloak 서버에서 로그아웃을 수행합니다.

---

## 3. How to Run

### a. create config.yaml

```shell
touch config/config.yaml
nano config/config.yaml
```

```yaml
# config.yaml
server:
  port: 3000
  host: "0.0.0.0"

keycloak:
  url: "http://keycloak-server:8080/auth" # Keycloak 서버 URL
  realm: "your-realm" # Keycloak Realm 이름
  client_id: "your-client" # Keycloak 클라이언트 ID
  client_secret: "your_client_secret" # Keycloak 클라이언트 시크릿

security:
  refresh_max_age: 7776000 # 90 days
  refresh_allow_path: /some-path
  refresh_allow_domain: some-domain.com
  refresh_cookie_name: refresh_token
  cors_allow_origin: http://localhost:3000
```


### b. run the server
``` shell
docker build -t keycloak-token-proxy .
docker run -d -p 3000:3000 --name keycloak-token-proxy keycloak-token-proxy
```


## 4. License
MIT License © 2025 hrabit64