# 버추얼클래스 Private REST API

## 일반 정보 (General API Information)
- **기본 엔드포인트(Base URL)**: `https://www.tsvirtualclass.com`
- 모든 엔드포인트는 **JSON 객체 또는 배열**을 반환합니다.
- HTTP `5XX` 코드는 버추얼클래스 **내부 오류**입니다. 이를 **실패로 단정하지 마세요**. 실행 결과는 **UNKNOWN**(성공/실패 불명)일 수 있습니다.
- 어떤 엔드포인트든 **오류**를 반환할 수 있습니다. 오류 페이로드 예시는 아래와 같습니다:
  ```json
  {
    "message": "비정상 접근입니다. 올바른 경로로 다시 접근해 주세요."
  }
  ```
- 세부 오류 코드/메시지는 별도 문서에 정의됩니다.
- `GET` 요청의 파라미터는 **query string** 으로 전송합니다.
- `POST`, `PUT`, `DELETE` 요청의 파라미터는 **query string** 또는 `application/x-www-form-urlencoded` **request body**(혼용 가능)로 전송할 수 있습니다.
- 파라미터 **순서는 무관**합니다.
- 동일 파라미터가 query string과 body에 모두 있으면 **query string 값이 우선**합니다.

---

## 엔드포인트 보안 타입 (Endpoint Security Type)
- API 키는 `X-VIRTUALCLASS-API` **헤더**로 전달합니다.
- **API 키와 시크릿 키는 대소문자를 구분**합니다.
- 기본적으로 API 키는 **모든 보안 라우트**에 접근 가능합니다.
- 서명값을 담은 `X-VIRTUALCLASS-SIGN` **헤더**가 필요합니다.
- 서명은 **HMAC-SHA256** 방식입니다. 메시지(예: `query string` 원문 또는 `request body` 원문)에 **시크릿 키**를 HMAC 키로 하여 서명을 계산합니다.
- `X-VIRTUALCLASS-SIGN`에 넣는 **서명(16진수 문자열)은 대소문자 비구분**입니다.
  (*단, 키 자체는 대소문자 구분*)

---

## SIGNED 예시
리눅스에서 `echo`, `openssl`, `curl`을 이용한 예시입니다.

**키**
- `api_key`: `YOUR_API_KEY`
- `secret_key`: `YOUR_SECRET_KEY`

**파라미터**
- `company_code=softways`

### 1) Query String 서명
- 원문: `company_code=softways`
```bash
echo -n "company_code=softways" | openssl dgst -sha256 -hmac "YOUR_SECRET_KEY"
# SHA2-256(stdin)= 295eeb9f5...185d1a986c9  ← 서명 예시
```

**요청 예시**
```bash
curl -X GET \
  "https://www.tsvirtualclass.com/private/is-company?company_code=softways" \
  -H "X-VIRTUALCLASS-API: YOUR_API_KEY" \
  -H "X-VIRTUALCLASS-SIGN: 위에서 계산한_서명값"
```

### 2) Request Body 서명
- 원문: `name=홍길동&email=gdhong@softways.co.kr&phone=01012345678`
```bash
echo -n "name=홍길동&email=gdhong@softways.co.kr&phone=01012345678" | openssl dgst -sha256 -hmac "YOUR_SECRET_KEY"
# SHA2-256(stdin)= a7d508cd636fc...16f79e6c40b57  ← 서명 예시
```

```php
$query_string = 'name=홍길동&email=gdhong@softways.co.kr&phone=01012345678';
$secret = 'YOUR_SECRET_KEY';
$signature = hash_hmac('sha256', $query_string, $secret); // a7d508cd636fc...16f79e6c40b57  ← 서명 예시
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public final class VcSign {
    private VcSign() {}
    public static String hmacSha256Hex(String secret, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] out = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString(); // PHP hash_hmac(..., ..., false)와 동일(소문자 hex)
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
```

**요청 예시 BASH**
```bash
curl -X POST \
  "https://www.tsvirtualclass.com/private/signup/softway" \
  -H "X-VIRTUALCLASS-API: YOUR_API_KEY" \
  -H "X-VIRTUALCLASS-SIGN: 위에서 계산한_서명값" \
  -d "name=홍길동&email=gdhong@softways.co.kr&phone=01012345678"
```


** 응답 예시**
```json
# SIGN에 필요한 Header를 포함하지 않았을 때
{
  "result": false,
  "message": "missing_headers"
}

# API_KEY 가 유효하지 않을 때
{
  "result": false,
  "message": "invalid_api_key"
}

# SECRET_KEY 가 지정되지 않았을 때(소프트웨이즈로 연락 바랍니다.)
{
  "result": false,
  "message": "secret_not_found"
}

# 요청 SIGN 값과 서버에서 SIGN을 생성한 값이 일치하지 않을 때
{
  "result": false,
  "message": "signature_mismatch"
}
```

---

## Private API 엔드포인트

### 1) 기관 조회
```
GET /private/is-company   (HMAC SHA256)
```
사용가능한 기관이 맞는지 조회 합니다.

**파라미터**

이름 | 타입 | 필수 | 설명
---|---|---|---
`company_code` | STRING | 필수 | 예: `softways` (기관 코드)

> `company_code`은 반드시 전송해야 합니다.

**응답 예시**
```json
# 사용 가능한 기관일 때
{
  "result": true
}

# 사용 불가한 기관일 때
{
  "result": false
}
```

---

### 2) 회원 등록
```
POST /private/signup/{company_code}   (HMAC SHA256)
```
회원을 등록합니다. `{company_code}` 예: `softways`

**파라미터**

이름 | 타입 | 필수 | 설명
---|---|---|---
`name` | STRING | 필수 | 이름, 최소 2자리, 최대 20자리
`email` | STRING | 필수 | 이메일, 최대 50자리
`phone` | STRING | 필수 | 휴대폰번호, 최대 11자리

> 원문 표기에 따르면 “query_string을 허용한다”이지만, **개인정보 보안 안정성 차원에서 세 필드 모두 request body 전송을 권장**합니다.

**응답 예시**
```json
# 회원 등록이 되었을 때
{
  "result": true,
  "data": {
    "user_token": "a7d508cd636fca3aa4eff1b3d0e13d1b764f924d8f852551eec16f79e6c40b57"
  }
}

# 회원 등록이 되지 않았을 때
{
  "result": false,
  "message": "이미 등록된 휴대폰번호 입니다."
}
```

---

### 3) 회원 등록 취소
```
POST /private/cancel/{company_code}
```
등록된 회원을 취소합니다. `{company_code}` 예: `softways`

**파라미터**

이름 | 타입 | 필수 | 설명
---|---|---|---
`user_token` | STRING | 필수 | 예: a7d508cd636fc....e6c40b57 회원 등록시 부여받은 user_token

> `user_token`는 반드시 전송해야 합니다.

**응답 예시**
```json
# 회원 등록이 취소 되었을 때
{
  "result": true
}

# 회원 등록 취소가 되지 않았을 때
{
  "result": false,
  "message": "해당 회원이 존재 하지 않습니다."
}
```

---

### 4) 로그인
```
POST /private/login/{company_code}
```
로그인 처리를 합니다. `{company_code}` 예: `softways`

**파라미터**

이름 | 타입 | 필수 | 설명
---|---|---|---
`user_token` | STRING | 필수 | 예: a7d508cd636fc....e6c40b57 회원 등록시 부여받은 user_token

> `user_token`는 반드시 전송해야 합니다.

**응답 예시**
```json
# 로그인 처리 되었을 때 서비스에 접근 할 수 있는 URL을 리턴 합니다.
{
  "result": true,
  "data": {
    "url": "https://www.tsvirtualclass.com/space/softways/dashboard/c0701fd68cb797a050cbbb25494fa4732d0404b6cd5a3a9168b830bbff2539c3"
  }
}

# 로그인 처리 되지 않았을 때
{
  "result": false,
  "message": "해당 회원이 존재 하지 않습니다."
}
```

---

## 참고
- **DEV 엔드포인트(DEV URL)**: `https://adv.softedu24.com`
