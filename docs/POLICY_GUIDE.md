# 사용자 정의 DLP 정책 가이드

이 문서는 “무엇을 필터링할지”와 “어디에 설정할지”를 결정하는 운영 가이드다. 모든
예시는 명백한 합성 문자열만 사용한다. 테스트 파일·이슈·커밋·CI 로그에 실제 개인정보,
고객 데이터, 운영 토큰, 실제 코드명을 넣지 않는다.

## 1. 설정 방식 선택

| 보호하려는 정보 | 권장 기능 | 저장 위치 | 예 |
|---|---|---|---|
| 공개 가능한 형식 | custom regex | ConfigMap | `EMP-[0-9]{8}` |
| 공개 가능한 분류어 목록 | custom literal | ConfigMap | 합성 문서 등급어 |
| 여러 개념의 동시 출현 | contextual groups | ConfigMap | 인수 + 대상 + 회사 |
| 실제 코드명·계약값 | protected literal | Kubernetes Secret | exact substring |
| 공백 없는 고엔트로피 토큰 | protected SHA-256 token | Kubernetes Secret | digest + 길이 |
| 검증된 정상값의 일시 예외 | scoped allowlist | Kubernetes Secret | exact digest + TTL |

ConfigMap은 조회 권한과 Helm release history에 노출될 수 있다. 실제 기밀값은 custom
literal/regex/contextual vocabulary에 넣지 않고 protected-value registry에 등록한다.

## 2. action 선택

| action | 동작 | 권장 용도 |
|---|---|---|
| `block` | 전체 메시지를 거부 | 주민번호, 카드, API key, 최고 기밀 |
| `redact` | 탐지 span을 `[REDACTED:<kind>]`로 교체 후 전달 | 전화, 계좌, 대체 가능한 식별값 |
| `alert` | 원문을 그대로 전달하고 감사 로그만 기록 | 비민감 분류어 관찰·튜닝 |

Protected value에는 `alert`를 사용할 수 없다. `alert`는 원문을 그대로 외부로 전달하기
때문에 production loader와 관리 CLI가 모두 설정을 거부한다.

동일한 action floor는 고신뢰 내장 kind인 `rrn`, `card`, `secret`과 해당 고신뢰 rule
override에도 적용된다. 이들은 `block` 또는 `redact`만 허용한다. 단, checksum을 적용할 수
없는 저신뢰 `rrn-format-only`는 오탐 조정을 위해 명시적 `alert` override를 허용한다.

사용자 정의 rule의 kind가 `rrn`, `card`, `secret`, `confidential`, `policy_error`이면
동일하게 `alert`를 사용할 수 없다. kind를 생략한 custom rule은 기본값이
`confidential`이므로 반드시 `block` 또는 `redact`를 선택해야 한다. 비민감 분류어를
관찰하려는 경우에만 별도의 비보호 kind(예: `document_label`)와 `alert`를 사용한다.

## 3. 비민감 형식 규칙

### 3.1 Regex: 사번 형식

```yaml
custom_rules:
  - id: synthetic-employee-id
    description: 합성 사번 형식
    kind: business_identifier
    action: redact
    scope:
      directions: [request, response]
      methods: [POST]
      path_prefixes: [/v1/hr]
    matcher:
      type: regex
      pattern: '\bEMP-[0-9]{8}\b'
```

Regex는 최대 512자, rule당 최대 100 match, 1~100ms 실행 timeout을 갖는다. zero-width,
timeout, match flood는 `policy_error`로 바뀌어 fail-closed `block`된다.

### 3.2 Literal: 공개 가능한 분류어

```yaml
custom_rules:
  - id: synthetic-document-label
    kind: document_label
    action: alert
    matcher:
      type: literal
      values: [SYNTH-RESTRICTED, SYNTH-PARTNER-ONLY]
      ignore_case: true
      whole_word: true
```

Literal은 regex로 해석하지 않고 escape된다. 그러나 값 자체는 ConfigMap에 남으므로 실제
코드명이나 토큰을 여기에 넣으면 안 된다.

### 3.3 Contextual: 의미 단서의 제한적 결합

```yaml
custom_rules:
  - id: synthetic-merger-context
    kind: confidential
    action: block
    scope:
      directions: [request, response]
    matcher:
      type: contextual
      groups:
        - [SYNTH-ACQUISITION, SYNTH-MERGER]
        - [SYNTH-TARGET, SYNTH-CANDIDATE]
        - [SYNTH-COMPANY, SYNTH-VENDOR]
      window_chars: 160
      ignore_case: true
```

각 group에서 최소 한 단어가 같은 bounded window 안에 있어야 탐지된다. 범용 의미 모델이
아니며 등록 vocabulary 밖의 동의어·문장 바꿔쓰기는 놓칠 수 있다.

## 4. 실제 기밀값 등록

패키지를 설치하면 `dlp-protected-values` 명령을 사용할 수 있다.

```bash
pip install .
```

원문 exact match는 숨김 입력으로 등록한다.

```bash
dlp-protected-values add-literal \
  --file /secure/protected-values.yaml \
  --id project-code \
  --action block \
  --direction request \
  --direction response
```

공백 없는 8~512자 ASCII 토큰은 원문 대신 SHA-256과 정확한 길이를 저장할 수 있다.

```bash
dlp-protected-values add-token \
  --file /secure/protected-values.yaml \
  --id deploy-token \
  --action block
```

SHA-256은 암호화가 아니다. 짧거나 예측 가능한 값은 사전대입이 가능하므로 SHA mode를
쓰지 말고 Secret literal로 저장한다. CLI는 repository 내부 경로를 기본 거부하고,
production loader로 전체 파일을 검증한 뒤 원자적으로 교체한다.

## 5. 원문 없는 사전 검증

등록 목록은 값과 digest를 제외한 ID, action, matcher 종류, scope 개수만 출력한다.

```bash
dlp-protected-values list --file /secure/protected-values.yaml
```

Hidden probe는 입력을 화면에 보이지 않게 받고 최종 판정·finding 개수·kind 집계만
출력한다. 원문, matcher, digest, rule ID는 출력하지 않는다. scan 비활성 및 body 초과
control도 실제 policy와 동일하게 반영한다.

```bash
dlp-protected-values probe \
  --policy configs/policy.yaml \
  --file /secure/protected-values.yaml \
  --direction request \
  --method POST \
  --path /v1/chat
```

합성 테스트 fixture로만 자동화하고 실제 기밀 probe는 로컬 운영자 터미널에서 일회성으로
수행한다. probe 입력을 shell argument, history, CI variable에 넣지 않는다.

## 6. 예외와 제거

Allowlist는 보호 kind(`rrn`, `card`, `secret`, `confidential`, `policy_error`)에 적용되지
않는다. 비보호 오탐에만 exact digest, target rule, 방향, HTTP method, path prefix, 사유,
30일 이내 만료를 모두 요구한다.

```bash
dlp-protected-values add-allowlist \
  --file /secure/protected-values.yaml \
  --id synthetic-demo-exception \
  --target phone-mobile \
  --reason "synthetic demo fixture" \
  --expires-at 2026-07-20T00:00:00+09:00 \
  --direction request \
  --method POST \
  --path-prefix /demo
```

항목 제거도 ID가 정확히 한 번 존재할 때만 성공하며, 전체 파일을 다시 검증한 뒤 원자적
교체한다.

```bash
dlp-protected-values remove \
  --file /secure/protected-values.yaml \
  --section protected-values \
  --id project-code
```

## 7. Kubernetes 적용 순서

1. repository 밖에서 registry를 만들고 `list`와 hidden `probe`로 확인한다.
2. `python scripts/validate_policy.py --protected-values ...`를 실행한다.
3. 새 이름의 immutable Secret을 만든다. 기존 Secret을 제자리 수정하지 않는다.
4. Helm의 `protectedValues.existingSecret`만 새 이름으로 변경해 rollout한다.
5. 합성 clean/redact/block smoke test와 감사 로그 원문 비노출을 확인한다.

```bash
kubectl create secret generic dlp-protected-v2 \
  --from-file=protected-values.yaml=/secure/protected-values.yaml
kubectl patch secret dlp-protected-v2 --type=merge -p '{"immutable":true}'

helm upgrade --install dlp-proxy deploy/helm/dlp-proxy \
  --set protectedValues.existingSecret=dlp-protected-v2 \
  --wait
```

Secret은 Base64 인코딩일 뿐 암호화가 아니다. etcd encryption at rest, 최소 RBAC,
Secret 조회 감사, External Secrets 또는 Secrets Store CSI를 함께 적용한다.

## 8. 운영 posture 확인

`GET /policy/status`는 실제 값·matcher·digest·경로를 노출하지 않고 현재 정책의 안전
상태를 반환한다.

```json
{
  "status": "loaded",
  "posture": "hardened",
  "fail_open_controls": [],
  "scan_request": true,
  "scan_response": true,
  "oversize_action": "block",
  "unscannable_action": "block"
}
```

다음 중 하나라도 존재하면 `posture`는 `degraded`다.

- request 또는 response scan 비활성
- oversize 또는 unscannable action이 `alert`
- programmatic policy에서 민감 kind/rule이 forwarding action으로 구성됨

`degraded`는 자동 차단 상태가 아니라 운영 경고다. 의도한 예외인지 변경 승인과 감사
기록을 확인하고, 원치 않은 상태면 ConfigMap을 수정해 rollout한다.
