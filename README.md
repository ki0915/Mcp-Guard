# Mcp-Guard

LLM API / MCP 서버로 나가는 요청·응답을 가로채 한국 개인정보(PII)와
사내 기밀정보를 탐지하고, 정책에 따라 **마스킹(redact) / 차단(block) /
로깅(alert)** 처리하는 아웃바운드 DLP 리버스 프록시입니다.

## 무엇을 탐지하나

- **한국 PII**: 주민등록번호(mod-11 체크섬 검증), 전화번호, 카드번호(Luhn 검증),
  은행 계좌번호(문맥 기반)
- **시크릿**: AWS/GitHub/OpenAI/Anthropic/Slack/Google API 키, JWT, PEM 개인키,
  일반 `secret=`/`token=` 형태의 고엔트로피 값
- **기밀 키워드**: 대외비, CONFIDENTIAL 등
- **사용자 정의 규칙**: `custom_rules` 정책으로 자체 literal/regex 패턴 추가 가능

탐지되면 요청/응답 본문·URL 경로·쿼리 스트링에서 정책에 따라 마스킹하거나
차단하고, 모든 판정을 JSON 감사 로그로 남깁니다.

전각 숫자(０１０-...), 공백/제로폭 문자로 쪼갠 숫자열, base64로 인코딩된
토큰 등 흔한 우회 표현은 `dlp_proxy/transforms.py`가 원문 오프셋을 유지한 채
정규화해서 탐지 대상에 포함시킵니다 (`scripts/improvement_report.py`로
우회 벤치마크 탐지율 측정).

## 빠른 시작

### 개인 PC (K8s 없이)

```bash
pip install .
export DLP_UPSTREAM=https://api.anthropic.com   # 프록시할 대상 API
python -m dlp_proxy                              # localhost:8080 에서 대기
```

LLM SDK의 base URL을 프록시로 바꿉니다:

```python
import anthropic
client = anthropic.Anthropic(base_url="http://localhost:8080")
```

### stdio 방식 MCP 서버

HTTP를 쓰지 않는 stdio MCP 서버는 `dlp-stdio-proxy`로 감쌉니다. 자식 프로세스를
띄우고 stdin/stdout JSON-RPC 프레임을 스캔하며, 감사 로그는 stderr로 분리해
프로토콜 스트림을 오염시키지 않습니다.

```bash
dlp-stdio-proxy -- python -m example_mcp_server
```

### 로컬 Kubernetes (k3d/minikube)

```bash
docker build -t dlp-proxy:0.1.0 .
docker build -t dlp-mock-upstream:0.1.0 mock_upstream

k3d cluster create dlp --wait
k3d image import dlp-proxy:0.1.0 dlp-mock-upstream:0.1.0 -c dlp

helm install dlp-proxy deploy/helm/dlp-proxy --wait
```

실제 LLM API 앞에 두려면:

```bash
helm install dlp-proxy deploy/helm/dlp-proxy \
  --set upstream=https://api.example.com \
  --set mockUpstream.enabled=false
```

## 정책 설정

`configs/policy.yaml` (K8s에서는 ConfigMap으로 마운트):

```yaml
default_action: alert
rules:
  rrn: block
  card: block
  secret: block
  phone: redact
  account: redact
  keyword: alert
```

정책 검증: `python scripts/validate_policy.py --policy configs/policy.yaml`

## 개발

```bash
pip install .[dev]
pytest -q                             # 테스트 실행
python scripts/accuracy_report.py     # 탐지율/오탐율 측정
python scripts/improvement_report.py  # 우회(evasion) 벤치마크 탐지율 측정
python bench/bench.py 200             # 지연 오버헤드 측정 (페어드)
python bench/stream_bench.py          # 스트리밍 경로 오버헤드 측정
ruff check .                          # 린트
```

## 한계

정규식·체크섬·엔트로피 기반 패턴 매칭이며 완벽한 차단이 아닙니다.

- 패턴이 없는 의미적 유출(문장으로 풀어쓴 기밀 등)은 탐지하지 못합니다.
- Base64/전각 숫자/공백 분리 등 흔한 변형은 정규화해서 잡지만, 이 목록에
  없는 인코딩이나 다중 요청 분할 유출은 여전히 막지 못합니다.
- 스트리밍 응답은 본문 전체를 버퍼링한 뒤 스캔하므로 지연이 늘어납니다.

실수로 인한 유출 방지가 목적이며, 악의적 우회 시도에 대한 방어는 아닙니다.

## 라이선스 / 목적

사내·개인 정보 유출 방지(방어) 목적 도구입니다.
