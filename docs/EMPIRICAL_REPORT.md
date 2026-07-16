# Mcp-Guard 실증 테스트 보고서

> 성능·배포 측정일: 2026-07-12 KST · 레지스트리/전체 회귀 재검증: 2026-07-15 KST
>
> Python 3.12.13 · Windows 11 · Docker 29.6.1 · k3d 5.8.3

이 보고서는 현재 구현을 **합성 데이터만으로** 재실행해 얻은 결과를 기록한다. 사용자,
고객, 직원의 실제 개인정보와 운영 API key는 테스트·로그·이미지에 사용하지 않았다.
수치는 작은 회귀 코퍼스와 로컬 루프백 환경의 결과이며 실서비스 모집단 성능으로
일반화할 수 없다.

![Mcp-Guard 아키텍처](assets/architecture.png)

## 1. 결론

| 질문 | 실측 결과 | 판정 |
|---|---:|---|
| 기존 한국 PII/시크릿 회귀가 유지되는가? | 양성 35/35, 정상 0/14 오탐 | 통과 |
| 대표 우회 표현에 대한 개선이 수치로 보이는가? | case recall 16.667% → 93.333%, **+76.666%p** | 개선 확인 |
| 개선 때문에 고정 정상셋 오탐이 늘었는가? | 0/30 → 0/30 | 이 코퍼스에서는 증가 없음 |
| scan 자체 비용은 얼마인가? | 평균 +0.0440ms, p95 +0.0774ms | 로컬 microbenchmark 기준 |
| 실제 HTTP proxy 비용은 얼마인가? | 평균 +3.10ms, p95 +3.65ms | 200 paired runs |
| SSE event 검사가 buffering TTFB를 줄이는가? | 평균 37.158ms → 4.892ms, **-86.835%** | 100 runs/mode |
| 배포가 재현되는가? | fresh k3d + Helm, 2 pods Ready, 실제 redact/block | 통과 |
| 코드 품질 gate가 통과하는가? | 187 passed, 1 POSIX-only skip; Ruff/Bandit/actionlint/Helm 통과 | 통과 |
| 사용자 정의 기밀 rule이 `alert`로 원문을 전달할 수 있는가? | 기본 `confidential` 포함 보호 kind 6 cases와 Helm negative test에서 모두 거부 | 차단 확인 |
| 원격 CI/CD가 끝까지 동작하는가? | [Actions #29485736882](https://github.com/ki0915/Mcp-Guard/actions/runs/29485736882): 187 tests, GHCR push, k3d/Helm, curl smoke 모두 성공 | 통과 |

원격 실행은 2026-07-16 `workflow_dispatch`로 PR 브랜치에서 수행했다. proxy와 mock-upstream
이미지를 `ghcr.io/ki0915/mcp-guard/*`에 실제 푸시한 뒤 임시 k3d 클러스터에 배포했다.
PR 이벤트에서는 외부 패키지 변경을 막기 위해 이미지를 빌드만 하고 push/deploy는 생략한다.
`main` push와 수동 실행은 동일한 release 경로를 사용한다.
단계별 결과와 게시 이미지 SHA는
[`github-actions-full-cicd-20260716.txt`](evidence/github-actions-full-cicd-20260716.txt)에 고정했다.

## 2. 정확도·오탐 실증

### 2.1 기존 내장 탐지 회귀

명령:

```bash
python scripts/accuracy_report.py
```

| 데이터셋 | 통과 | 전체 | case 통과율 |
|---|---:|---:|---:|
| 한국 PII positive + negative controls | 27 | 27 | 100.0% |
| 시크릿 positive + negative controls | 14 | 14 | 100.0% |
| 정상 텍스트 false-positive set | 14 | 14 | 100.0% |

양성만 분리하면 35/35 탐지, 정상셋은 0/14 오탐이다. 주민번호는 유효·무효 checksum,
전화·카드·계좌, 시크릿 10건 이상을 포함하지만, **준비된 합성 fixture에 대한 회귀
결과**이지 통계적으로 대표성 있는 production accuracy는 아니다.

### 2.2 우회·문맥 전후 비교

고정 코퍼스: [`tests/data/evasion_benchmark.json`](../tests/data/evasion_benchmark.json)

- 총 90건: sensitive 60, benign 30
- sensitive 구성: raw control 10, NFKC 12, digit split 12, Base64 12,
  contextual 10, 의도적으로 남긴 residual 4
- raw-only baseline: 내장 탐지기를 원문에만 실행
- enhanced: NFKC, 숫자 사이 whitespace/format-control 축약, 1회 Base64 decode,
  운영자 정의 contextual group rule 2개 추가
- 지표: 케이스가 기대한 detector kind/rule과 일치했는지 평가

| 모드 | TP | FN | FP | TN | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| raw-only baseline | 10 | 50 | 0 | 30 | 16.667% | 0.000% |
| enhanced | 56 | 4 | 0 | 30 | **93.333%** | **0.000%** |

카테고리별 enhanced recall은 raw/NFKC/digit-split/Base64/contextual 모두 100%였다.
다만 다음 4건은 실패 사례로 삭제하지 않고 데이터셋에 보존했다.

1. 이중 Base64처럼 재귀 decode가 필요한 값
2. 임의 본문 안의 percent encoding
3. 오탐 억제를 위해 축약하지 않는 slash 숫자 분리
4. 운영자가 등록한 contextual vocabulary 밖의 의미적 우회 문장

전체 결과와 exact dataset SHA-256은
[`improvement-report.json`](evidence/improvement-report.json)에 있다.

## 3. 성능 실증

### 3.1 Scanner microbenchmark

90건 전체를 모드마다 200회, 총 18,000 sample씩 교차 실행했다.

| 모드 | 평균 | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| raw-only | 0.0180ms | 0.0175ms | 0.0258ms | 0.0415ms |
| enhanced | 0.0621ms | 0.0573ms | 0.1032ms | 0.1534ms |
| 증가분 | **+0.0440ms** | +0.0398ms | **+0.0774ms** | +0.1119ms |

이는 Python 함수 단위 비용이며 HTTP, JSON, 네트워크 비용을 포함하지 않는다.

### 3.2 HTTP end-to-end proxy overhead

명령: `python bench/bench.py 200`

1,102-byte 정상 합성 요청을 localhost HTTP/1.1 keep-alive에서 direct와 proxy 순서를
번갈아 20회 warm-up 후 200쌍 측정했다.

| 경로 | 평균 | p50 | p95 |
|---|---:|---:|---:|
| direct mock upstream | 0.75ms | 0.74ms | 0.94ms |
| DLP proxy 경유 | 3.85ms | 3.79ms | 4.48ms |
| paired overhead | **+3.10ms** | +3.05ms | **+3.65ms** |

증거: [`bench-result.json`](evidence/bench-result.json). 원격 LLM latency, TLS, 실제 rule 수,
본문 크기와 CPU 제한에 따라 운영 수치는 달라진다.

### 3.3 SSE time-to-first-byte

명령: `python bench/stream_bench.py 100`

upstream은 첫 complete SSE event를 즉시 보내고 monotonic clock으로 검증된 25ms 뒤
두 번째 event를 보냈다. direct, full-buffer, event-inspection을 모드마다 warm-up 10회 +
실측 100회 실행했다.

| 모드 | 평균 TTFB | p95 TTFB | 평균 total |
|---|---:|---:|---:|
| direct | 1.631ms | 3.168ms | 32.105ms |
| full-buffer | 37.158ms | 48.326ms | 37.233ms |
| complete-event inspection | **4.892ms** | **10.130ms** | 37.656ms |

event mode는 buffer 대비 평균 TTFB **32.266ms(86.835%)**, p95 **38.196ms**를 줄였다.
대신 한 event가 끝날 때까지는 대기하며 event 사이에 나뉜 의미를 재조립하지 않는다.
증거: [`stream-bench-result.json`](evidence/stream-bench-result.json).

## 4. 테스트·정적 분석

| 검증 | 결과 |
|---|---|
| 전체 pytest | **187 passed, 1 skipped** in 1.88s (2026-07-16) |
| skip 사유 | Windows에서 POSIX file-mode 전용 test 1건 |
| `ruff check .` | 통과 |
| Bandit (`dlp_proxy scripts mock_upstream`) | 통과 |
| `actionlint` | 통과 |
| `helm lint --strict` | 0 failed |
| Docker proxy/mock build | 통과 |

### 4.1 기밀 정책·Protected-value 레지스트리 안전장치

2026-07-15 변경에서 전용 합성 테스트 14건을 추가했다.

| 검증 대상 | 결과 |
|---|---|
| protected `alert` 설정 | production loader가 거부 |
| protected `redact` 설정 | 허용 후 실제 action 확인 |
| safe inventory | literal·digest 비출력 확인 |
| ID 기반 remove | exact 1건 제거, 실패 시 원본 보존 |
| hidden probe 결과 | 원문·rule ID 없이 block metadata만 반환 |
| scan off / oversize probe | 실제 policy control과 동일 판정 |
| `rrn`/`card`/`secret` kind 3종 `alert` | loader와 Helm schema가 거부 |
| 고신뢰 rule override 3종 `alert` | loader가 거부 |
| 알 수 없는 rule override | 오타 가능성으로 시작 전 거부 |
| policy posture | hardened/degraded와 fail-open 목록 확인 |

설치된 `dlp-protected-values list`도 합성 registry에 실행해 ID·action·scope metadata는
표시하면서 literal과 SHA-256 prefix가 출력되지 않음을 확인했다. 이는 비밀값 자체의
안전성을 증명하는 보편적 수치가 아니라, 명시된 14개 관리 불변식의 회귀 결과다.
명령과 비민감 결과는
[`registry-guardrails-20260715.txt`](evidence/registry-guardrails-20260715.txt)에 고정했다.

## 5. fresh k3d / Helm 실증

2026-07-12에 `dlp-empirical-20260712` 클러스터를 새로 만들고 현재 workspace 이미지 두
개를 import했다. 합성 protected-values는 미리 만든 immutable Kubernetes Secret로만
주입하고 Helm values/ConfigMap에는 넣지 않았다.

| 항목 | 결과 |
|---|---|
| Helm release | `deployed`, revision 1 |
| proxy / mock upstream | 각각 1/1 Running, restart 0 |
| health / clean request | 200 / 200 |
| 합성 전화번호 | 200, `[REDACTED:phone]`, 원문 응답 없음 |
| checksum-valid 합성 RRN | 403 `dlp_blocked` |
| block 전후 upstream count | 2 → 2, 전달되지 않음 |
| audit raw identifier 검색 | 0건; `sample=***` |
| 컨테이너 | UID/GID 10001, non-root, read-only rootfs |
| Secret 실제 대상 파일 | `0440 root:10001`, readable by proxy |
| 보호 literal | Helm manifest/values/ConfigMap 모두 미포함 |
| opt-in NetworkPolicy | `dlp-proxy-force-egress`, Egress 적용 |

명령·이미지 digest·판정 로그의 비민감 요약은
[`k8s-deploy-proof-20260712.txt`](evidence/k8s-deploy-proof-20260712.txt)에 있다.

## 6. 이력서에 사용할 수 있는 표현

다음 문장은 측정 범위를 함께 유지할 때만 사용한다.

- “Python 기반 MCP/LLM outbound DLP를 설계하고 187개 자동화 테스트와 fresh k3d/Helm
  smoke test로 request/response redact·block·audit 불변식을 검증했다.”
- “90건 합성 evasion regression corpus에서 raw-only 대비 case recall을 16.7%에서
  93.3%로 +76.7%p 개선했고, 고정 benign 30건의 오탐은 0건을 유지했다.”
- “NFKC·digit compaction·1-pass Base64·contextual rule의 추가 scan 비용을 p95
  +0.077ms로 계측하고, 200 paired HTTP run에서 proxy overhead p95 +3.65ms를 기록했다.”
- “SSE complete-event inspection으로 full-buffer 대비 평균 TTFB를 86.8% 단축했다
  (합성 25ms inter-event gap, 모드당 100회).”

“실서비스 탐지율 93.3%”, “완벽 차단”, “오탐이 없다”처럼 측정 범위를 지우는 표현은
사용하지 않는다.

## 7. 남은 한계

- contextual rule은 operator vocabulary의 동시 출현을 찾는 것이며 범용 의미 모델이 아니다.
- Base64는 bounded 1-pass만 decode한다. 재귀·암호화·압축·임의 변환은 우회할 수 있다.
- digit compaction은 오탐 억제를 위해 숫자 사이 whitespace/format-control만 제거한다.
- SSE event mode는 event 경계를 넘는 분할 유출을 재구성하지 않는다.
- HTTP header, WebSocket, 이미지·음성·PDF/OCR은 검사하지 않는다.
- stdio adapter는 newline-delimited JSON-RPC MCP만 지원한다.
- response block은 upstream에 이미 보낸 request를 회수하지 못한다.
- 앱이 프록시를 우회하면 검사하지 못한다. egress 강제와 RBAC가 별도로 필요하다.

## 8. 재현 명령

```bash
python scripts/accuracy_report.py
python scripts/improvement_report.py --rounds 200
python bench/bench.py 200
python bench/stream_bench.py 100
pytest -q
ruff check .
bandit -q -r dlp_proxy scripts mock_upstream -s B104
helm lint --strict deploy/helm/dlp-proxy
```

아키텍처 원본은 [`architecture.svg`](assets/architecture.svg), README용 raster는
[`architecture.png`](assets/architecture.png)이다.
