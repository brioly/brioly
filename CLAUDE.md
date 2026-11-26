# CLAUDE.md

이 파일은 brioly 레포에서 작업하는 Claude Code(와 기여자)를 위한 안내서입니다.

## 프로젝트

**brioly**는 회사의 인프라(AWS 등)와 코드(GitHub)를 스캔해서 아키텍처·기술 스택 현황 문서를 자동 생성하고, 주기적으로 최신 상태로 유지합니다. 온보딩 문서와 JD 소스 텍스트처럼 모델이 쓰는 문서는 brioly Cloud가 만듭니다.

- **현재 상태**: 초기 개발 단계. Go 모듈 `github.com/brioly/brioly`에 `brioly generate`, `diff`, `replay`, `components init`이 있습니다.
- **데이터 모델**: [`docs/design/fact-schema-v0.md`](docs/design/fact-schema-v0.md)(수집 규칙, ID, coverage, secret 규칙)와 [`docs/design/fact-schema-v1.md`](docs/design/fact-schema-v1.md)(속성 등급, 컴포넌트, 주석, 변경 이벤트. 코드에 구현됨).
- 이 레포는 공개를 전제로 합니다. 계획, 가격, 고객 자료, 실제 계정에서 나온 값(계정 ID, ARN, 리소스 이름)을 커밋하지 마세요. 테스트에는 가짜 값을 씁니다.

## 핵심 설계 원칙

아래 원칙을 어기는 코드를 작성하지 마세요. 바꿔야 한다고 판단되면 먼저 제안하고 합의합니다.

1. **수집은 결정적 코드로, LLM은 해석과 서술에만 씁니다. CLI는 처음부터 끝까지 결정적입니다.**
   - **사용자가 설정한 소스(AWS, 클러스터, Cloudflare의 API)를 읽는 것 말고 CLI가 밖으로 보내는 요청은 하나뿐입니다**: 버전 지원 종료일 표를 brioly.io에서 받는 GET. 수집한 내용은 담기지 않습니다.
   - **CLI(`cmd/brioly`)는 모델을 부르지 않습니다**(2026-11-26 결정). API 키 설정도, 모델이 쓰는 출력도, `--no-llm` 옵션도 없습니다. `brioly.yaml`의 예전 `llm`·`docs` 항목은 경고와 함께 무시합니다. 모델을 쓰는 코드는 `pkg/enrich`에만 있고, 이 모듈을 가져다 쓰는 brioly Cloud가 부릅니다.
   - 스캔은 SDK와 API 호출로 빠짐없이, 같은 입력이면 같은 출력이 나오게 수집합니다.
   - 스캔 단계에서 MCP나 LLM 에이전트를 쓰지 않습니다.
2. **OSS CLI는 결정적 문서(아키텍처, 기술 스택, 버전 지원, 인터넷 노출 점검, 다이어그램) 생성과 두 스냅샷의 diff까지 온전히 합니다.** 스캔 범위(계정·레포 수)로 기능을 막지 않습니다. 사실 이력 보관, 알림, 팀 기능은 brioly Cloud의 몫입니다.
3. **전체 재스캔, 부분 재작성.**
   - LLM 호출은 컴포넌트 단위로 나누고, 멤버의 structural 해시가 바뀐 컴포넌트만 다시 씁니다.
   - 속성은 `structural` / `detail` / `volatile` 3등급입니다. 서술문에는 structural만, 표의 칸에는 detail까지 씁니다.
   - 변경이 없으면 문서도 바뀌면 안 됩니다. 가짜 diff가 생기면 버그입니다.
   - 조회에 실패한 부분은 "없다"가 아니라 "읽지 못했다"입니다. 이전 스캔의 사실을 이어받아 표시하고(`facts.CarryForward`), 문서에서 지우지 않습니다.
4. **모든 서술에는 근거가 있어야 합니다.**
   - 문서의 각 서술은 `source_ref`(ARN, 파일 경로·라인 등)를 가진 사실에서 나와야 합니다.
   - 추론한 내용은 추론이라고 표시합니다.
5. **다이어그램은 사실 그래프에서 결정적으로 생성합니다**(Mermaid). LLM이 그리게 하지 않습니다.
6. **생성 문서는 고치지 않고, 사람의 지식은 주석으로 둡니다.**
   - 생성 문서는 언제든 통째로 다시 만들 수 있어야 합니다.
   - 사람이 아는 것(이유, 담당자, 주의점)은 컴포넌트·사실에 붙는 주석과 컴포넌트 레지스트리(`components.yaml`)에 둡니다. 대상이 바뀌면 주석을 지우지 않고 "아직 맞나요?"를 묻습니다.
   - 소스 간 충돌은 사실 종류별 신뢰 순서로 처리합니다. 스캔 순서로 정하지 않습니다.
7. **컴포넌트 ID는 앵커(대표 리소스)에서 만들고, 멤버는 규칙으로 묶습니다.** LLM은 요약, 워크로드 세부 역할, 애매한 레포 연결만 맡습니다.
8. **변경의 중요도(severity)는 결정적 규칙으로 정합니다.** LLM은 변경을 요약할 뿐 중요도를 정하지 않습니다.

## 보안 규칙 (반드시 지킬 것)

- **secret을 수집하지 않습니다.** DB 접속 정보, ID/PW, 토큰 등이 해당합니다.
  - Terraform state, Lambda·ECS 환경변수, `.env` 파일, 하드코딩된 키에 secret이 섞여 있을 수 있습니다.
  - 저장하거나 LLM에 보내기 **전에** gitleaks로 마스킹합니다.
- **Cloud는 AWS와 GitHub의 정적 키를 받거나 저장하지 않습니다.**
  - AWS: IAM Role + tenant별 External ID (구성 정보만 읽고 데이터는 읽지 않는 정책. `ReadOnlyAccess`는 쓰지 않음)
  - GitHub: GitHub App
  - 그 밖의 SaaS: OAuth 우선, 지원하지 않으면 API key를 KMS 봉투 암호화로 저장하고 쓰기 전용으로 둠
- **로컬 모드(`generate`, `sync`)는 키를 써도 됩니다**(AWS 자격 증명, Cloud sync 토큰. 모델 키는 쓰지 않습니다).
  - `brioly.yaml`에는 참조(`${ENV_VAR}`)만 적습니다.
  - AWS는 표준 자격 증명 체인을 씁니다.
- **코드 원문 처리 규칙**
  - 수집기 모드에서 LLM 키가 있으면 **A**(로컬에서 요약하고 요약만 전송. 요약 스키마에 원문 코드를 담을 필드를 두지 않음)
  - 키가 없으면 경고 후 동의를 받았을 때만 **B**(Cloud에서 분석 직후 폐기)
  - **A에서 B로 자동 전환하지 않습니다.** 키에 문제가 생기면 실패 처리하고 알립니다.
- **읽기 권한을 과장하지 않습니다.** ECS Task Definition·Lambda API는 환경변수 값을 평문으로 돌려주고, GitHub App은 소스 전체를 읽을 수 있습니다. 고객 안내·문서에서 "메타데이터만 읽는다"고 쓰지 않습니다. "읽을 수 있는 것"과 "저장·전송하는 것"을 구분해서 설명합니다.
- **해시가 같으면 문서도 같아야 합니다.** 렌더링에는 해시에 포함되는 값만 씁니다(커밋 SHA, 줄 번호, revision, volatile 값 출력 금지).
- **confused deputy 방지**: 사용자가 직접 입력한 계정·프로젝트·테넌트 ID를 믿지 않습니다. External ID나 동의 흐름으로 tenant에 묶은 값만 씁니다.
- clone한 코드는 작업 단위 임시 공간에만 두고, 작업이 끝나면 삭제합니다.

## 기술 스택

| 영역 | 선택 |
|---|---|
| CLI, 수집기, Cloud 백엔드·워커 | **Go** |
| 웹 UI | **TypeScript + Next.js** |
| 저장소 | PostgreSQL. 사실은 JSONB + `hash`, 이력은 `valid_from`/`valid_to`. 관계(Edge)는 테이블. 추후 pgvector |
| 작업 큐 | River (Postgres 기반). 필요해지면 Temporal 검토 |
| Secret 마스킹 | gitleaks |
| LLM | Claude Opus 5.5 (`claude-opus-5-5`). 공식 Anthropic SDK(Go: `anthropic-sdk-go`, TS: `@anthropic-ai/sdk`) 사용 |

### LLM 사용 규칙

- 출력은 **structured outputs**로 JSON 스키마를 강제합니다. 결과를 다시 사실 저장소에 넣고 diff해야 하기 때문입니다.
- 주기 스캔은 **Message Batches API**를 씁니다. 지연에 민감하지 않으므로 비용을 50% 줄일 수 있습니다.
- 고정 프롬프트에는 **prompt caching**을 적용합니다.
- **입력 해시 캐시**를 둡니다. 입력이 같으면 LLM을 다시 호출하지 않습니다.
- SDK API는 추측하지 말고 문서(claude-api 스킬, Context7)로 확인한 뒤 작성합니다.

### AI가 쓰는 문서의 규칙: `pkg/enrich/guide.md`

- 온보딩 문서와 JD처럼 LLM이 쓰는 문서에 대해 **정한 판단은 모두 [`pkg/enrich/guide.md`](pkg/enrich/guide.md)에 적습니다.** 이 파일은 바이너리에 포함되어 모든 요청의 시스템 프롬프트로 전달됩니다. 대화에서 정한 글쓰기 규칙(무엇을 쓰고 빼는지, 문서별 역할, 어조)을 Go 코드의 프롬프트 문자열에만 넣지 마세요. 코드의 프롬프트에는 출력 필드 설명처럼 스키마에 묶인 내용만 둡니다.
- **전체를 다시 쓰지 않고 최소한의 diff로 고칩니다.** 쓸 때마다 모델의 답(`enrich.State`)을 호출한 쪽이 저장해 두고(Cloud는 DB에), 다음 실행에서 입력이 같은 단위는 호출 없이 그대로 쓰고, 입력이 바뀐 단위는 이전 답을 함께 주어 바뀐 사실만 반영하게 합니다. 규칙은 가이드의 "Revising" 절에 있습니다.
- 가이드를 고치면 모든 단위가 다시 호출되지만, 이전 답을 받은 수정이므로 문서가 통째로 바뀌지는 않습니다.
- 각주 라벨은 인용한 ID에서 만듭니다(번호가 밀려 diff가 커지는 것을 막기 위함).

## 레포 구성

- **`brioly`** (이 레포, Apache-2.0): CLI, 수집기, 사실 스키마, 해석·렌더링 파이프라인. 명령은 `brioly generate`(로컬 문서 생성)와 `brioly sync`(한 번 수집해 사실만 Cloud로 전송)가 있고, `brioly agent`(상시 실행)는 계획입니다.
- **brioly Cloud**(별도 비공개 레포)는 이 레포를 Go 모듈로 가져다 씁니다. diff 엔진은 이 레포에 둡니다.

커넥터는 지원하는 인증 방식(`role` / `oauth` / `api_key`)을 선언하고, 모두 같은 사실 스키마를 반환합니다.

## 코드 구조

| 경로 | 역할 |
|---|---|
| `cmd/brioly` | CLI (`generate`, `sync`, `components init`, `diff`, `replay`, `version`). 설정을 읽어 `pkg/scan`을 부르고 결과를 파일로 씀. 모델을 부르지 않음(`pkg/enrich`를 import하지 않음) |
| `pkg/scan` | 결정적 파이프라인 전체: 수집 → 마스킹 → 읽지 못한 부분 이어받기 → 컴포넌트 묶기. CLI와 Cloud가 같은 `scan.Run`을 씀. `scan.Clean`(밖에서 온 스냅샷을 다시 마스킹·재계산)과 `scan.Combine`(두 스냅샷을 하나로, 겹치면 앞의 것 우선), `scan.Without`(저장된 스냅샷에서 한 커넥터의 사실·관계·coverage를 빼고 규칙 관계와 컴포넌트를 다시 만듦)도 여기 있음. AWS 자격 증명은 `aws.Config`로 주입 가능(수임한 Role). 호출한 쪽이 직접 수집한 결과는 `Options.Collected`로 넣음(자격 증명을 `Run`에 넘기지 않는 호출자용. 마스킹·이어받기·컴포넌트는 똑같이 거침) |
| `pkg/facts` | Fact·Edge·Component·Snapshot, kind 레지스트리(`kinds.go`: 속성 등급), 결정적 ID, structural·detail 해시, `Finalize` |
| `pkg/components` | 앵커 기반 컴포넌트 묶기(규칙), `components.yaml` 레지스트리. 배포 대상과 그것이 가리키는 리소스의 연결도 여기서 규칙으로 만듦(`deploy.go`: `rule:deploy-target`, `rule:deploy-manifest`, `rule:image-push`, `rule:deploy-path`). 이름만으로 이은 연결은 inferred, 후보가 둘 이상이면 고르지 않음(`DeployStatuses`가 문서에 이유를 줌) |
| `pkg/diff` | 스냅샷 비교, 변경 이벤트, severity 규칙, 속성 변동 집계 |
| `pkg/config` | `brioly.yaml` 로딩, `${VAR}` 치환(파싱 후 값 노드 단위) |
| `pkg/collect/code` | 로컬 레포 수집기. GitHub Actions workflow 파일(`.github/workflows/*.yml`)에서 트리거와 **배포 대상**(`code.deploy_target`)도 읽음: 잘 알려진 액션·명령과 대상 이름이 되는 매개변수의 표(`deploy.go`. 한 줄을 더하면 하나를 더 인식하고, `TestRecognisers`에 사례를 추가)로 인식. 이름은 파일이 직접 말하는 것만 씀(리터럴, `env:`, 리터럴 matrix, 스크립트가 스스로 정한 변수, 같은 레포의 재사용 workflow에 넘기는 입력). 그 밖(`vars`·`secrets`·step 출력·명령 결과)은 추측하지 않고 "무엇에 달려 있는지"를 이름으로 남김(`unresolved`). `run:` 스크립트 본문은 저장하지 않음. `env:`·스크립트 변수·matrix의 값은 인식된 배포 단계가 대상 이름으로 쓸 때만 저장하고, 그 변수의 이름이 secret처럼 보이거나(`secretName`) 값이 gitleaks에 걸리면 저장하지 않음(secret의 **이름**은 저장). 마스킹될 값은 사실 ID에 넣지 않음(ID는 나중에 마스킹되지 않음). 읽는 양과 값의 길이에 한도가 있음(`workflow.go`의 `max…`: 한도에 닿으면 coverage `partial`에 어느 한도인지 적음). 커밋·태그·실행 번호·액션 버전은 해시에 들어가지 않음. GitHub API는 부르지 않음(파일만). 파싱되지 않는 workflow 파일은 스캔을 실패시키지 않고 coverage `code.ci_workflow`·`code.deploy_target`을 `partial`로 남김(이전 스캔의 사실을 이어받음) |
| `pkg/collect/aws` | AWS 수집기. 서비스별 좁은 인터페이스로 fake 테스트 가능. 찾은 EKS 클러스터와 엔드포인트(호스트 → 사실)를 다음 수집기에 넘김 |
| `pkg/collect/kube` | Kubernetes 수집기(선택). 클러스터 API에서 워크로드·Service·Ingress만 GET으로 읽음. Secret·ConfigMap·파드는 읽지 않음. 의존성 없는 HTTP 클라이언트, 테스트는 가짜 API 서버 |
| `pkg/collect/cloudflare` | Cloudflare 수집기(선택, `sources.cloudflare.api_token`). API 토큰으로 GET만 보냄: zone과 SSL 모드, DNS 레코드와 프록시 여부, Workers(라우트·커스텀 도메인·바인딩 이름), Pages, Tunnel과 라우트, 로드 밸런서와 풀. 변수 값·TXT 내용·터널 토큰은 저장하지 않고, WAF·Access는 읽지 않음. 의존성 없는 HTTP 클라이언트, 테스트는 가짜 API 서버. 토큰을 아예 쓰지 못한 호출자는 `cloudflare.Unread`로 "읽지 못함"을 남겨 이전 사실을 이어받음. 뒤에 있는 것(AWS 로드 밸런서, Ingress)과의 연결은 수집기가 아니라 `pkg/components`의 규칙(`hosts.go`)이 호스트 이름으로 만듦 |
| `pkg/redact` | gitleaks 기반 secret 마스킹 |
| `pkg/enrich` | 유일한 LLM 사용처. CLI는 쓰지 않고 brioly Cloud가 씀: 컴포넌트별 설명, 개요, JD 초안. 글쓰기 규칙은 `guide.md`, 이전 답(`State`)을 받아 바뀐 부분만 수정, 온보딩 문서는 코드로 조립. 한 종류만 쓰는 옵션(`NoOnboarding`, `NoJobDescriptions`) |
| `pkg/lifecycle` | 버전 지원 종료일 조회. 날짜 표는 바이너리에 넣지 않고 `https://brioly.io/lifecycle/v1/data.json`에서 받음(`Fetch`, 형식·날짜 검증). CLI는 스캔 전에 받고, 못 받으면 이유를 출력하고 종료(2026-11-26 결정). Cloud도 같은 주소를 읽음. `BRIOLY_LIFECYCLE_URL`로 주소를 바꿀 수 있음(폐쇄망 미러, 테스트). 표는 `scripts/update-lifecycle.sh`가 endoflife.date에서 만듦. 표에 없는 버전은 추측하지 않고 "모름". 얼마나 임박했는지는 스캔 시각 기준 |
| `pkg/render` | 결정적 문서와 다이어그램, `[[fact-id]]` 인용 해석. 문서: `architecture.md`, `tech-stack.md`, `version-support.md`(버전 지원), `internet-exposure.md`(인터넷 노출 점검. 등급은 고정 규칙). 배포 대상이 있는 스냅샷은 `architecture.md`에 Delivery 절(어느 레포의 어느 workflow가 무엇을 배포하는지, 연결되지 않은 대상과 그 이유)이 생김. 없는 스냅샷의 문서는 그대로임(`delivery.go`). 다이어그램에는 그리지 않음(요청 흐름만 그림). `render.NewDiagrams`는 그림을 직접 그리는 쪽(brioly Cloud)을 위한 것: 뷰(시스템, 인터넷 노출, 클러스터별 워크로드)마다 상자의 위치와 선의 경로까지 고정 규칙으로 계산한 `DiagramLayout`과, 리소스별 속성 패널(`ResourcePanel`: structural·detail·label만, volatile 없음)을 줌. CLI가 쓰는 파일(Mermaid)은 여기서 나오지 않고 그대로임 |

- 새 kind나 속성을 추가하면 `pkg/facts/kinds.go`에 등급을 선언합니다. 선언하지 않은 속성은 버려지고, 수집기 테스트의 `facts.Undeclared` 검사에서 걸립니다. 분류나 정규화를 바꾸면 `RegistryVersion`을 올립니다.
- 테스트: `go test ./...`. 새 수집기는 "같은 입력이면 같은 해시", "배포(태그·revision 변경)로 해시가 바뀌지 않음", "환경변수 값이 결과에 남지 않음"을 테스트로 보장합니다.
- 테스트는 fake 모델을 씁니다. 실제 Claude API를 부르는 테스트를 추가하지 않습니다.
