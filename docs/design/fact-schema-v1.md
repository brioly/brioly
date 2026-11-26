# 사실 스키마 v1 설계: 속성 등급, 컴포넌트, 주석, 변경 이벤트

> 상태: **구현됨** (`pkg/facts`, `pkg/components`, `pkg/enrich`, `pkg/diff`). 설계와 다르게 구현한 부분은 9절 · 2026-11-23 · 이전 버전: [`fact-schema-v0.md`](fact-schema-v0.md) · 계획: [`../mvp-milestones.md`](../mvp-milestones.md)

v0는 "무엇이 있는가"를 안정적으로 수집하는 데 초점을 뒀습니다. v1은 2026-11-23 리뷰와 그 뒤의 결정을 반영해 **"무엇이 의미 있게 바뀌었는가"**와 **"사람의 지식을 어디에 두는가"**를 다룹니다. v0의 Fact·Edge·coverage·secret 규칙은 그대로 유지하고, 아래 내용이 v0의 2.4절(추론 Fact ID), 5.4절, 6절(블록 연결)을 대체합니다.

## 0. 이번에 확정된 결정

| 결정 | 내용 |
|---|---|
| 사람의 수정 | 생성 문서를 직접 고치고 pin으로 보존하는 방식을 **폐기**합니다. 생성 문서는 언제든 통째로 다시 만들 수 있고, 사람의 지식은 컴포넌트·사실에 붙는 **주석(annotation)**으로 따로 둡니다. |
| Cloud의 중심 | "문서를 최신으로 유지"에서 **"의미 있는 변경의 요약·알림 + 사실 이력 위의 Q&A"**로 옮깁니다. |
| 컴포넌트 ID | 멤버 전체의 해시가 아니라 **앵커(대표 리소스)**에서 만듭니다. |
| 속성 등급 | 해시 포함/제외의 2단계를 `structural` / `detail` / `volatile` **3단계**로 나눕니다. |

## 1. 속성 3등급

### 1.1 등급의 뜻

| 등급 | 바뀌면 일어나는 일 | 예 |
|---|---|---|
| `structural` | 변경 이벤트 발생, 관련 서술 재작성, 알림 대상 | 공개 여부, 엔진 종류, Multi-AZ, SG 규칙, 리스너 포트 |
| `detail` | 표의 값만 조용히 갱신. 서술 재작성 없음, 알림 없음(변경 피드에는 접힌 상태로 기록) | AMI, 인스턴스 타입, CPU·메모리, 패치 버전 |
| `volatile` | 아무 일도 없음. `facts.json`에만 기록 | 실행 수, 상태, revision, 이미지 tag |

Fact는 등급별로 맵을 나눠 갖고, 해시도 둘입니다.

```go
type Fact struct {
    // ... v0의 ID, Kind, Name, Source, Ref, Derivation, ObservedAt
    Attributes     map[string]any    `json:"attributes"`        // structural
    Details        map[string]any    `json:"details,omitempty"` // detail
    Volatile       map[string]any    `json:"volatile,omitempty"`
    Labels         map[string]string `json:"labels,omitempty"`  // 허용 목록에 있는 태그만 (structural)
    StructuralHash string            `json:"structural_hash"`   // kind, name, attributes, labels
    DetailHash     string            `json:"detail_hash"`       // details
}
```

**렌더링 규칙**: 서술문(문장)은 `Attributes`와 `Labels`만 씁니다. `Details`는 표의 칸에만 씁니다. `Volatile`은 문서에 쓰지 않습니다. 그래야 "structural 해시가 같으면 서술이 같다"가 성립합니다.

### 1.2 분류보다 정규화가 먼저

값을 그대로 등급에 넣지 않고, 의미 있는 부분만 잘라 structural에 넣습니다.

| 원래 값 | structural | detail |
|---|---|---|
| 의존성 `^4.19.2` | `major: 4` | `version_constraint: ^4.19.2` |
| RDS `engine_version: 16.4` | `engine_major: 16` | `engine_version: 16.4` |
| Lambda `runtime: nodejs22.x` | 그대로 (런타임 교체는 의미 있는 변경) | |
| 태그 | 허용 목록의 키만 `labels`로 | 나머지 태그는 `details.tags` |

태그 허용 목록의 기본값은 `env`, `environment`, `team`, `owner`, `service`, `app`, `project`이고(대소문자 무시), `brioly.yaml`의 `labels.allow`로 바꿀 수 있습니다. 배포 도구가 붙이는 태그(배포 시각, 커밋 SHA 등)가 structural 해시를 흔들지 않게 하기 위해서입니다.

### 1.3 kind 레지스트리

등급을 수집기 코드 곳곳에 흩어 두지 않고, kind별 선언 하나로 모읍니다. 수집기는 값을 채우기만 하고, 어느 맵에 넣을지는 레지스트리가 정합니다. 레지스트리에 없는 속성은 **버립니다**(v0의 허용 목록 원칙과 같음).

```go
// pkg/facts/kinds
var Registry = map[string]Kind{
    "aws.rds.cluster": {
        Structural: []string{"engine", "engine_major", "engine_mode", "multi_az", "storage_encrypted",
            "publicly_accessible", "subnet_group", "security_group_ids"},
        Detail:   []string{"engine_version", "instance_class", "endpoint", "reader_endpoint"},
        Volatile: []string{"status", "member_count"},
        Anchor:   true, // 2절
    },
}
const RegistryVersion = 1 // 분류가 바뀌면 올림 (5절 재기준)
```

### 1.4 초기 분류 (잠정)

실제 데이터로 검증하기 전의 출발점입니다(6절).

| kind | structural | detail |
|---|---|---|
| `aws.ec2.vpc` / `subnet` / `route_table` | CIDR, AZ, public 여부, 라우트, main 여부 | |
| `aws.ec2.security_group` | ingress, egress | |
| `aws.ec2.instance` | subnet, SG, IAM 프로필 | instance_type, ami_id |
| `aws.autoscaling.group` | subnets, launch template 이름 | min_size, max_size |
| `aws.elbv2.load_balancer` | type, scheme, subnets, SG | dns_name |
| `aws.elbv2.listener` / `rule` / `target_group` | 프로토콜, 포트, 조건, 우선순위, 액션, target_type | health_check_path |
| `aws.ecs.service` | launch_type, subnets, SG, assign_public_ip, LB 연결, task_definition_family | |
| `aws.ecs.task_definition` | 컨테이너 이름·image_repository·포트, network_mode | cpu, memory, env_keys, secret_keys |
| `aws.lambda.function` | runtime, package_type, VPC 설정 | handler, memory_mb, timeout_s, architectures, env_keys |
| `aws.rds.*` | 1.3절 참조. 단, 클러스터의 `multi_az`는 detail (`RegistryVersion` 2) | |
| `code.repository` | primary_language | 언어 비율 |
| `code.dependency` (dev 제외) | ecosystem, major | version_constraint |
| `code.dependency` (dev) | | 전부 detail |
| `code.framework` | 이름 | |
| `code.dockerfile` | final_base_image, exposed_ports | base_images, multi_stage |
| `code.ci_workflow` | triggers, trigger_filters, deploy_targets, calls, environments, auth | actions |
| `code.deploy_target` | target_type, job, environment, auth, unresolved, 대상을 가리키는 값 (v0 문서의 "GitHub Actions 배포 경로") | recognized_by, role_to_assume, defined_in, resolved_from |
| `iac.terraform.*` | resource_type, module source | |
| `k8s.workload` | 종류, namespace, image_repositories, ports | replicas |

Edge는 모두 structural입니다.

## 2. 컴포넌트

### 2.1 Fact가 아닌 별도 타입

v0에서는 컴포넌트가 `inferred.component` Fact였습니다. v1에서는 스냅샷의 별도 배열로 둡니다. 대부분을 LLM이 아니라 규칙으로 만들기 때문입니다.

```go
type Component struct {
    ID       string   `json:"id"`       // 2.2절
    Anchor   string   `json:"anchor"`   // 앵커 Fact ID
    Name     string   `json:"name"`     // 기본값: 앵커의 이름. 레지스트리가 덮어씀
    Role     string   `json:"role"`     // 규칙으로 정하고, 워크로드 세부 역할만 LLM이 제안
    Members  []string `json:"members"`  // Fact ID, 정렬
    Summary  string   `json:"summary,omitempty"` // LLM. 해시에 포함하지 않음
    Hash     string   `json:"hash"`     // 멤버 ID + 멤버들의 structural 해시
}
```

### 2.2 앵커와 ID

**앵커**는 컴포넌트의 정체성을 대표하는 리소스 하나입니다. 앵커가 될 수 있는 kind는 레지스트리에서 `Anchor: true`로 표시합니다.

| 앵커 kind | 컴포넌트 | 기본 역할 |
|---|---|---|
| `aws.ecs.service`, `aws.lambda.function`, `aws.autoscaling.group`, 단독 `aws.ec2.instance`, `k8s.workload` | 워크로드 | `workload` (LLM이 frontend / backend_api / worker / scheduled_job 중 제안) |
| `aws.rds.cluster`, 클러스터 밖의 `aws.rds.instance` | 데이터 저장소 | `data_store` |
| `aws.elbv2.load_balancer` | 진입점 | `network_edge` |
| 어떤 워크로드와도 연결되지 않은 `code.repository` | 코드만 있는 컴포넌트 | `code_only` |

```
component ID = "cmp_" + hex(sha256(앵커 Fact ID))[:12]
```

- 이 kind들의 ARN은 이름 기반이라(ECS 서비스, Lambda, RDS) 배포·교체에도 바뀌지 않습니다. ALB는 ARN에 임의 문자열이 있어 재생성하면 ID가 바뀌는데, 이 경우는 2.5절의 재연결로 처리합니다.
- 멤버가 늘거나 줄어도 ID는 그대로입니다.
- 이전 상태 없이 계산되므로 무료 CLI에서도 같은 ID가 나옵니다.

### 2.3 멤버를 규칙으로 묶기

LLM 없이 edge를 따라갑니다.

| 출발 | 따라가는 edge | 멤버로 추가 |
|---|---|---|
| ECS 서비스 | `uses` → | Task Definition |
| 워크로드 | ← `routes_to` | 타깃 그룹, 그리고 그 타깃 그룹으로 보내는 리스너 규칙 |
| 로드 밸런서 | `contains` → | 리스너 (규칙은 목적지 워크로드 쪽에 속함) |
| 워크로드 | `built_from` → | 레포 (아래) |
| 레포 (멤버가 된 경우) | `uses`, `contains` → | 프레임워크, Dockerfile, CI 워크플로와 그 워크플로의 배포 대상 중 어디에도 연결되지 않은 것. 의존성은 수가 많아 넣지 않음(기술 스택 문서에 나열) |
| 워크로드의 멤버 | ← `deploys`, `built_from` → | 그것을 배포하거나 그 이미지를 push하는 배포 대상(`code.deploy_target`)과 그 대상이 든 워크플로 (2026-11-26) |

RDS 클러스터의 인스턴스도 멤버로 넣지 않습니다. 리플리카 오토스케일링으로 늘고 줄기 때문이며, 추가·삭제는 `info` 이벤트로만 남깁니다.

VPC, 서브넷, 라우트 테이블, 보안 그룹은 어느 컴포넌트에도 넣지 않습니다. 문서의 네트워크 절에서 따로 설명합니다.

**레포 연결(`built_from`)**은 확실한 것만 규칙으로 잇습니다.

1. 워크로드의 이미지 저장소 이름(마지막 경로 요소)이나 워크로드 이름이 레포 이름과 **정확히 같고 후보가 하나**이면 연결합니다(`derivation: inferred`, `producer: rule:name-match`).
2. 후보가 여럿이거나 없으면 LLM에게 **후보 목록 안에서 고르게** 합니다(없음도 선택지). 결과는 컴포넌트 해시로 캐시합니다.
3. 레지스트리에 사람이 적은 연결이 있으면 그것이 우선합니다.
4. (2026-11-26) 레포의 workflow가 그 워크로드를 배포하거나 그 이미지를 push한다는 근거가 레포 하나를 가리키면 1의 이름 규칙보다 먼저 연결합니다(`producer: rule:deploy-path`). 조건은 v0 문서의 "GitHub Actions 배포 경로" 절에 있습니다.

**컴포넌트 간 관계**는 멤버 사이의 `depends_on`·`routes_to`·`runs_on`에서 계산합니다(예: "Public API → main-db").

### 2.4 컴포넌트 레지스트리

사람이 컴포넌트에 대해 내린 결정과 지식을 담습니다. CLI에서는 `brioly.yaml` 옆의 `components.yaml`(없어도 동작), Cloud에서는 DB입니다.

```yaml
version: 1
components:
  - id: cmp_9f2c51ab03de
    anchor: aws:arn:aws:ecs:ap-northeast-2:123456789012:service/prod/api
    name: Public API            # 표시 이름
    role: backend_api
    owner: platform-team
    add: [gh:acme/api]          # 멤버 추가
    remove: []                  # 멤버 제외
    merge: [cmp_77aa01c2e9f0]   # 다른 컴포넌트를 흡수 (예: 같은 서비스의 worker)
    notes:                      # 주석 (3절)
      - body: "결제 승인 지연 때문에 2025년에 Fargate로 옮겼다. 배포는 #deploy 채널 공지 후에 한다."
ignore:                         # 임시 리소스는 컴포넌트·변경 이벤트에서 제외
  - kind: aws.ecs.service
    name: "preview-*"
```

- `generate`는 이 파일을 **읽기만** 합니다. 쓰는 것은 사람이거나 `brioly components init`(현재 컴포넌트 목록으로 뼈대를 생성) 같은 명시적 명령입니다.
- 적용 순서: `ignore` → 규칙으로 만든 컴포넌트 → ID → `merge`(연쇄 병합 포함) → `add` → 레포 확장(프레임워크·Dockerfile·CI 워크플로) → `remove` → `name`/`role`/`owner` → 메모.
- 병합된 컴포넌트의 메모는 병합한 쪽으로 따라갑니다. 앵커를 찾지 못한 항목의 메모는 버리지 않고 "더 이상 찾을 수 없음"으로 표시해 보여줍니다.
- `ignore`, `merge`, `add`, `remove`, `id`를 바꾸면 재기준 회차가 됩니다(5절). 이름·담당자·메모 변경은 해당하지 않습니다.

### 2.5 앵커가 사라졌을 때

서비스 이름을 바꾸거나 ALB를 다시 만들면 앵커 ID가 바뀝니다.

- **CLI**: 레지스트리 항목의 앵커가 스냅샷에 없으면 경고합니다. 멤버가 가장 많이 겹치는 새 컴포넌트를 후보로 보여주고, 사람이 `anchor`를 고칩니다. `id`는 레지스트리에 적힌 값을 유지합니다.
- **Cloud**: 사라진 컴포넌트와 새 컴포넌트의 멤버 겹침(Jaccard)이 0.5 이상이면 "같은 컴포넌트인가요?"를 제안합니다. 수락하면 기존 ID를 새 앵커에 묶어서 주석과 이력이 이어집니다.

### 2.6 LLM 호출 단위

v0는 스냅샷 전체를 한 프롬프트에 넣어서, 사실 하나만 바뀌어도 전부 다시 추론했습니다. v1은 조각으로 나눕니다.

| 호출 | 입력 | 캐시 키 |
|---|---|---|
| 컴포넌트 요약·역할 (컴포넌트마다) | 멤버의 structural 속성, 멤버 사이의 edge, 관련 컴포넌트 이름, 해당 주석. 멤버가 아닌 사실(레포의 의존성 등)은 넣지 않음 | 컴포넌트 `Hash` + 주석 해시 + 프롬프트 버전 + 모델 |
| 시스템 개요 (한 번) | 컴포넌트 목록(이름·역할·요약)과 컴포넌트 간 관계 | 위 입력의 해시 |
| JD 소스 텍스트 (직무마다) | 기술 스택 요약 + 컴포넌트 목록 | 위 입력의 해시 |

온보딩 문서는 "개요 + 컴포넌트별 절"을 **코드로 조립**합니다. 컴포넌트 하나가 바뀌면 그 절만 다시 씁니다. 컴포넌트별 호출은 서로 독립이라 Batches API에 그대로 실을 수 있습니다.

## 3. 주석 (사람의 지식)

생성 문서는 고치지 않습니다. 사람이 아는 것(왜 이렇게 만들었는지, 담당자, 주의할 점)은 주석으로 적습니다.

```go
type Annotation struct {
    ID           string    `json:"id"`
    Target       string    `json:"target"`        // 컴포넌트 ID, Fact ID, 또는 "doc:<절 키>"
    Body         string    `json:"body"`          // Markdown
    Author       string    `json:"author,omitempty"`
    UpdatedAt    time.Time `json:"updated_at"`
    ObservedHash string    `json:"observed_hash"` // 작성 시점의 대상 해시(컴포넌트 Hash 또는 structural 해시)
}
```

| 상황 | 동작 |
|---|---|
| 대상이 그대로 | 문서의 해당 컴포넌트 절에 "팀이 남긴 메모"로, 생성된 서술과 구분해서 표시 |
| 대상의 해시가 바뀜 | 주석은 그대로 두고 **"대상이 바뀌었습니다. 메모가 아직 맞나요?"**를 변경 피드에 올림. 확인하면 `ObservedHash` 갱신 |
| 대상이 사라짐 | 주석을 지우지 않고 "연결이 끊긴 메모"로 모아서 보여줌 |

- LLM에는 주석을 "사람이 제공한 맥락"으로 표시해서 넘기고, 인용은 `[[note:<id>]]`로 합니다. 주석 내용이 수집한 사실과 어긋나면 사실을 따르고 어긋남을 드러냅니다(v0의 신뢰 순서: 현재 상태는 라이브 인프라가 우선, 의도·이유는 사람이 우선).
- 주석도 저장·전송 전에 secret 마스킹을 거칩니다.
- CLI에서는 레지스트리의 `notes`가 주석입니다. Cloud에서는 UI로 작성하고, 작성자와 이력이 남습니다.

## 4. 변경 이벤트

brioly Cloud가 값을 더하는 지점입니다. 두 스냅샷을 비교해 이벤트를 만듭니다.

```go
type ChangeEvent struct {
    ID          string   `json:"id"`
    Type        string   `json:"type"`
    Severity    string   `json:"severity"`             // high | medium | low | info
    ComponentID string   `json:"component_id,omitempty"`
    Subject     string   `json:"subject"`              // Fact, Edge 또는 컴포넌트 ID
    Changes     []Change `json:"changes,omitempty"`    // 속성별 before/after
    RuleID      string   `json:"rule_id,omitempty"`    // severity를 정한 규칙
}
```

| type | 조건 |
|---|---|
| `fact_added` / `fact_removed` | ID가 생기거나 사라짐. 삭제는 coverage가 `complete`일 때만 |
| `structural_changed` | structural 해시가 다름 |
| `detail_changed` | detail 해시만 다름. 항상 `info` |
| `edge_added` / `edge_removed` | 관계 변화 (예: 새 의존 관계) |
| `component_added` / `component_removed` / `membership_changed` | 컴포넌트 수준 변화 |
| `coverage_changed` | 읽을 수 없게 된 영역이 생김 (권한 문제 알림) |
| `annotation_stale` | 3절 |

**severity는 결정적 규칙으로 정합니다.** LLM은 이벤트를 요약할 뿐, 중요도를 정하지 않습니다. 초기 규칙:

| 규칙 | severity |
|---|---|
| `publicly_accessible` false → true (RDS), 또는 처음부터 공개인 RDS가 추가됨 | high |
| 보안 그룹 ingress에 `0.0.0.0/0` 또는 `::/0` 추가, 또는 그런 규칙을 가진 보안 그룹이 추가됨 | high |
| `storage_encrypted` true → false, RDS 인스턴스의 `multi_az` true → false (클러스터의 `multi_az`는 리더 수에 따라 바뀔 수 있어 detail) | high |
| 서브넷이 private → public | high |
| internet-facing 로드 밸런서 추가, 워크로드·데이터 저장소 추가 또는 삭제 | medium |
| 엔진 major 변경, 런타임 변경, 새 `depends_on` | medium |
| workflow가 저장된 AWS access key를 쓰기 시작함(`auth`에 `aws:static_keys`가 생김) | medium |
| 그 밖의 structural 변경 | low |
| detail 변경 | info |

**이벤트를 만들지 않는 경우**
- 사실이 속한 계정·리전(또는 레포)의 수집 상태가 두 스냅샷에서 다르거나 한쪽이라도 `error`/`partial`인 경우의 추가·속성 변경·관계·멤버 변경. 조회가 하루 실패했다가 복구되면 값과 관계가 사라졌다 나타나기 때문입니다. 수집 상태 변화 자체는 `coverage_changed`로 알립니다. 양쪽에서 똑같이 `denied`인 영역은 안정된 것으로 봅니다.
- 새 워크로드의 `component_added`(앵커의 `fact_added`와 중복)와 클러스터 인스턴스의 증감(`info`)
- 재기준 회차(5절)
- 레지스트리의 `ignore`에 해당하는 리소스
- coverage가 `complete`가 아닌 영역의 삭제

**주간 요약**은 이벤트 목록을 컴포넌트별로 묶어 LLM이 서술하고, 각 문장은 이벤트 ID를 인용합니다. `info`만 있는 주에는 "의미 있는 변경 없음"으로 끝냅니다.

v0 계획의 `do not ask again` 규칙은 **음소거 규칙**(특정 규칙 ID·컴포넌트·kind 조합의 이벤트를 알리지 않음)으로 바뀝니다.

## 5. 재기준 (rebaseline)

스키마, kind 레지스트리, 정규화 규칙이 바뀌면 실제 변경이 없어도 해시가 달라집니다.

```
baseline_key = schema_version : RegistryVersion : 태그 허용 목록 : components.yaml의 구조 부분 해시
```

- 스냅샷마다 `baseline_key`를 기록합니다.
- 이전 스냅샷과 `baseline_key`가 다르면 그 회차는 **이벤트를 만들지 않고** 새 기준으로 삼습니다. 주석의 `ObservedHash`도 조용히 갱신합니다.
- 프롬프트·모델 버전 변경은 해시와 무관합니다. LLM 캐시만 무효화되어 서술이 다시 쓰이고, 변경 이벤트는 생기지 않습니다.

## 6. 재생 테스트로 분류 검증하기

1.4절의 분류와 4절의 규칙은 추측에서 출발했습니다. 실제 데이터로 고칩니다.

1. 실제 계정(brioly 자체 인프라, 이후 파트너)에서 매일 스냅샷을 기록합니다(`facts.json`을 날짜별로 보관. secret은 이미 제거된 상태).
2. `brioly replay <dir>`가 연속한 스냅샷을 비교해 kind·속성별 변경 횟수를 집계합니다.
3. 판정 기준
   - 사람이 "아무것도 안 바꾼 날"에 `low` 이상 이벤트가 **0건**이어야 합니다.
   - 배포만 한 날에는 `info`만 나와야 합니다.
   - 일부러 만든 변경(SG 개방, 서비스 추가 등)은 **빠짐없이** 잡혀야 합니다. 가짜 변경이 없는 것만 보면, 진짜 변경을 놓쳐도 통과하기 때문입니다.
4. 자주 흔들리는 속성은 등급을 내리거나 정규화를 추가하고 `RegistryVersion`을 올립니다.

기록한 스냅샷 묶음은 회귀 테스트 자료로 계속 씁니다. 실제 인프라 정보이므로 공개 레포에는 올리지 않습니다(`private/`).

## 7. v0에서 옮겨가는 순서

| 순서 | 작업 | 영향 범위 |
|---|---|---|
| 1 | `pkg/facts/kinds`: kind 레지스트리, `Details`, 두 해시, `baseline_key` | `pkg/facts`, 두 수집기(값을 레지스트리로 분배) |
| 2 | 정규화: 버전 major, 태그 허용 목록 | 수집기, `pkg/config`(`labels.allow`) |
| 3 | `pkg/components`: 앵커, 규칙 기반 묶기, 레지스트리 적용 | 새 패키지. `inferred.component` Fact 제거 |
| 4 | `pkg/enrich` 재작성: 컴포넌트 단위 호출과 캐시, 문서 조립 | `pkg/enrich`, `pkg/render` |
| 5 | `pkg/diff`: 변경 이벤트와 severity 규칙, `brioly replay` | 새 패키지. OSS에 둠(아래) |
| 6 | 주석 렌더링과 `annotation_stale` | `pkg/render`, `pkg/diff` |

**diff 엔진을 OSS에 두는 이유**: 무료/유료를 기능을 막아서 나누지 않기로 했습니다. 두 `facts.json`을 비교하는 일은 CLI에서도 되게 하고, Cloud는 이력 보관, 알림 전달, 요약, Q&A, 팀 기능으로 값을 받습니다.

## 8. 열린 질문

- [ ] 여러 워크로드가 한 레포를 공유할 때(모노레포) 레포를 각 컴포넌트의 멤버로 중복해서 넣을지, 하위 경로 단위로 나눌지
- [ ] `network_edge` 컴포넌트를 로드 밸런서마다 둘지, 도메인(Route 53 수집 이후) 단위로 묶을지
- [ ] `env_keys` 변경을 detail로 두는 것이 맞는지 (새 의존을 암시할 수 있음. 다만 실제 의존은 `depends_on` edge로 잡힘)
- [ ] severity 규칙을 사용자가 조정할 수 있게 할지, 음소거 규칙만 둘지
- [ ] 멀티 계정에서 같은 이름의 서비스(dev·prod)를 한 컴포넌트의 환경으로 볼지, 별개 컴포넌트로 볼지

## 9. 구현하면서 달라진 점

| 설계 | 구현 |
|---|---|
| kind 레지스트리를 `pkg/facts/kinds` 패키지에 | `pkg/facts/kinds.go` 파일에 둠 (`Finalize`가 직접 쓰므로 같은 패키지가 단순함) |
| 주석에 `ObservedHash`를 저장 | CLI에서는 저장하지 않음. 두 스냅샷 사이에 컴포넌트 해시가 바뀌었고 그 컴포넌트에 주석이 있으면 `annotation_stale` 이벤트를 냄. 확인 상태를 기억하는 것은 Cloud 몫 |
| `ignore`는 컴포넌트와 이벤트에서만 제외 | 해당 사실과 그 edge를 스냅샷에서 아예 제거함. 문서에도 나오지 않아야 문서가 흔들리지 않기 때문 |
| 레포 후보가 여럿이면 LLM이 고름 | **미구현.** 경고를 내고 사람이 `add`로 지정하게 함 |
| Task Definition의 컨테이너별 `env_keys` | `container_env_keys`, `container_secret_keys`(detail)로 분리. 컨테이너 목록(structural)에는 이름·이미지 저장소·포트만 남김 |
| 레포가 멤버일 때 | 그 레포의 프레임워크, Dockerfile, CI 워크플로도 멤버로 넣음(2.3절에 반영) |
| 멀티 계정의 같은 이름 서비스 (8절) | 우선 **별개 컴포넌트**. 앵커 ID에 계정이 들어 있어 자연히 나뉨. 묶고 싶으면 `merge` 사용 |
| 수집 실패가 있던 회차의 LLM 재작성 | 변경 이벤트는 내지 않지만, 컴포넌트 해시는 달라질 수 있어 그 회차에 해당 컴포넌트를 다시 쓸 수 있음. 이전 상태를 아는 Cloud에서 막을 예정 |
| `brioly replay`의 판정 기준 자동화 | 집계표만 출력. "변경 없는 날 0건" 같은 판정은 사람이 봄 |
