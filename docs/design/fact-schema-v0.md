# 사실(Fact) 스키마 v0

> 상태: 현재 코드가 구현한 버전 · 2026-11-23
>
> **다음 버전은 [`fact-schema-v1.md`](fact-schema-v1.md)입니다.** v1이 이 문서의 추론 Fact(2.4절 일부, 3.3절, 5.4절)와 문서 블록 연결(6절)을 대체하고, 속성을 3등급으로 나눕니다. 7절 리뷰 과제의 결정도 v1에 있습니다.

brioly의 모든 문서는 이 스키마로 표현된 **사실(Fact)**과 **관계(Edge)**에서 만들어집니다. 수집기(OSS)와 Cloud가 같은 스키마를 쓰기 때문에, 간편 연결 모드와 수집기 모드를 오가도 이력이 그대로 이어집니다.

## 1. 설계 목표

| 목표 | 이 스키마에서의 장치 |
|---|---|
| **diff가 가능해야 함** | 결정적인 `id`, 정규화된 `attributes`의 `hash` |
| **변경이 없으면 해시도 같아야 함** | 자주 바뀌는 값은 해시에서 제외(`volatile`), 해시 계산 전에 정규화 |
| **모든 서술에 근거가 있어야 함** | 모든 Fact와 Edge에 `source_ref` 또는 `evidence`를 둠 |
| **secret이 새지 않아야 함** | 속성을 **허용 목록(allowlist)** 방식으로 수집하고, 환경변수 값은 저장하지 않음 |
| **수집 실패를 삭제로 오해하지 않아야 함** | 스냅샷에 커넥터별 수집 범위(coverage)를 기록 |
| **관찰한 것과 추론한 것을 구분해야 함** | `derivation: observed | inferred` |

## 2. 데이터 모델

```
Snapshot (스캔 1회)
 ├── coverage[]     커넥터·리전별로 무엇을 수집했고 무엇에 실패했는지
 ├── Fact[]         리소스, 파일, 의존성 등 "무엇이 있는가"
 └── Edge[]         Fact 사이의 관계, "무엇이 무엇과 연결되는가"
```

### 2.1 Fact

```go
type Fact struct {
    SchemaVersion string            `json:"schema_version"`     // "v0"
    ID            string            `json:"id"`                 // 결정적 ID (2.4절)
    Kind          string            `json:"kind"`               // 예: "aws.ec2.vpc" (3절)
    Name          string            `json:"name,omitempty"`     // 사람이 읽는 이름 (Name 태그, 리소스 이름 등)
    Source        Source            `json:"source"`             // 어디서 수집했나
    Ref           SourceRef         `json:"source_ref"`         // 근거 링크
    Attributes    map[string]any    `json:"attributes"`         // 구조적 속성. 해시에 포함됨
    Volatile      map[string]any    `json:"volatile,omitempty"` // 자주 바뀌는 값. 해시에서 제외, 표시용
    Labels        map[string]string `json:"labels,omitempty"`   // 태그와 라벨. 해시에 포함됨
    Derivation    Derivation        `json:"derivation"`
    ObservedAt    time.Time         `json:"observed_at"`        // 해시에서 제외
    Hash          string            `json:"hash"`               // 2.5절
}

type Source struct {
    Connector string `json:"connector"`        // "aws" | "github" | "local_repo"
    Scope     string `json:"scope"`            // AWS 계정 ID, GitHub 조직/레포
    Region    string `json:"region,omitempty"` // AWS 리전 (글로벌 서비스는 비움)
}

type SourceRef struct {
    Type      string `json:"type"`                 // "arn" | "file" | "url"
    Value     string `json:"value"`                // ARN, 레포 내 파일 경로, URL
    LineStart int    `json:"line_start,omitempty"` // type=file일 때
    LineEnd   int    `json:"line_end,omitempty"`
    Commit    string `json:"commit,omitempty"`     // type=file일 때 기준 커밋 SHA
}

type Derivation struct {
    Type     string   `json:"type"`               // "observed" | "inferred"
    Evidence []string `json:"evidence,omitempty"` // inferred일 때 근거가 된 Fact/Edge ID
    Producer string   `json:"producer,omitempty"` // inferred일 때 "model@prompt-version" (예: "claude-opus-5-5@enrich-v0.1")
}
```

### 2.2 Edge

```go
type Edge struct {
    SchemaVersion string     `json:"schema_version"`
    ID            string     `json:"id"`   // sha256(from|type|to) 앞 16바이트를 hex로
    Type          string     `json:"type"` // 2.3절
    From          string     `json:"from"` // Fact ID
    To            string     `json:"to"`   // Fact ID
    Derivation    Derivation `json:"derivation"`
    Ref           *SourceRef `json:"source_ref,omitempty"` // 관계를 직접 보여주는 근거가 있을 때
    Hash          string     `json:"hash"`
}
```

### 2.3 Edge 타입 (v0)

| type | 의미 | 예시 | 주된 derivation |
|---|---|---|---|
| `contains` | 포함 관계 | VPC → Subnet, ECS Cluster → Service | observed |
| `attached_to` | 붙어 있음 | Security Group → ENI·인스턴스·RDS | observed |
| `routes_to` | 트래픽 전달 | ALB Listener Rule → Target Group → ECS Service | observed |
| `runs_on` | 워크로드가 도는 플랫폼 | 레포의 Kubernetes Deployment → EKS 클러스터 (로드 밸런서 태그로 추론) | inferred |
| `depends_on` | 런타임 의존 | ECS Service → RDS (환경변수 값이 RDS 엔드포인트와 일치) | observed / inferred |
| `exposes` | 외부 노출 | Route 53 레코드 → ALB, CloudFront → ALB·S3 | observed |
| `defines` | IaC가 리소스를 정의 | Terraform resource → AWS 리소스 | observed (state나 태그로 매칭) / inferred |
| `built_from` | 이미지의 출처 | ECS 컨테이너 이미지 → 레포 (ECR 이름, Dockerfile) | inferred |
| `deploys` | 배포 경로 | GitHub Actions 워크플로 → ECS Service / Lambda | observed / inferred |
| `uses` | 코드가 사용하는 것 | 레포 → 의존성, 레포 → 프레임워크 | observed |

### 2.4 결정적 ID 규칙

ID는 **같은 대상이면 몇 번을 스캔해도 같은 값**이어야 합니다. 그래야 diff가 동작합니다.

| 대상 | ID 형식 | 예시 |
|---|---|---|
| AWS 리소스 | `aws:` + ARN. ARN이 없는 리소스는 `aws:{service}:{region}:{account}:{type}/{native-id}` | `aws:arn:aws:ec2:ap-northeast-2:123456789012:vpc/vpc-0abc` |
| 레포 | `gh:{owner}/{repo}` 또는 `repo:{name}`(로컬). git 저장소의 하위 폴더(모노레포 패키지)는 `//{하위 경로}`를 붙임 | `gh:acme/api`, `gh:acme/mono//services/api` |
| 레포 안의 파일 | `{레포ID}:file:{path}` | `gh:acme/api:file:Dockerfile` |
| 의존성 | `{레포ID}:dep:{매니페스트 경로}:{ecosystem}:{name}`. 모노레포에서 같은 패키지를 여러 매니페스트가 다른 버전으로 선언하므로 경로를 포함 | `gh:acme/api:dep:package.json:npm:express` |
| k8s 워크로드 | `{레포ID}:k8s:{파일 경로}:{namespace}/{kind}/{name}`. dev·prod overlay가 같은 이름을 쓰므로 경로를 포함 | `gh:acme/infra:k8s:k8s/prod/api.yaml:default/deployment/api` |
| 추론된 Fact | `inferred:{kind}:{members ID들의 정렬된 해시}`. 해시(2.5절)는 evidence의 해시로 계산 | `inferred:component:9f2c…` |

**주의할 점**
- **커밋 SHA와 버전은 ID에 넣지 않습니다.** 커밋 SHA는 `source_ref.commit`에 넣고, 버전은 `attributes`에 넣습니다. 그래야 "express 4.18 → 4.19"가 **같은 Fact의 속성 변경**으로 잡힙니다.
- **ECS Task Definition**은 배포할 때마다 revision이 올라갑니다. 그래서 Fact의 단위를 **family**로 잡고(`…:task-definition/api`), revision 번호는 `volatile`에 넣습니다.

### 2.5 해시 계산

```
hash = sha256( canonical_json({ kind, name, attributes, labels }) )
```

정규화(canonicalization) 규칙은 다음과 같습니다.
1. 객체 키는 사전순으로 정렬합니다.
2. **순서에 의미가 없는 배열은 정렬**합니다. 예: Security Group 규칙, Subnet 목록. 순서에 의미가 있는 배열(예: ALB 규칙의 우선순위)은 kind 정의에서 따로 명시합니다.
3. 숫자와 문자열 표현을 통일합니다. 예: 포트는 항상 정수로 씁니다.
4. `volatile`, `observed_at`, `source_ref.commit`은 **해시에서 제외**합니다.

**무엇을 `volatile`에 넣는가**: 실행 중 태스크 수, 인스턴스 상태, 마지막 수정 시각, 이미지 tag·digest, Task Definition revision 등입니다. 이런 값은 화면에는 보여줄 수 있지만, 이 값이 바뀌었다고 문서를 다시 쓰면 **가짜 diff**가 생깁니다.

> 이미지는 `attributes.image_repository`(예: `123….dkr.ecr…/api`)만 해시에 포함하고, tag와 digest는 `volatile`에 넣습니다.

### 2.6 Snapshot과 coverage

```go
type Snapshot struct {
    SchemaVersion    string     `json:"schema_version"`
    ID               string     `json:"id"`
    StartedAt        time.Time  `json:"started_at"`
    FinishedAt       time.Time  `json:"finished_at"`
    CollectorVersion string     `json:"collector_version"`
    Coverage         []Coverage `json:"coverage"`
    Facts            []Fact     `json:"facts"`
    Edges            []Edge     `json:"edges"`
}

type Coverage struct {
    Connector string   `json:"connector"`        // "aws"
    Scope     string   `json:"scope"`            // 계정 ID
    Region    string   `json:"region,omitempty"`
    Kind      string   `json:"kind"`             // "aws.ecs.service"
    Status    string   `json:"status"`           // "complete" | "partial" | "denied" | "error" | "skipped"
    Detail    string   `json:"detail,omitempty"` // 예: "AccessDenied: ecs:DescribeServices"
}
```

**diff 규칙: 수집 실패는 삭제가 아닙니다.**

상위 목록 조회가 실패하면(예: ECS 클러스터 목록 권한 거부) 그 아래 종류(서비스, Task Definition)도 `skipped`로 기록합니다. 하위 호출이 모두 성공했더라도 목록 자체가 불완전하기 때문입니다.

- 이전 스냅샷에 있던 Fact가 이번에 보이지 않더라도, 해당 `(connector, scope, region, kind)`의 coverage가 `complete`일 때만 **삭제**로 판단합니다.
- 그 외의 상태(`partial`, `denied`, `error`, `skipped`)라면 **"확인 불가"**로 처리하고 문서를 바꾸지 않습니다. 이때 사용자에게 권한 문제를 알립니다.

## 3. Kind 목록 (v0, MVP 범위)

### 3.1 AWS

| kind | 해시에 포함하는 주요 속성 (allowlist) | volatile |
|---|---|---|
| `aws.ec2.vpc` | cidr_blocks, is_default | |
| `aws.ec2.subnet` | vpc_id, cidr_block, az, public(라우팅으로 판단) | available_ip_count |
| `aws.ec2.route_table` | vpc_id, routes(대상 → 타깃 종류와 ID) | |
| `aws.ec2.nat_gateway` / `aws.ec2.internet_gateway` | vpc_id, subnet_id | state |
| `aws.ec2.security_group` | vpc_id, ingress·egress 규칙(정렬) | |
| `aws.ec2.instance` (Auto Scaling 그룹 소속은 제외) | instance_type, subnet_id, sg_ids, ami_id, iam_profile | state, public IP 유무 |
| `aws.autoscaling.group` (Auto Scaling API) | subnet_ids, min_size, max_size, launch template | desired_capacity, 실행 중 인스턴스 수·타입·AMI |
| `aws.elbv2.load_balancer` | type(alb/nlb), scheme, subnets, sg_ids | state |
| `aws.elbv2.listener` / `aws.elbv2.rule` / `aws.elbv2.target_group` | 포트, 프로토콜, 조건(우선순위 순서 유지), 타깃 종류 | 타깃 health |
| `aws.ecs.cluster` / `aws.ecs.service` | launch_type, subnets, sg_ids, LB 연결, task_definition_family | desired_count(오토스케일링으로 바뀜), running_count, 현재 revision |
| `aws.ecs.task_definition` | cpu, memory, 컨테이너(name, image_repository, ports, **env 키 이름만**) | revision, image tag·digest |
| `aws.eks.cluster` / `aws.eks.nodegroup` | version, endpoint 공개 여부, 서브넷, 인스턴스 타입, 크기 범위 | status |
| `aws.lambda.function` | runtime, handler, memory, timeout, vpc_config, **env 키 이름만**, 트리거 | last_modified, code_sha |
| `aws.rds.cluster` / `aws.rds.instance` | engine, engine_version, instance_class, multi_az, storage_encrypted, publicly_accessible, subnet_group, endpoint | status, 클러스터 멤버 수(리플리카 오토스케일링) |
| `aws.elasticache.replication_group` | engine, version, node_type, cluster_mode, multi_az | status |
| `aws.s3.bucket` | region, versioning, encryption, public_access_block (**객체는 수집하지 않음**) | |
| `aws.cloudfront.distribution` | origins, aliases, behaviors 요약 | status |
| `aws.route53.zone` / `aws.route53.record` | 이름, 타입, alias 대상 | |
| `aws.sqs.queue` / `aws.sns.topic` | fifo 여부, DLQ 연결, 구독 대상 종류 | 메시지 수 |
| `aws.apigateway.api` | 타입(REST/HTTP/WS), 엔드포인트 종류, 통합 대상 | |

> AWS 서비스 목록은 아직 확정되지 않았습니다.

### 3.2 코드 (GitHub / 로컬 레포)

| kind | 주요 속성 |
|---|---|
| `code.repository` | 기본 브랜치, 주 언어, 언어 비율(구간 단위로 반올림해서 사소한 변동을 줄임) |
| `code.dependency` | ecosystem(npm, go, pip, maven…), name, version_constraint, dev 여부 |
| `code.framework` | 이름(Next.js, Spring Boot, FastAPI…), 감지 근거 |
| `code.dockerfile` | base_image, 노출 포트, 멀티 스테이지 여부 |
| `code.ci_workflow` | 플랫폼(GitHub Actions…), 트리거, 배포 대상 힌트 |
| `iac.terraform.resource` | resource type, 이름, 모듈 경로 (**state 파일은 읽지 않음**) |
| `k8s.workload` | 종류(Deployment 등), 이미지 저장소, 포트, 레플리카 |

### 3.3 추론 결과 (Enrich 단계, `derivation: inferred`)

| kind | 의미 |
|---|---|
| `inferred.component` | 여러 리소스를 묶은 논리적 컴포넌트. 예: "결제 API = ECS Service + Task Definition + Target Group + 레포 acme/payments" |
| `inferred.component_role` | 컴포넌트의 역할 설명 (짧은 구조화 텍스트) |

추론 결과는 반드시 `evidence`에 근거 Fact와 Edge의 ID를 담습니다. **근거 ID의 해시가 같으면 LLM을 다시 호출하지 않습니다**(입력 해시 캐시).

## 4. secret 방지 규칙

1. **속성은 kind별 허용 목록에 있는 것만 수집합니다.** API 응답을 통째로 저장하지 않습니다. AWS가 응답에 새 필드를 추가해도 자동으로 들어오지 않습니다.
2. **환경변수는 키 이름만 저장합니다.** 값은 저장하지 않습니다.
   - 단, 값이 **이미 수집한 리소스의 엔드포인트와 일치하면**(RDS 엔드포인트, SQS URL, ElastiCache 주소, 다른 서비스의 DNS 등) 값 대신 **`depends_on` Edge**로 바꿔서 남깁니다. 관계 정보는 살리고 값은 버리는 방식입니다.
3. **태그와 라벨**, 그리고 문자열 속성 전체에 gitleaks 규칙으로 마스킹을 적용합니다. 매칭되면 `"[REDACTED]"`로 바꾸고 coverage에 경고를 남깁니다.
4. **Terraform state 파일은 읽지 않습니다**(평문 secret 위험). Terraform은 `.tf` 소스만 파싱합니다.
5. S3 객체, DB 데이터, Secrets Manager·Parameter Store 값은 **API 호출 자체를 하지 않습니다.** M2의 IAM 정책에서도 이 권한을 빼서 이중으로 막습니다.

## 5. 예시

### 5.1 관찰한 Fact: ALB

```json
{
  "schema_version": "v0",
  "id": "aws:arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/api-prod/50dc6c495c0c9188",
  "kind": "aws.elbv2.load_balancer",
  "name": "api-prod",
  "source": { "connector": "aws", "scope": "123456789012", "region": "ap-northeast-2" },
  "source_ref": { "type": "arn", "value": "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/api-prod/50dc6c495c0c9188" },
  "attributes": {
    "type": "application",
    "scheme": "internet-facing",
    "subnet_ids": ["subnet-0a1", "subnet-0b2"],
    "security_group_ids": ["sg-0lb"]
  },
  "volatile": { "state": "active" },
  "labels": { "env": "prod", "team": "platform" },
  "derivation": { "type": "observed" },
  "observed_at": "2026-11-23T03:00:00Z",
  "hash": "sha256:4be1…"
}
```

### 5.2 환경변수에서 만든 Edge: ECS Service → RDS

ECS 컨테이너의 환경변수 `DB_HOST` 값이 Aurora 클러스터 엔드포인트와 일치하는 경우입니다. 값 자체는 어디에도 저장하지 않습니다.

```json
{
  "schema_version": "v0",
  "id": "e:7c41…",
  "type": "depends_on",
  "from": "aws:arn:aws:ecs:ap-northeast-2:123456789012:service/prod/api",
  "to": "aws:arn:aws:rds:ap-northeast-2:123456789012:cluster:main-db",
  "derivation": { "type": "observed" },
  "source_ref": { "type": "arn", "value": "arn:aws:ecs:ap-northeast-2:123456789012:task-definition/api" },
  "hash": "sha256:91aa…"
}
```

### 5.3 코드 Fact: 의존성

```json
{
  "schema_version": "v0",
  "id": "gh:acme/api:dep:package.json:npm:express",
  "kind": "code.dependency",
  "name": "express",
  "source": { "connector": "github", "scope": "acme/api" },
  "source_ref": { "type": "file", "value": "package.json", "line_start": 14, "line_end": 14, "commit": "3f9e2a1" },
  "attributes": { "ecosystem": "npm", "version_constraint": "^4.19.2", "dev": false },
  "derivation": { "type": "observed" },
  "observed_at": "2026-11-23T03:00:05Z",
  "hash": "sha256:0d3c…"
}
```

### 5.4 추론한 Fact: 컴포넌트

```json
{
  "schema_version": "v0",
  "id": "inferred:component:9f2c51…",
  "kind": "inferred.component",
  "name": "Public API",
  "source": { "connector": "brioly", "scope": "enrich" },
  "source_ref": { "type": "url", "value": "brioly://evidence/9f2c51" },
  "attributes": {
    "summary": "외부 고객용 REST API. ALB를 거쳐 ECS Fargate에서 실행되며 Aurora PostgreSQL을 사용함",
    "members": [
      "aws:arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/api-prod/50dc6c495c0c9188",
      "aws:arn:aws:ecs:ap-northeast-2:123456789012:service/prod/api",
      "gh:acme/api"
    ]
  },
  "derivation": {
    "type": "inferred",
    "evidence": ["aws:arn:aws:ecs:…:service/prod/api", "e:7c41…", "gh:acme/api:file:Dockerfile"],
    "producer": "claude-opus-5-5@enrich-v0.1"
  },
  "observed_at": "2026-11-23T03:02:10Z",
  "hash": "sha256:a71e…"
}
```

> `summary`는 LLM이 생성한 텍스트라서 같은 입력에도 매번 달라질 수 있습니다. 그래서 **추론 Fact의 해시는 `summary`가 아니라 `evidence`의 해시**로 계산합니다(근거가 같으면 같은 Fact). `summary`는 `volatile`로 옮기는 방안도 M1에서 검증합니다.

## 6. 문서 블록과의 연결 (M3 대비, 참고용)

M3의 부분 재작성을 위해 문서의 각 블록은 근거 Fact를 가리킵니다.

```json
{ "block_id": "b_net_01", "fact_refs": ["aws:arn:…:vpc/vpc-0abc", "aws:arn:…:subnet/…"], "facts_hash": "sha256:…", "pinned": false }
```

- `facts_hash`는 `fact_refs`가 가리키는 Fact들의 해시를 모아 계산합니다. 이 값이 바뀐 블록만 다시 씁니다.
- 문서에 찍는 근거 링크는 해시에 포함되는 값(ARN, 파일 경로)만 씁니다. 커밋 SHA·줄 번호·revision은 `facts.json`에만 남깁니다. 그래야 해시가 같을 때 문서도 같습니다.
- `pinned: true`인 블록(사용자가 수정한 블록)은 `facts_hash`가 바뀌었을 때 다시 쓰지 않고 **코멘트로 제안**합니다.

## 7. 열린 질문

> 2026-11-23 Fable 5.2 리뷰에서 나온 설계 과제(아직 결정 전): 컴포넌트 ID를 members 해시가 아닌 영속 ID로 두고 멤버 겹침으로 매칭할지, 속성별 "중요도"(문서에 반영할 변경인지)를 둘지, 섹션을 블록-사실 참조 대신 선택자(kind + 범위)에 묶을지, 스키마·프롬프트·모델 버전이 바뀔 때의 재기준(rebaseline) 규칙.

- [ ] 추론 Fact의 `summary`를 `attributes`에 둘지 `volatile`에 둘지 (5.4절)
- [ ] 멀티 계정 AWS Organizations를 v0에서 지원할지 (Fact ID에는 이미 계정 ID가 들어 있음)
- [ ] 언어 비율의 반올림 구간 (예: 5% 단위)
- [ ] 스냅샷 전송 형식: 전체 스냅샷 vs 변경분만 (MVP는 전체 전송으로 단순하게 시작하는 것을 권장)

## 읽지 못한 부분은 이전 스캔에서 이어받는다 (2026-11-24 추가)

조회가 거부되거나 일부만 성공하면 그 종류에 대해서는 "없다"고 말할 수 없습니다. 그대로 문서를 만들면 읽지 못한 리소스가 삭제된 것처럼 보입니다. 그래서 coverage가 `complete`가 아닌 종류(같은 계정·리전)는 이전 스냅샷(`facts.json`)에서 이어받습니다(`facts.CarryForward`).

| 경우 | 처리 | 표시 |
|---|---|---|
| 이전에 있고 이번에 없는 사실 | 그대로 복사 | `stale: "not_read"`, 문서에는 "(not read in this scan)" |
| 양쪽에 있지만 이번에 값이 빠진 사실(예: 태그 조회 실패) | 빠진 속성과 이름을 이전 값으로 채움 | `stale: "partly_read"`, 문서에는 "(partly read in this scan)" |
| 한쪽 끝이 위 종류인 관계 | 양쪽 끝이 모두 남아 있으면 복사 | `stale: true` |

- `stale`은 해시에 들어가지 않습니다. 이어받은 사실은 이전과 해시가 같아 변경 이벤트가 생기지 않고, "coverage lost" 이벤트만 남습니다.
- 컴포넌트를 묶는 규칙이 만든 관계(`rule:*`)는 복사하지 않고 다시 계산합니다.
- 분류 기준(스키마 버전, `RegistryVersion`, 라벨 허용 목록)이 다른 스냅샷에서는 이어받지 않습니다.
- 한계: 사실이 없는 종류의 조회 실패(예: 네트워크 인터페이스)에서 나온 관계는 이어받지 못합니다. 이 경우 문서는 "읽지 못함"이라고만 씁니다. 읽지 못하는 동안 실제로 삭제된 리소스는 조회가 복구될 때까지 문서에 남습니다.

## Kubernetes 클러스터 읽기 (2026-11-24 추가)

클러스터의 API 서버를 읽는 방법은 두 가지입니다(`pkg/collect/kube`). 자격 증명은 어느 쪽도 저장하지 않습니다.

- **kubeconfig**: brioly.yaml의 `sources.k8s.kubeconfig`가 가리키는 파일의 현재 컨텍스트(또는 `contexts`에 적은 컨텍스트)를 그 파일이 정한 자격 증명(토큰, 클라이언트 인증서, exec 플러그인)으로 읽습니다. EKS·GKE·AKS·자체 구축을 가리지 않습니다. 환경변수 `KUBECONFIG`나 `~/.kube/config`를 스스로 찾아 읽지는 않습니다(예전 이름 `sources.kubernetes`는 경고와 함께 읽힘).
- **`sources.k8s.eks: true`**: AWS 스캔이 찾은 EKS 클러스터마다, 스캔에 쓰는 AWS 신원으로 만든 단기 토큰으로 읽습니다. kubeconfig가 필요 없습니다.

kubeconfig의 API 서버가 AWS 스캔이 찾은 EKS 클러스터와 같으면 그 `aws.eks.cluster` 사실에 붙이고 한 번만 읽습니다. 그렇지 않으면 클러스터를 나타내는 `k8s.cluster` 사실(ID `k8s:cluster:<API 서버 호스트>`, 구조 속성은 버전)을 만듭니다. 이름은 kubeconfig의 클러스터 이름이라 파일마다 다를 수 있습니다.

| 읽는 것 | 사실 | 구조 속성 |
|---|---|---|
| Deployment, StatefulSet, DaemonSet, CronJob | `k8s.workload` | 종류, 네임스페이스, 이미지 저장소, 포트, 스케줄 |
| Service | `k8s.service` | 타입, 포트, 포트 매핑 |
| Ingress | `k8s.ingress` | 클래스, 호스트, 경로 → Service, TLS 여부 |

- **읽지 않는 것**: Secret, ConfigMap, 파드, 로그. 요청 자체를 보내지 않으며 예시 ClusterRole에도 권한이 없습니다.
- **환경변수**: 파드 템플릿에는 값이 평문으로 들어 있습니다. 이름만 `container_env_keys`(detail)로 남기고, 값은 메모리에서 의존 관계를 찾는 데만 쓰고 버립니다.
- **ID**: `k8s:<클러스터 사실 ID>:<namespace>/<kind>/<name>`. 레포 매니페스트에서 나온 같은 kind의 사실과는 `source.connector`(`kubernetes`)로 구분합니다.
- **관계(모두 observed)**: 워크로드·Service·Ingress `runs_on` 클러스터, Service `routes_to` 워크로드(selector가 파드 라벨에 포함), Ingress `routes_to` Service, 로드 밸런서 `routes_to` Service·Ingress(status가 보고하는 DNS 이름이 AWS 수집기가 본 이름과 같을 때), 워크로드 `depends_on` 엔드포인트·Service(환경변수 값의 호스트 이름이 정확히 일치할 때).
- **매니페스트와의 연결(inferred)**: 종류·네임스페이스·이름이 같은 매니페스트가 정확히 하나일 때 `defines` 관계로 잇고, 매니페스트는 실행 중인 워크로드의 컴포넌트에 들어갑니다. 여러 개면 잇지 않고 경고합니다.
- **기본 제외**: `kube-system`, `kube-public`, `kube-node-lease` 네임스페이스와 `default/kubernetes` Service.
- **실패 처리**: 401·403은 coverage `denied`, 일부 목록만 실패하면 `partial`. 이전 스캔에서 읽은 사실은 `CarryForward`로 유지됩니다.
- 클러스터를 읽지 않으면 이전처럼 로드 밸런서 태그와 매니페스트로 추론합니다.

## Cloudflare 읽기 (2026-11-26 추가)

Cloudflare API(v4)를 API 토큰으로 읽습니다(`pkg/collect/cloudflare`, brioly.yaml의 `sources.cloudflare.api_token`에는 `${CLOUDFLARE_API_TOKEN}` 같은 참조만 적음). GET 요청만 보내고, 토큰은 `Authorization` 헤더 말고는 어디에도 남지 않습니다(사실, source_ref, 로그, 오류 메시지). 리다이렉트는 따라가지 않습니다.

| 읽는 것 | 사실 | 구조 속성 | detail | volatile |
|---|---|---|---|---|
| Zone, zone 설정 | `cloudflare.zone` | 종류, 활성 여부(상태가 `active`인지), 일시 중지 여부, SSL 모드, Always Use HTTPS, 최소 TLS 버전 | 플랜 | 상태 |
| DNS 레코드 | `cloudflare.dns_record` | zone, 타입, 프록시 여부, 가리키는 곳(A·AAAA·CNAME·MX·NS만) | TTL, 레코드 수 | |
| Worker, 라우트, 커스텀 도메인, 바인딩 | `cloudflare.worker` | 라우트의 호스트(경로는 버리고 "일부 경로"라고만 표시), 도메인, 바인딩(`종류:이름`) | 변수 이름, secret 이름, compatibility date | |
| Pages 프로젝트 | `cloudflare.pages_project` | pages.dev 주소, 커스텀 도메인, 운영 브랜치, 레포 | 환경변수 이름 | |
| Tunnel, 설정 | `cloudflare.tunnel` | 설정 위치, ingress(`호스트 -> 스킴://호스트:포트`, 평가 순서 유지) | 터널 ID | 상태 |
| 로드 밸런서 | `cloudflare.load_balancer` | zone, 프록시·활성 여부, 분배 정책, 기본 풀과 fallback 풀의 이름(순서 유지. 지역별 풀과 규칙의 풀은 읽지 않음) | | |
| 풀 | `cloudflare.lb_pool` | 활성 여부, origin 주소 | | |

- **읽을 수 있는 것과 저장하는 것은 다릅니다.** Worker 설정과 Pages 프로젝트는 평문 변수의 값을 돌려줍니다. 응답에서 이름만 디코딩하고 값은 Go 값으로 만들지도 않습니다(변수와 secret의 **이름**은 저장합니다). TXT를 비롯한 다른 타입의 레코드 내용, 레코드의 comment와 tag, 터널 ingress의 path와 origin 설정, 서비스 주소에 적힌 자격 증명·경로·쿼리, 풀 origin의 Host 헤더는 저장하지 않습니다.
- **요청 자체를 보내지 않는 것**: Worker 코드와 secret, KV·R2·D1 내용, Pages 배포와 빌드 로그, 터널 토큰, 풀의 monitor, WAF·방화벽·rate limiting 규칙, Access, API 토큰, 인증서, 로그.
- **배포로 바뀌는 값은 아예 수집하지 않습니다**(수정 시각, etag, 버전·배포 ID, 레코드 ID). 그래서 배포는 어떤 해시도 바꾸지 않습니다.
- **레코드 사실의 단위는 (zone, 이름, 타입)입니다.** 같은 이름의 A 레코드 여러 개는 한 사실의 `targets`입니다. 모든 레코드가 프록시될 때만 `proxied`가 true입니다.
- **ID에는 모두 계정 ID가 들어갑니다**(같은 이름의 zone이 두 계정에 있을 수 있음. 도메인을 옮기는 동안 한쪽은 pending): `cloudflare:zone/<계정 ID>/<zone>`, `cloudflare:dns/<계정 ID>/<zone>/<TYPE>/<이름>`, `cloudflare:lb/<계정 ID>/<zone>/<호스트>`, `cloudflare:worker/<계정 ID>/<이름>`, `…:pages/…`, `…:tunnel/<계정 ID>/<터널 ID>`, `…:pool/<계정 ID>/<풀 ID>`.
- **Scope는 고정값 `api.cloudflare.com`이고, Region이 읽은 위치입니다**: zone 사실은 빈 값, DNS 레코드와 로드 밸런서는 `<계정 ID>/<zone 이름>`, Worker·Pages·Tunnel·풀은 계정 ID. coverage도 그 단위로 기록하므로 한 zone을 읽지 못해도 다른 zone의 변경과 삭제는 그대로 잡힙니다.
- **zone이나 계정 목록 자체를 읽지 못하면**(만료된 토큰) 어느 zone을 못 읽었는지 이름을 댈 수 없습니다. 이때는 Region이 `*`(`facts.AnyRegion`)인 coverage를 남기고, `CarryForward`는 이것을 그 kind에 대해 **자기 coverage 항목이 없는** region에 적용합니다(이번에 읽은 region은 자기 항목으로 판단). 목록 조회가 일시적으로 실패해 일부 계정을 방문하지 못했을 수 있을 때도 계정 단위 kind에 `*` 항목을 남깁니다. 이전 스캔에서 `complete`였던 zone·계정이 이번 스캔에 항목조차 없으면(토큰이 그 계정을 더 이상 보지 못함) `diff`가 `coverage-lost`로 알립니다. zone도 계정도 하나도 보이지 않는 응답(권한이 좁혀진 토큰의 빈 목록)도 "전부 삭제"가 아니라 읽지 못한 것으로 처리합니다.
- **사실의 속성을 채우는 조회**(zone 설정, Worker 라우트·커스텀 도메인·바인딩, 터널 설정, 계정 목록)는 coverage kind가 따로 있습니다(`cloudflare.zone_settings`, `cloudflare.worker_route`, `cloudflare.worker_domain`, `cloudflare.worker_settings`, `cloudflare.tunnel_configuration`, `cloudflare.account`). 다시 물어도 같은 답이 올 조회(401·403·404를 비롯한 4xx. 408·429 제외)는 그 kind만 `denied`가 되고 사실 자체는 `complete`로 남습니다. 그래야 "항상 없는 권한" 하나 때문에 그 영역의 변경 이벤트가 모두 꺼지지 않습니다(`diff`는 `partial`·`error`가 있는 영역의 이벤트를 만들지 않음). 일시적인 실패(5xx, 네트워크)일 때만 사실의 kind도 `partial`이 되어 이전 값이 채워집니다. 목록 조회도 같습니다: 4xx는 `denied`, 그 밖은 `error`. Worker 라우트는 zone마다 읽지만 계정의 Worker에 붙으므로, 한 zone의 라우트를 읽지 못하면 그 계정 Worker 전체의 `routes`를 비웁니다.
- **실패 처리**: 읽지 못한 값(설정, 라우트, 바인딩, ingress, 풀 이름)은 빈 값이나 대체 문구가 아니라 속성 자체를 비웁니다. 429는 `Retry-After`만큼 기다렸다가 세 번까지 다시 보냅니다. 오류 메시지에는 요청 경로의 틀(`/zones/{zone}/dns_records`)과 HTTP 상태, Cloudflare 오류 코드만 남기고 Cloudflare가 보낸 문구는 버립니다(문구에 요청 주소가 들어 있을 수 있음).
- **뒤에 있는 것과의 연결은 수집기가 만들지 않습니다.** `pkg/components`의 규칙이 스냅샷에 저장된 호스트 이름으로 만듭니다(`rule:*`). 양쪽을 서로 다른 스캔이 읽은 경우(DNS는 CLI, 로드 밸런서는 Cloud)에도 합친 스냅샷에서 연결되게 하기 위해서입니다.

| 관계 | 조건 | derivation |
|---|---|---|
| 레코드 `exposes` 로드 밸런서·Service·Ingress | CNAME 대상이 그 리소스의 DNS 이름과 같음(`dualstack.` 접두사 허용) | observed (`rule:host-match`) |
| 레코드 `exposes` Tunnel·Pages·Worker | 대상이 `<터널 ID>.cfargotunnel.com` 또는 pages.dev 주소, 이름이 커스텀 도메인, (프록시된 레코드만) 이름이 Worker 라우트의 호스트와 정확히 같음 | observed |
| 레코드 `exposes` Ingress | 대상이나 커스텀 도메인으로 연결되지 않았고(Worker 라우트만 걸린 경우 포함), 레코드 이름이 클러스터에서 읽은 Ingress의 host와 같음 | inferred (`rule:ingress-host`) |
| Tunnel `routes_to` 리소스 | ingress의 서비스 호스트가 알려진 엔드포인트와 같음 | observed |
| Tunnel `routes_to` Service | 서비스 호스트가 `이름.네임스페이스.svc…`이고 그런 Service를 가진 클러스터가 하나뿐 | inferred (`rule:service-name`) |
| 풀 `routes_to` 리소스 | origin 주소가 알려진 엔드포인트와 같음 | observed |

- `_`로 시작하는 라벨이 있는 이름(인증서·도메인 검증, DKIM)은 호스트 이름으로 보지 않습니다.
- **인터넷 노출 점검**: 호스트 이름마다 "Cloudflare proxy"인지 "DNS only"인지(일시 중지된 zone은 모두 DNS only, 활성이 아닌 zone은 "Cloudflare가 서비스하지 않음")와, origin에 Cloudflare를 거치지 않고 닿을 수 있는지를 스캔이 본 범위에서만 적습니다. 프록시된 레코드만으로는 origin이 직접 접근을 막는다고 쓰지 않습니다. Worker 라우트가 걸린 이름이라도 레코드가 가리키는 주소가 따로 있으면 그 주소를 origin으로 함께 적습니다. origin이 AWS 로드 밸런서이고 보안 그룹에 **리스너 포트를 덮는 TCP 규칙**이 `0.0.0.0/0`으로 열려 있으면 Medium(ICMP나 다른 포트는 해당 없음), SSL 모드 `off`·`flexible`은 Medium, 프록시로 설정된 레코드가 있는데 zone이 일시 중지면 Medium, `full`은 Low입니다. Cloudflare를 스캔하지 않은 스냅샷의 문서에는 Cloudflare에 관한 문장이 들어가지 않습니다.
- **변경 중요도**: 프록시 해제(레코드), zone 일시 중지, zone이 활성에서 비활성으로 바뀜은 high(`cloudflare-proxy-disabled`), SSL 모드가 `off`·`flexible`로 바뀌면 medium(`origin-encryption-weakened`).
- **범위 밖**: WAF·rate limiting 규칙(규칙식에 헤더 값이 들어갈 수 있고, 정직한 요약 규칙을 아직 정하지 못함), Access(정책의 의미를 해석해야 함), workers.dev 주소, R2·KV·D1, A 레코드의 IP와 AWS 리소스의 연결(AWS 수집기가 공인 IP를 저장하지 않음), CloudFront·API Gateway·S3 웹사이트(AWS 수집기에 아직 없음).
