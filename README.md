# brioly

brioly scans your AWS account, Kubernetes clusters, Cloudflare and code repositories and writes architecture and tech stack documents for you. The documents are made by fixed code from what was collected, with no AI model involved: every statement links to its source, and the same system always gives the same documents.

> Status: early development (M1). Interfaces and output formats will change.

## What you get

```
brioly-docs/
├── architecture.md      # network, entry points, compute, data stores, dependencies, delivery (which repository deploys what), internet exposure
├── tech-stack.md        # cloud services, languages, frameworks, containers, CI/CD, IaC
├── version-support.md   # when the versions you run on stop being supported (clusters, databases, runtimes, base images)
├── internet-exposure.md # what the internet can reach, open security groups, public or unencrypted databases, which host names go through Cloudflare's proxy
├── diagrams/system.mmd  # Mermaid diagram generated from the facts
└── facts.json           # everything brioly collected, with source references
```

Commit the whole directory. `facts.json` is also what the next run falls back on: when part of a scan fails (a missing permission, a throttled API), brioly keeps what the last scan saw of that part and marks it "not read in this scan" instead of dropping it from the documents.

## Quick start

```sh
curl -sSL https://brioly.io/install.sh | sh   # Linux and macOS; checks the download against the release's checksums
# or: go install github.com/brioly/brioly/cmd/brioly@latest
# or: download an archive from https://github.com/brioly/brioly/releases (Windows too)

cp brioly.example.yaml brioly.yaml   # edit sources
brioly generate                      # scan and write the documents; no API key, no model (reads a table of dates from brioly.io)

brioly sync --dry-run                # scan and report how much would be sent to brioly Cloud
brioly sync                          # send the facts to a brioly Cloud workspace (needs cloud.token)

brioly components init               # starter components.yaml: name things, set owners, add notes
brioly diff old/facts.json new/facts.json   # what changed, rated by fixed rules
```

## How it works

1. **Collect.** Plain API calls and file parsing. AWS: VPC, subnets, route tables, gateways, security groups (and what actually uses them, from network interfaces), EC2, Auto Scaling groups, load balancers (with tags and registered targets), ECS, EKS clusters and node groups, Lambda (with what triggers a function), RDS, ElastiCache, DynamoDB tables, S3 buckets (their public access settings and what they notify: never an object), CloudFront distributions, Route 53 zones and records, API Gateway (REST, HTTP and WebSocket APIs: routes, how they are authorized, what they lead to), SQS queues, SNS topics, and IAM roles (who may assume them and the names of their policies: no policy document). A distribution's origin, a DNS alias or an API's integration that is a bucket, a load balancer, a function or an API is linked to it from the configuration. Kubernetes (optional): workloads (Deployments, StatefulSets, DaemonSets, CronJobs), Services and Ingresses read from a cluster's API server. Set `sources.k8s.kubeconfig` in brioly.yaml to a kubeconfig file to read its current context, for any cluster kubectl can reach (EKS, GKE, AKS, self-managed), or set `sources.k8s.eks: true` to read every EKS cluster the AWS scan finds without a kubeconfig. What is found is linked to the load balancers and databases of the AWS scan. Without it, what runs in a cluster is known from manifests in the scanned repositories, and a load balancer is linked to its Service through the tags Kubernetes puts on it (marked as inferred). Cloudflare (optional, `sources.cloudflare`): zones with their SSL mode, DNS records and whether each goes through Cloudflare's proxy, Workers (routes, custom domains, what they are bound to), Pages projects, Tunnels and their routes, load balancers and pools. A record, a tunnel route or a pool whose address is a load balancer, a database or an Ingress of the other scans is linked to it by host name; a link made from a name alone is marked as inferred. Code: languages, dependencies, frameworks, Dockerfiles, GitHub Actions workflows (triggers, and what each job deploys to: see [Delivery](#delivery)), Terraform sources, Kubernetes workloads and Services.
2. **Normalize.** Everything becomes facts and relationships with stable IDs and content hashes ([schema](docs/design/fact-schema-v0.md)).
3. **Group.** Rules follow the relationships from an anchor (an ECS service, a Lambda function, a database cluster, a load balancer, a distribution, an API, a cache, a table) to form components. A component's ID comes from its anchor, so it stays the same as members come and go.
4. **Render.** Same facts, same documents: on an unchanged environment the Markdown documents and the diagram come out byte-for-byte the same (`facts.json` records scan times, so it does change).

## Security

- brioly only calls the read actions in [docs/examples/aws-readonly-policy.json](docs/examples/aws-readonly-policy.json) (plus `sts:GetCallerIdentity`): `Describe*`/`List*` actions, a few `Get*` actions that return settings (a bucket's region, public access block, policy status and notification targets, the account's public access block, named queue attributes), and `apigateway:GET` on the eleven listing paths the policy names. It never lists or reads S3 objects, receives a queue's messages, reads a table's items or database contents, Secrets Manager or Parameter Store values, or Terraform state, and the policy does not allow it.
- Some of those answers hold more than brioly keeps, and none of it is copied into a fact: a CloudFront distribution's custom origin headers, an API's resource policy and its stages' variables, the endpoints of SNS subscriptions that are not AWS resources (email addresses, phone numbers, URLs), the values of TXT records, the conditions of an IAM role's trust policy. brioly does not request bucket policies, queue policies or IAM permissions policies at all: of a bucket's policy it keeps only AWS's own verdict on whether it is public.
- Be aware of what read access means: the ECS `DescribeTaskDefinition` and Lambda `ListFunctions` APIs return environment variable values in plain text. brioly stores them by **name only**; a value is used in memory to detect that a service talks to a known endpoint (for example an RDS cluster), then discarded.
- In a Kubernetes cluster brioly only lists workloads, Services and Ingresses. It never reads Secrets, ConfigMaps, pods or logs, and the [example role](docs/examples/kubernetes-readonly.yaml) does not allow it. The same caveat applies as for ECS: a workload's pod template contains environment variable values in plain text, and brioly keeps their names only.
- From Cloudflare brioly only sends GET requests, with an API token you create ([permissions below](#cloudflare)). What that token can read and what brioly keeps are different: a Worker's settings and a Pages project return the values of plain-text variables, and brioly keeps the **names** of variables and secrets only (the values are never decoded from the answer). Of DNS records it keeps where A, AAAA, CNAME, MX and NS records point; the content of TXT and every other type, and record comments and tags, are not kept. Of a tunnel route and a Worker route it keeps the host name (and for a tunnel the origin's scheme, host and port), not paths or origin settings. Your Cloudflare account ID is part of the identifiers of what is collected. It never requests Worker code, the values of secrets, KV, R2 or D1 contents, tunnel tokens, WAF rules, Access policies, API tokens or certificates.
- Of a workflow file brioly keeps: its triggers and their filters (branches, tags, paths, cron), the names of its jobs' environments and of the actions and workflows it uses, the names a recognised deploy step is given as its target (a cluster and a service, a function, an image, a file path), whether that step is under a condition, and how the job signs in. The text of a `run:` script is never kept. A value from `env:`, from a variable a script sets or from a matrix is kept in one case only: where a recognised deploy step uses it as the name of its target; and not even then when the variable's own name says it is a secret (`PASSWORD`, `TOKEN`, `KEY`, `SECRET`, ...) or the value looks like a credential to the masking rules. An expression is kept by the name it refers to (`secrets.DEPLOY_ROLE`, `vars.ECS_SERVICE`): that is a name, not a value. If you write a secret into the place a target's name is read from under a name that does not say so (`--function-name fn-$DB`, with `DB` holding a password), brioly has no way to tell and keeps it as the name.
- URL credentials (`https://user:pass@...`) are stripped from collected values.
- Collectors copy only the fields they declare; the raw API responses are never stored, logged or sent to a model. On top of that, values that look like secrets are masked with [gitleaks](https://github.com/gitleaks/gitleaks) rules before anything is written or sent.
- Use a read-only AWS profile (one from `~/.aws/config` or `~/.aws/credentials`, so an access key kept there works). [docs/examples/aws-readonly-policy.json](docs/examples/aws-readonly-policy.json) lists every action brioly calls; an action you leave out is reported as an incomplete part of the scan, not as missing resources.

## What leaves your machine

- `brioly generate`: nothing about your system leaves your machine. brioly reads the sources you configured (the AWS API, your clusters' API servers, the Cloudflare API, your local repositories) with your credentials, and writes files. It never calls an AI model. Besides reading those sources it makes one request: a GET of the table of end-of-support dates from `https://brioly.io/lifecycle/v1/data.json` (or the address in `BRIOLY_LIFECYCLE_URL`). That request carries no data; like any request it shows the server your IP address.
- `brioly sync`: the collected facts are sent to your brioly Cloud workspace, after masking, over HTTPS with a sync token you create there. The same facts as `facts.json`: resource names, configuration values, relationships, dependency names, file paths and environment variable **names**. Source code, environment variable values and what you wrote in `components.yaml` are never sent, and nothing is sent to a model. Each send replaces the previous one. `--dry-run` scans and sends nothing.
- Nothing brioly collected is sent anywhere by `brioly generate`.

## Your knowledge stays yours

Generated documents are never meant to be edited: they are rebuilt on every run. What only people know goes into `components.yaml`: display names, owners, which pieces belong together, and notes ("moved to Fargate in 2025 because..."). Notes appear in the documents next to the component, apart from generated text, and are given to the model as trusted context. brioly reads this file and never rewrites it.

## Changes that matter

Every attribute is either structural (a database became public, a runtime changed), a detail (a patch version, an instance size) or volatile (task counts, image tags). `brioly diff` compares two snapshots and rates each change with fixed rules: opening a security group to the internet is always high, a patch bump is always info, a deployment is nothing at all. Keep snapshots with `generate --history DIR` and run `brioly replay DIR` to see which attributes churn in your environment.

## Version support and exposure

`version-support.md` lists the versions you run on (EKS and Kubernetes, RDS and Aurora engines, ElastiCache engines, Lambda runtimes, the base images of your Dockerfiles, a few frameworks) with the day their standard support ends, soonest first. The dates are a table that brioly.io serves (built from [endoflife.date](https://endoflife.date) with `scripts/update-lifecycle.sh`), so that a new date reaches you without a new release. `brioly generate` reads it at the start of every run; if it cannot, it stops and says why. A version that is not in the table is listed as not known. Inside a network that cannot reach brioly.io, serve a copy of the table and set `BRIOLY_LIFECYCLE_URL` to its address.

`internet-exposure.md` lists what the internet can reach and the settings that widen or weaken that: security groups open to `0.0.0.0/0` (rated by which ports), databases with a public address or without encryption, public cluster endpoints. With Cloudflare it also lists every host name, whether it goes through Cloudflare's proxy or is DNS only, and what the scan could see of whether the origin can be reached without Cloudflare. A proxied record alone is never taken as proof that it cannot. Every finding comes from a fixed rule that the document states, and it ends with what the review does not cover. It is a review of configuration, not a security audit.

## Delivery

When a scanned repository has GitHub Actions workflows (`.github/workflows/*.yml`), brioly reads from those files **which repository deploys where**. There is nothing to configure, and nothing is asked of GitHub: only the files in the checkout are read.

- **What is recognised.** A table of well-known actions and commands and the parameters that name their target: `aws-actions/amazon-ecs-deploy-task-definition` and `aws ecs update-service` (cluster, service), `aws lambda update-function-code`, `aws s3 sync` and `aws cloudfront create-invalidation`, `docker push` and `docker/build-push-action` (also behind `aws-actions/amazon-ecr-login` and `docker/metadata-action`), `kubectl apply`, `kubectl set image` and `kubectl rollout restart`, `helm upgrade`, `cloudflare/wrangler-action` and `wrangler deploy` / `wrangler pages deploy` (the Worker's name is read from the wrangler configuration file next to the code), `terraform apply`, `serverless deploy`, `sam deploy`, `cdk deploy`, a release published on GitHub, and a few for platforms brioly does not read. The table is `pkg/collect/code/deploy.go`: one line teaches it another action or command.
- **Only what the file states.** A name is taken when it is written in the file: literally, through an `env:` value at workflow, job or step level, through a matrix written out in the file, through a variable the script sets itself, or through the inputs a workflow of the same repository passes when it calls another (`uses: ./.github/workflows/x.yml`). A name that comes from anywhere else (a repository variable or secret, the output of a step, the result of a command) is recorded as what it depends on, for example `${{ vars.ECS_SERVICE }}`, and the target is listed as "not determinable from the file". brioly does not guess. A workflow of another repository that is called is named, not fetched.
- **Linked by rule, and it says how.** A target is linked to a resource of the other scans by the names the workflow states: an ECS service by cluster and service name, a Lambda function by name, a Worker or Pages project by name, a Kubernetes workload by kind, name and namespace, manifests applied by path to the workloads those files declare, and an image that is pushed to whatever runs that image. A link that rests on names alone is marked as inferred; it is certain only when the workflow also states the account and region. When two resources that were read fit the name (the same service in two regions), neither is picked and both are listed. When none does, the target is listed as named in the workflow and not found: it may be in an account, region or cluster that is not scanned.
- **How the job signs in** is recorded too, and only as far as the file shows it. "Through GitHub's OIDC provider (a role, no stored key)" is said when the job assumes a role, uses no access keys anywhere before the deploy step, and has the `id-token: write` permission. Access keys anywhere earlier in the job are what signs in, whatever role is assumed with them afterwards. A role without that evidence is "assumes a role; how it signs in is not determinable from the file". `brioly diff` rates a workflow that starts to use stored keys as medium.
- **The repository behind a component.** A repository whose workflow pushes the image only one component runs is taken to be that component's code, whatever the two are called. A repository that only deploys a component (and nothing else) is taken when names decide nothing: a repository whose name fits the component exactly still wins over one that merely deploys it. A repository that deploys several components without building them is not taken: it is more likely where deploys are run from.
- **Not understood:** composite actions and actions brioly has no line for, scripts called from a step (`./deploy.sh`, `make deploy`, an npm script), arguments of shell functions (`$1`), and anything deployed by another CI system, by Argo CD or Flux from a cluster, or by Terraform resources rather than by a workflow step. `if:` conditions are not evaluated: a target is listed whenever its step is written, and marked as conditional when the job or step has one. A workflow file that is not valid YAML, or larger than 1 MB, is listed as a part that was not read; what the last scan read of the workflows is kept meanwhile.
- **Limits.** What is read of workflows is bounded, so that no repository can make a scan run long: 8 MB of workflow files and 24 MB of scripts and values per repository, 4 MB per workflow, 300 steps per job, 1000 deploy targets, names of at most 256 bytes. A workflow that reaches a limit is read up to it and listed as not read in full, with the limit it reached. This is the same on every scan of the same files; while it lasts, deploy targets removed from that repository's workflows stay listed as "not read in this scan".

## Cloudflare

```yaml
sources:
  cloudflare:
    api_token: ${CLOUDFLARE_API_TOKEN}   # a reference: the token itself stays in your environment
```

Create an API token in the Cloudflare dashboard (My Profile, API Tokens, Create Custom Token) with these permissions, all **Read**, for the accounts and zones you want documented:

| Scope | Permission | What brioly reads with it |
|---|---|---|
| Zone | Zone: Read | the zones |
| Zone | DNS: Read | DNS records |
| Zone | Zone Settings: Read | SSL mode, "Always Use HTTPS", minimum TLS version |
| Zone | Workers Routes: Read | which Worker answers which route |
| Zone | Load Balancers: Read | load balancers |
| Account | Workers Scripts: Read | Workers, their custom domains and bindings |
| Account | Cloudflare Pages: Read | Pages projects |
| Account | Cloudflare Tunnel: Read | Tunnels and their routes |
| Account | Load Balancing: Monitors And Pools: Read | load balancer pools (monitors are not requested) |

A permission you leave out is not an error: that part is reported as not read, with the request that was refused, and the rest is collected and compared as usual. What is read is recorded per zone and per account, so a zone the token cannot read says nothing about the others (one exception: Worker routes are read per zone, and when they cannot be read for one zone the routes of that account's Workers are left as "not read"). When Cloudflare cannot be read at all (an expired token, an outage), what the last scan saw is kept and marked "not read" instead of disappearing. The token is sent to `api.cloudflare.com` only and is not written to the documents, `facts.json`, logs or errors.

Not read: WAF, firewall and rate limiting rules, Access applications and policies, page and transform rules, the `workers.dev` addresses of Workers, load balancer pools other than the default and fallback ones, R2, KV, D1 and other storage, certificates, logs and analytics.

## Keeping documents up to date

`brioly generate` writes documents once; run it from a scheduled CI job and commit the output to keep them current ([GitHub Actions example](docs/examples/github-actions.yml)). brioly Cloud (in development) adds what files in git cannot: a history of your infrastructure facts, summaries and alerts for the changes that matter, questions answered from that history, and a place for your team's own notes.

## Development

```sh
go test ./...
go build -o bin/brioly ./cmd/brioly
```

## License

[Apache License 2.0](LICENSE). The name "brioly" and its logos are not covered by the license.
