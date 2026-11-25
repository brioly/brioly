# brioly

brioly scans your AWS account, Kubernetes clusters and code repositories and writes architecture and tech stack documents for you. The documents are made by fixed code from what was collected, with no AI model involved: every statement links to its source, and the same system always gives the same documents.

> Status: early development (M1). Interfaces and output formats will change.

## What you get

```
brioly-docs/
├── architecture.md      # network, entry points, compute, data stores, dependencies, internet exposure
├── tech-stack.md        # cloud services, languages, frameworks, containers, CI/CD, IaC
├── version-support.md   # when the versions you run on stop being supported (clusters, databases, runtimes, base images)
├── internet-exposure.md # what the internet can reach, open security groups, public or unencrypted databases
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
brioly generate                      # scan and write the documents; no API key, no model

brioly sync --dry-run                # scan and report how much would be sent to brioly Cloud
brioly sync                          # send the facts to a brioly Cloud workspace (needs cloud.token)

brioly components init               # starter components.yaml: name things, set owners, add notes
brioly diff old/facts.json new/facts.json   # what changed, rated by fixed rules
```

## How it works

1. **Collect.** Plain API calls and file parsing. AWS: VPC, subnets, route tables, gateways, security groups (and what actually uses them, from network interfaces), EC2, Auto Scaling groups, load balancers (with tags and registered targets), ECS, EKS clusters and node groups, Lambda, RDS. Kubernetes (optional): workloads (Deployments, StatefulSets, DaemonSets, CronJobs), Services and Ingresses read from a cluster's API server. Run with `KUBECONFIG=path brioly generate` to read the current context of any cluster kubectl can reach (EKS, GKE, AKS, self-managed), or set `sources.kubernetes.eks: true` to read every EKS cluster the AWS scan finds without a kubeconfig. What is found is linked to the load balancers and databases of the AWS scan. Without it, what runs in a cluster is known from manifests in the scanned repositories, and a load balancer is linked to its Service through the tags Kubernetes puts on it (marked as inferred). Code: languages, dependencies, frameworks, Dockerfiles, GitHub Actions workflows, Terraform sources, Kubernetes workloads and Services.
2. **Normalize.** Everything becomes facts and relationships with stable IDs and content hashes ([schema](docs/design/fact-schema-v0.md)).
3. **Group.** Rules follow the relationships from an anchor (an ECS service, a Lambda function, a database cluster, a load balancer) to form components. A component's ID comes from its anchor, so it stays the same as members come and go.
4. **Render.** Same facts, same documents: on an unchanged environment the Markdown documents and the diagram come out byte-for-byte the same (`facts.json` records scan times, so it does change).

## Security

- brioly only calls `Describe*`/`List*` APIs (plus `sts:GetCallerIdentity`). It never reads S3 objects, database contents, Secrets Manager or Parameter Store values, or Terraform state.
- Be aware of what read access means: the ECS `DescribeTaskDefinition` and Lambda `ListFunctions` APIs return environment variable values in plain text. brioly stores them by **name only**; a value is used in memory to detect that a service talks to a known endpoint (for example an RDS cluster), then discarded.
- In a Kubernetes cluster brioly only lists workloads, Services and Ingresses. It never reads Secrets, ConfigMaps, pods or logs, and the [example role](docs/examples/kubernetes-readonly.yaml) does not allow it. The same caveat applies as for ECS: a workload's pod template contains environment variable values in plain text, and brioly keeps their names only.
- URL credentials (`https://user:pass@...`) are stripped from collected values.
- Collectors copy only the fields they declare; the raw API responses are never stored, logged or sent to a model. On top of that, values that look like secrets are masked with [gitleaks](https://github.com/gitleaks/gitleaks) rules before anything is written or sent.
- Use a read-only AWS profile (one from `~/.aws/config` or `~/.aws/credentials`, so an access key kept there works). [docs/examples/aws-readonly-policy.json](docs/examples/aws-readonly-policy.json) lists every action brioly calls; an action you leave out is reported as an incomplete part of the scan, not as missing resources.

## What leaves your machine

- `brioly generate`: nothing leaves your machine. brioly talks to AWS and to your clusters, reads your local repositories, and writes files. It never calls an AI model.
- `brioly sync`: the collected facts are sent to your brioly Cloud workspace, after masking, over HTTPS with a sync token you create there. The same facts as `facts.json`: resource names, configuration values, relationships, dependency names, file paths and environment variable **names**. Source code, environment variable values and what you wrote in `components.yaml` are never sent, and nothing is sent to a model. Each send replaces the previous one. `--dry-run` scans and sends nothing.
- `brioly generate` sends nothing to brioly or to anyone else.

## Your knowledge stays yours

Generated documents are never meant to be edited: they are rebuilt on every run. What only people know goes into `components.yaml`: display names, owners, which pieces belong together, and notes ("moved to Fargate in 2025 because..."). Notes appear in the documents next to the component, apart from generated text, and are given to the model as trusted context. brioly reads this file and never rewrites it.

## Changes that matter

Every attribute is either structural (a database became public, a runtime changed), a detail (a patch version, an instance size) or volatile (task counts, image tags). `brioly diff` compares two snapshots and rates each change with fixed rules: opening a security group to the internet is always high, a patch bump is always info, a deployment is nothing at all. Keep snapshots with `generate --history DIR` and run `brioly replay DIR` to see which attributes churn in your environment.

## Version support and exposure

`version-support.md` lists the versions you run on (EKS and Kubernetes, RDS and Aurora engines, Lambda runtimes, the base images of your Dockerfiles, a few frameworks) with the day their standard support ends, soonest first. The dates are a table inside the binary, taken from [endoflife.date](https://endoflife.date) and refreshed with `scripts/update-lifecycle.sh`; brioly fetches nothing while it runs, and a version that is not in the table is listed as not known.

`internet-exposure.md` lists what the internet can reach and the settings that widen or weaken that: security groups open to `0.0.0.0/0` (rated by which ports), databases with a public address or without encryption, public cluster endpoints. Every finding comes from a fixed rule that the document states, and it ends with what the review does not cover. It is a review of configuration, not a security audit.

## Keeping documents up to date

`brioly generate` writes documents once; run it from a scheduled CI job and commit the output to keep them current ([GitHub Actions example](docs/examples/github-actions.yml)). brioly Cloud (in development) adds what files in git cannot: a history of your infrastructure facts, summaries and alerts for the changes that matter, questions answered from that history, and a place for your team's own notes.

## Development

```sh
go test ./...
go build -o bin/brioly ./cmd/brioly
```

## License

[Apache License 2.0](LICENSE). The name "brioly" and its logos are not covered by the license.
