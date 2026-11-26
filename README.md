# brioly

brioly scans your AWS account, Kubernetes clusters, Cloudflare and code repositories and writes architecture and tech stack documents for you. The documents are made by fixed code from what was collected, with no AI model involved: every statement links to its source, and the same system always gives the same documents.

> Status: early development (M1). Interfaces and output formats will change.

## What you get

```
brioly-docs/
├── architecture.md      # network, entry points, compute, data stores, dependencies, internet exposure
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

1. **Collect.** Plain API calls and file parsing. AWS: VPC, subnets, route tables, gateways, security groups (and what actually uses them, from network interfaces), EC2, Auto Scaling groups, load balancers (with tags and registered targets), ECS, EKS clusters and node groups, Lambda, RDS. Kubernetes (optional): workloads (Deployments, StatefulSets, DaemonSets, CronJobs), Services and Ingresses read from a cluster's API server. Set `sources.k8s.kubeconfig` in brioly.yaml to a kubeconfig file to read its current context, for any cluster kubectl can reach (EKS, GKE, AKS, self-managed), or set `sources.k8s.eks: true` to read every EKS cluster the AWS scan finds without a kubeconfig. What is found is linked to the load balancers and databases of the AWS scan. Without it, what runs in a cluster is known from manifests in the scanned repositories, and a load balancer is linked to its Service through the tags Kubernetes puts on it (marked as inferred). Cloudflare (optional, `sources.cloudflare`): zones with their SSL mode, DNS records and whether each goes through Cloudflare's proxy, Workers (routes, custom domains, what they are bound to), Pages projects, Tunnels and their routes, load balancers and pools. A record, a tunnel route or a pool whose address is a load balancer, a database or an Ingress of the other scans is linked to it by host name; a link made from a name alone is marked as inferred. Code: languages, dependencies, frameworks, Dockerfiles, GitHub Actions workflows, Terraform sources, Kubernetes workloads and Services.
2. **Normalize.** Everything becomes facts and relationships with stable IDs and content hashes ([schema](docs/design/fact-schema-v0.md)).
3. **Group.** Rules follow the relationships from an anchor (an ECS service, a Lambda function, a database cluster, a load balancer) to form components. A component's ID comes from its anchor, so it stays the same as members come and go.
4. **Render.** Same facts, same documents: on an unchanged environment the Markdown documents and the diagram come out byte-for-byte the same (`facts.json` records scan times, so it does change).

## Security

- brioly only calls `Describe*`/`List*` APIs (plus `sts:GetCallerIdentity`). It never reads S3 objects, database contents, Secrets Manager or Parameter Store values, or Terraform state.
- Be aware of what read access means: the ECS `DescribeTaskDefinition` and Lambda `ListFunctions` APIs return environment variable values in plain text. brioly stores them by **name only**; a value is used in memory to detect that a service talks to a known endpoint (for example an RDS cluster), then discarded.
- In a Kubernetes cluster brioly only lists workloads, Services and Ingresses. It never reads Secrets, ConfigMaps, pods or logs, and the [example role](docs/examples/kubernetes-readonly.yaml) does not allow it. The same caveat applies as for ECS: a workload's pod template contains environment variable values in plain text, and brioly keeps their names only.
- From Cloudflare brioly only sends GET requests, with an API token you create ([permissions below](#cloudflare)). What that token can read and what brioly keeps are different: a Worker's settings and a Pages project return the values of plain-text variables, and brioly keeps the **names** of variables and secrets only (the values are never decoded from the answer). Of DNS records it keeps where A, AAAA, CNAME, MX and NS records point; the content of TXT and every other type, and record comments and tags, are not kept. Of a tunnel route and a Worker route it keeps the host name (and for a tunnel the origin's scheme, host and port), not paths or origin settings. Your Cloudflare account ID is part of the identifiers of what is collected. It never requests Worker code, the values of secrets, KV, R2 or D1 contents, tunnel tokens, WAF rules, Access policies, API tokens or certificates.
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

`version-support.md` lists the versions you run on (EKS and Kubernetes, RDS and Aurora engines, Lambda runtimes, the base images of your Dockerfiles, a few frameworks) with the day their standard support ends, soonest first. The dates are a table that brioly.io serves (built from [endoflife.date](https://endoflife.date) with `scripts/update-lifecycle.sh`), so that a new date reaches you without a new release. `brioly generate` reads it at the start of every run; if it cannot, it stops and says why. A version that is not in the table is listed as not known. Inside a network that cannot reach brioly.io, serve a copy of the table and set `BRIOLY_LIFECYCLE_URL` to its address.

`internet-exposure.md` lists what the internet can reach and the settings that widen or weaken that: security groups open to `0.0.0.0/0` (rated by which ports), databases with a public address or without encryption, public cluster endpoints. With Cloudflare it also lists every host name, whether it goes through Cloudflare's proxy or is DNS only, and what the scan could see of whether the origin can be reached without Cloudflare. A proxied record alone is never taken as proof that it cannot. Every finding comes from a fixed rule that the document states, and it ends with what the review does not cover. It is a review of configuration, not a security audit.

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
