# jsintel

`jsintel` is a lightweight JavaScript reconnaissance CLI for bug bounty hunters and security researchers.

It helps identify useful front-end signals such as:

- exposed sourcemaps
- hidden endpoints
- framework fingerprints
- auth-related hints
- secret candidates

The tool is designed for **authorized security testing** and fits well into Unix-style recon pipelines.

## Features

- Analyze a single target with `-u`
- Read targets from a file with `-l`
- Read from `stdin`
- Support input types:
  - `auto`
  - `target`
  - `js`
- Detect common frameworks:
  - Next.js
  - Nuxt
  - React
  - Vue
  - Angular
  - Vite
  - Webpack
- Discover sourcemap references
- Fetch exposed sourcemaps
- Extract source paths from sourcemaps
- Extract endpoints from JavaScript
- Detect auth hints
- Flag secret candidates with redacted output
- Emit JSON Lines to `stdout`

## Installation

### Install with Go

``bash
go install github.com/lipe-poliveira/jsinte@latest

Make sure your Go binary path is in your PATH:
export PATH="$PATH:$HOME/go/bin

Build from source
git clone https://github.com/lipe-poliveira/jsinte.git
cd jsinte
go build -o jsintel .

Usage

jsintel supports three input styles:

single target with -u
file input with -l
standard input with stdin

It also supports three input modes:

auto
target
js

Basic syntax
./jsintel -u <target>
./jsintel -l <file>
cat <file> | ./jsintel

Input Types
-type auto

Auto mode tries to infer the input type:

entries that look like .js or .mjs URLs are treated as JavaScript assets
other entries are treated as target pages or hosts

Example:
./jsintel -l input.txt -type auto

-type target

Use this when the input contains pages, web roots, or hosts.

Example:
./jsintel -l live.txt -type target

In this mode, jsintel will:

fetch the target page
extract linked JavaScript assets
fetch the discovered assets
analyze them
-type js

Use this when the input already contains JavaScript asset URLs.

Example:
./jsintel -l js_urls.txt -type js

In this mode, jsintel skips HTML discovery and analyzes the JS assets directly.

Common Flags
-u           single target
-l           input file
-type        auto | target | js
-c           worker concurrency
-timeout     HTTP timeout
-max-body    max response body size
-k           insecure TLS
-no-info     omit info-level findings

Examples
Analyze a single target page
./jsintel -u https://target.example -type target

Analyze a file of live targets
./jsintel -l live.txt -type target -c 50

Analyze a file of JavaScript assets
./jsintel -l js_urls.txt -type js

Read targets from stdin
cat live.txt | ./jsintel -type target
Read JS assets from stdin
cat js_urls.txt | ./jsintel -type js
Save output to JSONL
./jsintel -l live.txt -type target > findings.jsonl
Remove info-level noise
./jsintel -l live.txt -type target -no-info
Pipeline Examples
Subdomain enumeration + liveness + JS analysis
subfinder -d target.example -silent \
  | httpx -silent \
  | ./jsintel -type target -c 50 > findings.jsonl
Crawl JavaScript URLs first, then analyze them
katana -u https://target.example -jc -silent \
  | grep -E '\.m?js(\?|$)' \
  | sort -u \
  | ./jsintel -type js > js-findings.jsonl
Filter only interesting findings with jq
cat findings.jsonl \
  | jq -cr 'select(.finding=="exposed_sourcemap" or .finding=="hidden_endpoint" or .finding=="secret_candidate")'
Filter only sourcemap-related findings
cat findings.jsonl \
  | jq -cr 'select(.finding=="sourcemap_reference" or .finding=="exposed_sourcemap")'
Filter only endpoint-related findings
cat findings.jsonl \
  | jq -cr 'select(.finding=="hidden_endpoint" or .finding=="api_route_hint")'
Filter only secret candidates
cat findings.jsonl \
  | jq -cr 'select(.finding=="secret_candidate")'
Output Format

Output is JSON Lines, one finding per line.

Example:

{"target":"https://target.example","asset":"https://target.example/_next/static/chunks/app.js","finding":"framework_detected","severity":"info","confidence":"high","framework":"nextjs","evidence":["framework_fingerprint"]}
{"target":"https://target.example","asset":"https://target.example/static/app.js","finding":"sourcemap_reference","severity":"medium","confidence":"high","sourcemap":"https://target.example/static/app.js.map","evidence":["sourceMappingURL"]}
{"target":"https://target.example","asset":"https://target.example/static/app.js","finding":"hidden_endpoint","severity":"medium","confidence":"medium","endpoint":"/internal/admin/export","evidence":["path_in_js","keyword:/internal","keyword:/admin"]}
Finding Types

Typical finding values include:

framework_detected
auth_hint
sourcemap_reference
exposed_sourcemap
hidden_endpoint
api_route_hint
secret_candidate
no_js_assets_found
fetch_error
asset_fetch_error
Secret Handling

jsintel redacts candidate secrets in output. It does not dump raw token values to stdout by default.

Examples of candidate secret patterns:

AWS access key IDs
Google API keys
JWT-like strings
Bearer-like strings
private key blocks
generic secret-like config entries
Firebase-related config patterns

These findings should be triaged carefully. A pattern match alone is not proof of impact.

Recommended Workflow

Use jsintel as part of a Unix-style chain:

enumerate targets
confirm liveness
collect pages or assets
analyze JavaScript
triage the results
validate findings only inside authorized scope

Example flow:

subfinder -d target.example -silent \
  | httpx -silent \
  | ./jsintel -type target \
  | jq -cr 'select(.finding=="exposed_sourcemap" or .finding=="hidden_endpoint" or .finding=="secret_candidate")'
Notes
jsintel does not enumerate subdomains
jsintel does not deeply crawl applications
jsintel does not validate exploitability automatically
jsintel is intended for triage and recon, not exploitation
