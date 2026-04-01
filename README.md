# jsinte

`jsinte` is a lightweight JavaScript reconnaissance CLI for bug bounty hunters and security researchers.

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


``Functional examples
Analyze a single live page
./jsintel -u https://target.example -type target

``Analyze a file of live hosts
./jsintel -l live.txt -type target -c 50 > findings.jsonl

``Analyze a file of JavaScript assets directly
./jsintel -l js_urls.txt -type js > js-findings.jsonl

``Use stdin in a standard pipeline
cat live.txt | ./jsintel -type target

``Feed it from subdomain and liveness tools
subfinder -d target.example -silent \
  | httpx -silent \
  | ./jsintel -type target -c 50 > findings.jsonl

``Feed it from a crawler that already found JavaScript files
katana -u https://target.example -jc -silent \
  | grep -E '\.m?js(\?|$)' \
  | sort -u \
  | ./jsintel -type js > js-findings.jsonl

``Filter only the most interesting findings
cat findings.jsonl | jq -cr 'select(.finding=="exposed_sourcemap" or .finding=="hidden_endpoint" or .finding=="secret_candidate")'

``Reduce info-level noise
./jsintel -l live.txt -type target -no-info

