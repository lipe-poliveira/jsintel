# jsintel

`jsintel` is a fast, pipeline-friendly CLI for JavaScript reconnaissance in authorized security testing, bug bounty, and defensive review workflows.

It helps researchers move from *"I found some JS files"* to *"I found sourcemaps, hidden endpoints, framework fingerprints, auth hints, and secret candidates worth triaging."*

## Features

- Analyze either:
  - target pages and extract linked JavaScript assets
  - direct `.js` / `.mjs` URLs
- Support multiple input styles:
  - `-u` for a single target
  - `-l` for a file list
  - `stdin` for Unix pipelines
- Auto-detect input type or force it with `-type target|js|auto`
- Detect common framework fingerprints:
  - Next.js
  - Nuxt
  - React
  - Vue
  - Angular
  - Vite
  - Webpack
- Discover sourcemap references
- Fetch exposed sourcemaps and extract source paths
- Extract candidate endpoints from:
  - quoted paths
  - quoted URLs
  - `fetch(...)`
  - `axios.<method>(...)`
  - method/path patterns such as `GET /api/...`
- Surface auth-related hints from JavaScript
- Detect candidate secrets and redact output by default
- Emit JSON Lines to `stdout`

## Why use it

Modern bug bounty programs often expose valuable intelligence in front-end bundles:

- sourcemaps left in production
- internal or undocumented endpoints
- admin or debug routes
- auth flow hints
- config leaks
- token-like strings that deserve review

`jsintel` is designed to be one piece of a larger recon pipeline, not an all-in-one crawler or active validator.

## Scope and Intended Use

Use this tool only in environments where you are authorized to test.

`jsintel` is meant for:

- bug bounty programs
- internal security review
- red team / application security workflows with permission
- passive and low-risk triage of JavaScript assets

It is **not** a token replay tool, bypass framework, or active exploit engine.

## Installation

### Build from source

```bash
go build -o jsintel .
