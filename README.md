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

```bash
go install github.com/lipe-poliveira/jsinte@latest
