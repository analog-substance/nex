# Nex

Nex is a tool that allows you to split/merge nmap scans and view/query scan data. Definitely a work in progress but is still useful.

## Installation

Nex requires go 1.19+
```
go install github.com/analog-substance/nex@latest
```

## Usage
```
Nmap explorer

Usage:
  nex [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  merge       Merge Nmap XML files into one
  split       Split nmap scans into separate files for each host scanned.
  view        View Nmap XML scans in various forms

Flags:
  -h, --help   help for nex

Use "nex [command] --help" for more information about a command.

```