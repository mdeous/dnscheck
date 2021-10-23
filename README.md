# dnscheck

## Introduction
`dnscheck` is a tool that reads a list of domains from a file and checks them for the following issues:

- CNAMEs pointing to an unclaimed resource (e.g. S3 bucket, GitHub pages, Azure CloudApp, etc.)
- CNAMEs pointing to an unregistered domain
- Zone delegations poiting to an unclaimed zone

Detection of CNAMEs pointing to unclaimed resources is based on the information available 
in [can-i-takeover-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).

## Yet another DNS takeover tool?
Yes! Because:
1. I wanted to understand these vulnerabilities better, and what's better for that than writing a tool to detect them?
2. I couldn't find a tool that I liked enough and that would check both dangling CNAMEs and zone takeovers.
(which doesn't mean such a tool doesn't exist!)

If you like this tool, use it  (I'll be happy if you do), if you want to improve it, please open
an issue, or even better, submit a PR, and if you don't like it, a list of [alternatives](#alternatives) is provided below.

## Usage
### Installation
#### From sources
Clone the repository and build the application:
```shell
git clone https://github.com/mdeous/dnscheck
cd dnscheck
make
```
You can then use the `dnscheck` binary that has been generated in the repository folder.

or

Install the application directly with Go:
```shell
go install https://github.com/mdeous/dnscheck
```
You should then have `dnscheck` available in your `PATH` (assuming you have a properly configured Go environment).

#### Pre-built binaries
Pre-built binaries for the most common architectures can be downloaded from the 
project's [latest release page](https://github.com/mdeous/dnscheck/releases/latest).
After downloading it, simply make the file executable and run it as described below.

### Checking domains for vulnerabilities
The only mandatory argument is the `-d`/`-domains` one, which should be the path to a file
containing the list of domains that should be checked. For the other optional options, please
refer to the help below.

The `-S` option can greatly improve detection, as it attempts to connect to the CNAMEs targets
using HTTPS instead of plain HTTP.

By default, the results are only displayed on stdout, if you want to save them to a file, you can
use the `-o` option.

Help:
```
❯ dnscheck check -h
Check for vulnerable domains

Usage:
  dnscheck check [flags]

Flags:
  -d, --domains string      file containing domains to check (default "domains.txt")
  -h, --help                help for check
  -n, --nameserver string   server and port to use for name resolution (default "8.8.8.8:53")
  -o, --output string       file to write findings to
  -S, --ssl                 use HTTPS when connecting to targets
  -t, --timeout uint        timeout for HTTP requests (default 10)
  -w, --workers int         amount of concurrent workers (default 10)

Global Flags:
  -f, --fingerprints string   custom service fingerprints file
  -v, --verbose               increase application verbosity
```

TODO: add an example of output

### Monitoring domains
TODO  (not implemented yet)

### Using custom service fingerprints
A custom fingerprints JSON file can be passed to `dnscheck` by using the `-f` option.

The fingerprints file must have the following format:
```json
{
  "services": [
    {
      "name": "ngrok",
      "cnames": [
        ".ngrok.io"
      ],
      "patterns": [
        " not found"
      ]
    }
  ]
}
```

Each vulnerable service fingerprint has the following fields:
- `name`: the name of the vulnerable service
- `cnames`: a list of (sub)domains known to be possibly vulnerable for the service (if any)
- `patterns`: a list of HTTP response strings which indicate an unclaimed resource (if any)

If `patterns` is an empty list, detection will be based on HTTP responses only, and if `cnames`
is an empty list, detection will be based on CNAME records values only. At least one of `cnames`
and `patterns` should be a non-empty list. If both are non-empty lists, both the CNAME _and_
the HTTP response should match the provided values to indicate a vulnerable domain.

In the example above, a vulnerable record needs to have a CNAME pointing to `*.ngrok.io`, and
when an HTTP(S) request is performed on the domain, the response should contain ` not found`.

## Alternatives
- [can-i-takeover-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- [subjack](https://github.com/haccer/subjack)
- [tko-sub](https://github.com/anshumanbh/tko-subs)
- [domain-protect](https://github.com/ovotech/domain-protect)
- [takeover](https://github.com/m4ll0k/takeover)
- and [many more](https://www.google.com/search?q=%28dns+OR+domain%29+takeover+site%3Agithub.com)...

## License
This project is licensed under the terms of the MIT License.
