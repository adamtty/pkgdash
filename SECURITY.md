# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub:
[**Report a vulnerability**](https://github.com/adamtty/pkgdash/security/advisories/new).
Don't open a public issue for them.

Include what you found, how to reproduce it, and what an attacker could do with it. You'll get a
reply within a week. Once it's fixed, you'll be credited in the advisory unless you'd rather not be.

## Supported versions

Only the latest commit on `main` is supported; there are no release branches.

## Scope

In scope: the service (`server.py`), the dashboard (`index.html`), the menu bar app, `install.sh` and
`demo.py`. Especially interesting: anything that lets a web page, a package, an advisory, a Docker image
or a project's files run code or trigger actions through pkgdash, or that lets another local program
use the menu bar app's permission to read your projects folder. See [Security](README.md#security)
for the protections already in place.

Out of scope: vulnerabilities in the package managers and registries pkgdash drives (report those
upstream), and attacks that need an attacker who can already read your projects folder.
