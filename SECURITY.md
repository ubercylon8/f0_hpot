# Security policy

## Reporting a vulnerability

Please report security vulnerabilities through GitHub's private vulnerability
reporting, not through a public issue:

<https://github.com/ubercylon8/f0_hpot/security/advisories/new>

This opens a private advisory visible only to you and the maintainers, so
details don't sit in a public tracker before a fix is available.

What to expect:

- An acknowledgement within a few days of the report.
- We'll work with you to understand impact and reproduce the issue, and will
  keep you updated as a fix is developed.
- Credit in the published advisory, unless you ask to remain anonymous.

## Responsible use

f0_hpot runs services designed to be attacked. They capture credentials,
NTLM challenge/response material and command input from whoever interacts
with them.

- Deploy only on infrastructure you own or are explicitly authorised to test.
- Captured credentials are supplied by the attacker and may belong to third
  parties. Treat incident data as sensitive; it is stored unencrypted in
  SQLite by default.
- Honeypot services deliberately present as vulnerable. Do not place them on
  a host you also use for anything else.
- Intercepting credentials has different legal footing in different
  jurisdictions. That is your call to make, not this project's.
