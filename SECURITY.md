# Security policy

## Reporting a vulnerability

Please do not publish vulnerabilities that could expose local files, local network services, or measurement controls. Open a private GitHub security advisory for this repository, or contact the repository owner through the listed project channel.

## Security design

- The UI binds only to loopback addresses.
- Every browser session receives a random request token for state-changing API calls.
- Imported HTTPS lists reject private, loopback, link-local and reserved destinations, cap response size, and revalidate redirects.
- The application does not generate arbitrary DNS/hosts/route overrides.
