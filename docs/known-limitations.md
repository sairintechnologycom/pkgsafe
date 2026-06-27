# Known Limitations

- Lifecycle behavior analysis is heuristic and best-effort. It redirects home,
  temp, and XDG paths and drops secret-like environment variables, but it is not
  a container, namespace, or VM sandbox.
- npm has the deepest artifact and lifecycle analysis coverage. PyPI, Go, and
  Cargo support is useful but not equivalent across every package format.
- Offline scans require advisory and registry metadata to be synced or cached
  first. Missing advisory data fails closed rather than silently allowing a
  package.
- The local REST API is designed for loopback developer tooling and should not
  be exposed as a public service.
- Generated release artifacts must be produced by the release pipeline or
  `make package` before packaging readiness can pass.
