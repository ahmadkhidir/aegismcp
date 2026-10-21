# Contracts

One entry per interface. `Frozen` means both sides agree; `Implemented` means it shipped and
conforms. A change after `Frozen` is a `change-request` issue and a PR that updates both sides.

## Entry template

```text
### C-###: <METHOD> <path>
Status: Frozen | Implemented | Frozen (revision N)
Auth: <who may call it, and how>
Request: <field: type, ...>
Response <code>: <field: type, ...>
Errors: <code (meaning), ...>
```
