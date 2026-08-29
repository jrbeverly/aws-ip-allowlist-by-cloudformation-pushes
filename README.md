# AWS IP Allowlist by CloudFormation Pushes

> [!WARNING]
> **AI-authored:** This change was autonomously planned and implemented by an AI software factory from a human-authored specification, with possible subsequent human review or modification.

Tests keeping a WAF IP set (or managed prefix list) in sync with an external CIDR feed by having a scheduled Lambda call `UpdateStack` on its own stack with `UsePreviousTemplate` and a new parameter value, so CloudFormation stays the only thing that mutates the resource.

```sh
make deploy
make sync
make destroy
```

## Notes

- pretty solid proof of concept; would not necessarily make this the standard model
- does prove out basic self-updating Lambda flow
- potentially useful for easier distribution/syncing of frequently changing network data
- strongest use case; third-party vendor IPs changing regularly
- also useful in large organizations; service IPs/ranges constantly in flux
- better fit where fixed IP sets, CIDRs, vendor ranges, service endpoints need dynamic propagation
- could fit into broader pipeline orchestration
- systems come online; relational maps created; downstream systems pull/update required network data
- organizational structure becomes more flow-oriented rather than rigid/static configuration
- possible M&A use case; acquired company/domains/ranges need to be incorporated across existing systems quickly
- could also become a maintained/customer-facing service
- provider maintains authoritative IP/network data
- customers get an easier mechanism for injecting/syncing that data into their own resources
- alternative model; centralized service that manages distribution into multiple target environments
