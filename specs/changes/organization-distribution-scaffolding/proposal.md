---
reason: Organizations that ship their own command on the engine must rename the example in four places and change three engine pins by hand at every engine update, and a missed pin only shows up when the command refuses to start.
affected_ids: [REQ-039]
compatibility: Adds the requirement, its acceptance rules, and the `distribution init` and `distribution update-engine` commands in the public CLI. Existing commands, saved results, profile formats and the manifest schema are unchanged. The installed organization command does not offer the new commands.
verification: Offline tests generate a distribution and load it with the engine's organization validation, check that no example name remains, reject unsafe names and targets, show that nothing is overwritten and no network connection is made, and check that update-engine sets all four pins, reports drifted pins, and changes nothing after a missing, ambiguous or symlinked pin. No wheel was built from a generated repository, and no live assessment was run.
---

# Organization distribution scaffolding

Adds REQ-039. An organization creates the files of its own Analyzer distribution with `appsec-analyzer distribution init NAME [DIR]` and aligns the engine pins with `appsec-analyzer distribution update-engine [DIR]`. The commands work on local files only. The [packaging guide](../../../docs/organization-distributions.md) keeps the build, dependency download, checksum and release steps.

## Decisions

The user approved the requirement wording in the conversation that drafted it. These decisions were made there:

- A `build` command that would clone, build wheels, assemble the wheelhouse and write checksums was considered and left out. It would download dependencies and run build tools, which adds supply-chain exposure, and the gain is small for organizations that release rarely. It can be proposed later as its own requirement.
- The group is called `distribution`, because the guide already calls the result an organization distribution. `organization` and `organization-config` already name other commands.
- `update-engine` takes the target version from the installed engine and has no version argument, so the pins cannot be set to a version that is not installed.
- The generated files are the packaged example under the organization's name. Its profiles, context, abuse cases and requirements are sample content; `init` says so in the generated README and in its output.

## Risks raised

- **File writes:** both commands write files. `init` writes only into a new or empty real directory and refuses anything else. `update-engine` checks every pin first and writes only if all four are found exactly once, in regular files.
- **Network and supply chain:** none. Neither command downloads, builds, installs or publishes anything. The generated dependency lock is the example's lock for Python 3.10 on Linux; the guide's instruction to review and resolve a lock for the organization's platforms still applies.
- **Cost and data:** no model calls and no data leave the machine.
- **Preview engine:** two engine commits can share the version `0.1.0a0`, so `update-engine` cannot tell them apart. The guide's advice to record both commit IDs in the release remains the organization's task.
