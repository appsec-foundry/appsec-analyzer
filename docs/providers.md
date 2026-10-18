# LiteLLM and Amazon Bedrock

`scan` and `assess` now check provider setup before cloning. Use `appsec-analyzer preflight --repo /path/to/project --profile "lite claude" --json` for a separate check with no generation. LiteLLM checks its authenticated model list; Bedrock checks credential format and TLS only, leaving server authentication and model access unverified. `preflight --test-model --budget USD` explicitly authorizes one separate primary-model generation test with a synthetic prompt. See [preflight checks and limitations](security-assessment.md#preflight-checks).

Full assessments can use a LiteLLM gateway or the Amazon Bedrock Converse API. Both adapters have offline transport and controller tests; neither has passed live assessment qualification. The requirements audit and focused analyst keep their existing provider options.

## Configure the connection

Create `~/.config/appsec-analyzer/providers.yaml` from the [connection example](../examples/provider-connections.yaml). If `XDG_CONFIG_HOME` is set, use `$XDG_CONFIG_HOME/appsec-analyzer/providers.yaml`. This operator-owned file is separate from scan and model profiles. It must be outside every analyzed repository, owned by the current user or root, and not writable by group or others (for example mode `0600` or `0644`). It cannot be a symlink or hard link. The [connection schema](../schemas/provider-connections.schema.yaml) rejects unknown fields, credentials and arbitrary commands. Do not put credential values in this file.

The example contains illustrative prices, output limits and deployment names. Replace them with values verified for your actual models, region and gateway. Each model entry records its maximum output, conservative USD rates per million input/output tokens, and the model sent upstream. The connection records a dated price revision and a route revision. Change the revisions when their underlying configuration changes; changed connection settings require a new run. No model is discovered automatically over the network.

`model_family: non-opus` declares that a route cannot use Opus. Declare `opus` for Opus routes. When an organization disables Opus, a missing declaration or an Opus route blocks the run. A gateway alias does not bypass that restriction; the operator must keep its declared family and pinned deployment accurate.

## Use LiteLLM

Configure an HTTPS gateway endpoint ending in `/v1/responses` on port 443 and provide `LITELLM_API_KEY` through your environment or secret manager. Use a virtual key scoped to the intended models and budget. The configured gateway model must support the Responses API, strict JSON-schema output, `store: false`, and token usage. See [LiteLLM Responses](https://docs.litellm.ai/docs/response_api) and [virtual keys](https://docs.litellm.ai/docs/proxy/virtual_keys).

Use the `lite` prefix followed by the configured model name:

```sh
appsec-analyzer profiles validate "lite claude"
appsec-analyzer scan --repo /path/to/project --model "lite claude" --budget 20
appsec-analyzer assess --repo /path/to/project --profile "lite claude" --budget 20 --non-interactive
```

`--profile lite --model "lite claude"` is equivalent for a new run. The prefix selects LiteLLM; `claude` selects the `lite.models.claude` entry in the connection file, whose `model` value is sent to the gateway. It does not invoke Claude CLI. An explicit model option applies to all roles; use a model profile for different gateway models per role. A prefix conflicting with an explicitly selected provider is rejected.

Set `deployment_id` to the exact deployment identifier returned by `x-litellm-model-id`. Analyzer requires that header to match and requires a finite nonnegative USD charge in `x-litellm-response-cost`; it does not substitute OpenAI prices or treat missing charges as zero. An unexpected fallback deployment or missing accounting cannot produce an accepted analysis result. Analyzer sends `num_retries: 0`, the higher-priority `x-litellm-num-retries: 0` header, and `disable_fallbacks: true` so its controller owns retries and model selection. Verify your gateway version honors these options on Responses requests and configure its virtual-key budget consistently with the authorized limit. Analyzer's limits apply to its own requests, not hidden upstream retries or shared account spending.

DNS must resolve only to public addresses. For a gateway on a private network, explicitly set `pinned_ip` to its reviewed RFC 1918 or IPv6 ULA address. TLS still verifies the configured hostname. Loopback, link-local, metadata and other special addresses are rejected. Redirects are not followed. No repository file or model answer can change the destination.

LiteLLM reasoning settings vary by upstream model. To enable `reasoning_effort` in a model profile, list only the supported values in that connection model's `reasoning_efforts` array. By default no reasoning parameter or output-token cap is sent. The configured model maximum is still reserved before each request.

## Use Amazon Bedrock

Set the AWS Region and exact foundation-model or inference-profile ID in the `bedrock` connection. This adapter uses regional `bedrock-runtime.<region>.amazonaws.com` endpoints in the standard AWS partition. It accepts model/profile IDs, not ARNs, prompt routers or custom endpoints. Choose a model and region that support Converse and JSON-schema structured output. See [Converse](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html) and [structured output](https://docs.aws.amazon.com/bedrock/latest/userguide/structured-output.html).

Provide an externally generated Bedrock API key through `AWS_BEARER_TOKEN_BEDROCK`. Its IAM principal needs permission to invoke the selected model. This adapter does not use AWS credential files, instance metadata, SigV4 credentials, or AWS endpoint overrides; a normal AWS access-key pair alone is insufficient. Follow [Bedrock API-key setup](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-use.html).

```sh
appsec-analyzer profiles validate "bedrock claude"
appsec-analyzer scan --repo /path/to/project --profile bedrock --budget 20
appsec-analyzer assess --repo /path/to/project --model "bedrock claude" --budget 20 --non-interactive
```

`bedrock claude` selects the `bedrock.models.claude` connection entry. Converse receives the existing role instructions, bounded excerpts and output contract, with no tools. The request sets `maxTokens` to the configured model maximum or an explicit lower role limit. Responses with tool use, truncation, missing token usage or unexpected cache accounting are rejected. Cost uses the configured regional input/output rates. Reasoning-effort mapping, prompt caching, SigV4 and nonstandard AWS partitions are not supported by this adapter.

## Role profiles and saved work

Create a model profile with `base: lite` or `base: bedrock`. Each role can select a configured model with its provider prefix, for example `roles.recon_scanner.model: lite small`. Every role in one model profile uses the same adapter. Connect the model profile to a scan profile as described in [scan and model profiles](profiles.md).

`profiles show` and `profiles validate` read configuration without credentials, repository retrieval or model calls. `capabilities` identifies both adapters as unqualified. Before model calls, the startup header identifies the destination; excerpts, supplied context and intermediate answers leave the machine. Provider and gateway settings govern logging, retention, and any cross-region routing; Analyzer does not establish those guarantees. Credentials are read only for transmission and never included in the profile snapshot. Connection details, deployment identity, prices and model options participate in resume compatibility.
