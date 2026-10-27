---
reason: The user finds `[y/N]` needless for `appsec-analyzer update`, a command they started themselves, and asked for Enter to confirm.
affected_ids: [REQ-043]
compatibility: The command `appsec-analyzer update` asks `[Y/n]` and installs on Enter, `y`, or `yes`. The offer after a rejected saved assessment keeps `[y/N]` and still needs an explicit yes. The requirement sentence changes from "without an explicit yes" to "without your confirmation". No other command, exit code, or saved artifact changes.
verification: tests/test_public_update_cli.py covers the upgrade after Enter, `y`, and `YES` with the prompt showing `[Y/n]`, and no installation after `n`, `no`, another answer, or end of input. tests/test_public_review_cli.py keeps its case that Enter installs nothing for the offer. The upgrade command is replaced by a stub in every test. No test runs a real update.
---

# Enter confirms the update command

The user asked for Y as the default of `appsec-analyzer update`, chose that this applies only to that command and not to the offer after a rejected result, chose to change the requirement sentence and keep the Enter rule in the acceptance contract, and asked for the change directly on `main`.

Risks raised before the decision:

- Enter is not an explicit yes. A stray Enter now installs code from the network. The source is still shown first, and the user started the command.
- For an installation from a checkout, the update also installs uncommitted changes of that checkout.
- The offer after a rejected result is not requested by the user, so it keeps the stricter `[y/N]`.
- End of input and non-interactive runs still install nothing, and there is still no option that skips the question.

Simpler variant that was not chosen: keep `[y/N]` and have the user type `y`.
