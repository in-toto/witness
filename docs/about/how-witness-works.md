# How Witness Works

### Signing
Witness is able to observe your software development life-cycle (SDLC) by wrapping around commands executed within them. By passing any command to Witness as an argument, the tool is able to understand what was executed but also on what infrastructure, by what user or service account and more. The information that Witness gathers while the command is running is down to which [Attestors](docs/attestor.md) are used. Attestors are implementations of an interface that find and assert facts about the system Witness is running on (e.g., [AWS Attestor](docs/attestors/aws-iid.md)). Finally, Witness can compile this information into an [in-toto attestation](https://github.com/in-toto/attestation), place it in a [DSSE Envelope](https://github.com/secure-systems-lab/dsse) and sign that envelope with the key that was supplied by the user. 

### Storing
For storage, the Witness project can upload signed attestations to an [Archivista](https://github.com/in-toto/archivista) server, a graph and storage service for in-toto attestations. This enables the discovery and retrieval of attestations for verification of software artifacts.

### Verifying
Witness allows users to verify the attestations that they generate by providing the `witness verify` command. To achieve this, Witness uses a [policy file](./docs/policy.md) defined by the user to check for presence of the expected attestations and that they were signed by the appropriate functionaries (Public keys or roots of trust that are trusted to sign certain types of attestation). To verify the attestation body itself, Witness supports defining [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies inside the policy file. This allows users to ensure the facts asserted by the Attestors are reported expected.

