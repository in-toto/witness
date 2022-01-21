# Using Witness To Prevent SolarWinds Type Attacks

This example shows how Witness can be used to mitigate against an attack where a malicious source file may be swapped
or modified at build time. This attack vector was infamously used as part of the SolarWinds malicious update attack in
2020, as described [here](https://www.bankinfosecurity.com/solarwinds-describes-attackers-malicious-code-injection-a-15746)

## Attack Details

In this scenario an attacker has compromised the builder and is observing processes, waiting for a build process to kick
off. Once the attacker observes a build of the targeted software the attacker injects their malicious code during the
compile process.

While on SolarWinds is built on Windows the same style of attack can be used on Linux hosts. In this example we will
mimic this attack vector with a tool we've developed named [SolarSploit](https://github.com/testifysec/solarsploit/).
This tool watches for the go compiler to start, attaches to the compiler as a debugger, and modifies the source being
compiled to inject a malicious function into the resulting binary.

## How Witness Can Mitigate This

In its default configuration Witness will record file hashes of all source files before and after each step of a build
process. If an attacker modified a source file between build stages this would be picked up and the resulting artifact
would fail Witness's verification process.

However, Witness's true strength against this vector of attack comes when tracing is enabled. Witness records every
single file and its hash that a traced process opens during its execution. This allows us to detect if any one has
changed a source file during the process's execution.

Additionally, Linux processes may only be traced by a singular tracer. If Witness is not the tracer Witness will fail
and not produce any attestations about the build process -- failing the verification process. If Witness is the tracer
the SolarSploit tool will fail to attach and inject the malicious source.

## Running The Demo

To run the demo simply run `./demo.sh` in this directory. Requires go, make, and docker to run.
