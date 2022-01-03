# Using Witness To Find Artifacts With Vulnerable Log4j Dependencies

This example shows how Witness and Sigstore's Rekor can be used in tandem to discover artifacts that were built with
vulnerable dependencies. There are many tools out there that can scan your projects for dependencies with CVEs but
discovering existing artifacts in environments with many running applications may prove difficult.

## Attack Details

In late 2021 several vulnerabilities were found in Log4j that could potentially allow malicious actors to execute
arbitrary code on a targeted system. The details of how this attack was executed is irrelevant for this example, but if
you would like to read more check out the [Wikipedia Article](https://en.wikipedia.org/wiki/Log4Shell).

## How Witness Can Help With Remediation

Witness and Rekor can help discover artifacts built with vulnerable dependencies. Witness creates attestations about
everything that goes into a build, effectively generating an SBOM for your build. These attestations are structured in a
way that allows Rekor to index attestations by dependencies. Witness policy can also be written around the dependencies
in an artifact and prevent or stop an artifact from running in critical environments.

This demo will show how we can discover artifacts that are affected by vulnerable dependencies and allow us to take
action on them.

## Running The Demo

This demo requires a local rekor instance to be running. The easiest way to do this is to use the docker-compose file in
rekor's [repostority](https://github.com/sigstore/rekor). 

```
$ git clone https://github.com/sigstore/rekor
$ cd rekor
$ docker-compose up -d
```

You may have to edit the `rekor-server` service in the docker compose to increase the max attestation size by adding
`--max_attestation_size=1000000` to the command line arguments for rekor.

After the rekor server is running `build.sh` will build the two java projects, one with a log4j 1.2.17 that has the
known CVE and the other without.

You may then use the `find-affected-artifacts` script to search attestations in Rekor for attestations that report
vulnerable versions of log4j being used in an artfact:


```
$ ./find-affected-artifacts.sh
{
  "name": "target/my-app-1.0-SNAPSHOT.jar",
  "digest": {
    "sha256": "f265085f42faf9a1fc2527a9c2fb2c40f240a553efa66874fb84f4a07a8cbe62"
  }
}
```

This is telling us that the jar with sha256sum of `f265085f42faf9a1fc2527a9c2fb2c40f240a553efa66874fb84f4a07a8cbe62` has
a vulnerable version of log4j in it.

The `verify.sh` script will run `witness verify` on both jars using a policy that is setup to disallow artifacts that
report this version of log4j.

```
$ ./verify.sh

Verifying policy on nonvulnerable package...
2022/01/04 01:57:02 Using config file: ../witness.yaml

Verifying policy on vulnerable package...
2022/01/04 01:57:02 Using config file: ../witness.yaml
policy was denied due to:
vulnerable log4j detected
```
