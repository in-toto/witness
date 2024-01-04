# Signing Attestations with Sigstore Keyless

><span style={{fontSize: '0.9em'}}>💡 Tip: If this is your first time using Witness, you might benefit from trying the [Getting Started](./getting-started.md) tutorial first! You might 
also benefit from trying the [Witness Policy](./artifact-policy.md) tutorial, as it gives key insight into how to create more simple policies.</span>

## Intro
This quick tutorial will walk you through a simple example of how Witness can be used. To complete it
successfully, you will need the following:

- [curl](https://curl.se/)
- [tar](https://www.gnu.org/software/tar/)
- [jq](https://jqlang.github.io/jq/)
- [openssl](https://www.openssl.org/)
- [base64](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html) (which is part of GNU coreutils)

You will also of course need to have witness installed, which can be achieved by following the [Quick Start](../README.md#quick-start).

### Get Rid of the Old Stuff
If you tried any of our other tutorials, you might have some files lying around in the your working directory that will interfere with this tutorial. Be sure to get rid of them, particularly `test.txt`, as Witness will not record file hashes for products that exist in the filesystem before its invocation.

Alternatively, you can run this tutorial in a fresh directory, just make sure to `git init` first.

### Make sure to `git init`
Witness expects that the current working directory is a git repository. If you are not in a git repository already, you can create a new one by running:
```
git init
```

You should now be able to run `git status` successfully.

## Let's Go!

### Run a build step and record the attestation
First, we want to run simple example step, wrapped with Witness. This will create attestations that will later help us verify that it was run safely: 
```
witness run -s test -o test.json --signer-fulcio-url https://fulcio.sigstore.dev --signer-fulcio-oidc-client-id sigstore --signer-fulcio-oidc-issuer https://oauth2.sigstore.dev/auth --timestamp-servers https://freetsa.org/tsr -- echo "hello" > test.txt
```

Wait! Don't run it yet! Make sure you know what's going on first.

### What's Going on Here?
Well, let's break down the flags called in this run command.

#### The Familiar Flags
- `-s test` - This is the name of the step we are running.
- `-o test.json` - This is the name of the file we want to output our attestation to.

#### The New Stuff

If you jumped the gun and actually ran the above command, you might have been greeted by a login screen in your web browser.
This is because we are using [Sigstore Keyless Signing](https://sigstore.dev/) to sign the attestations, rather than the static keys used in other
tutorials.

Sigstore is a service that provides public services for signing artifacts and attestations by leveraging
[OpenID Connect](https://openid.net/connect/) and a special Certificate Authority (CA) that they call [Fulcio](https://docs.sigstore.dev/certificate_authority/overview/). This
makes the signing process both more convenient for you, as you don't need to manage your own keys, and more secure, as you don't need to worry about those keys being compromised. 

So breaking down the rest of the flags:
- `--signer-fulcio-url https://fulcio.sigstore.dev` - This is the URL of the Fulcio service that we will use to sign our attestation.
- `--signer-fulcio-oidc-client-id sigstore` - This is the client ID that we will use to authenticate with Fulcio.
- `--signer-fulcio-oidc-issuer https://oauth2.sigstore.dev/auth` - This is the OIDC issuer that we will use to authenticate with Fulcio.
- `--timestamp-servers https://freetsa.org/tsr` - This is the timestamp server that we will use to timestamp our attestations.

Neat right? If you're interested, we recommend learning more about [how Sigstore works](https://sigstore.dev/how-it-works).

### Run the Magic ✨

Now you should be safe to run the command from the [first step](#run-a-build-step-and-record-the-attestation). Following the steps in your browser
should result in a message like "Sigstore Authentication Successful!". If you are using a terminal that doesn't support opening a browser, you can
copy the link that is printed out and paste it into your browser manually.

Afterwards, you should see the `witness run` command finished in your terminal with a silent `0` exit code.


### View the attestation data in the signed DSSE Envelope

Next, you might want to view the attestation that you generated and saved to `test.json`:

```
cat test.json | jq -r .payload | base64 -d | jq
```

But this all means nothing if we can't trust it.

### Download the Fulcio Root CA
Sigstore Keyless Signing uses X.509 certificates to perform the signing of attestations. As such, we need to trust the Fulcio Certificate Authority (CA),
which can be done by downloading the Fulcio Root CA Trust Bundle from the Fulcio API:

```
curl -s https://fulcio.sigstore.dev/api/v2/trustBundle > fulcio.pem 
```

If you `cat fulcio.pem`, you should see some JSON with some certificates inside. This is the Fulcio Root CA Trust Bundle, which includes the Fulcio Root CA certificate,
as well as the Fulcio Intermediate CA certificate. We will need both of these.

You will also need the root certificate for the FreeTSA Timestamping Authority:

```
curl -s https://freetsa.org/files/cacert.pem > freetsa.pem
```

### Create a Policy File
Here is an example policy template:

```
cat <<EOF >> policy-template.json
{
  "expires": "2030-12-17T23:57:40-05:00",
  "steps": {
    "test": {
      "name": "test",
      "attestations": [
        {
          "type": "https://witness.dev/attestations/product/v0.1"
        }
      ],
      "functionaries": [
        {
          "type": "root",
          "certConstraint": {
            "commonname": "*",
            "dnsnames": [
              "*"
            ],
            "emails": [
              "{{EMAIL}}"
            ],
            "organizations": [
              "*"
            ],
            "uris": [
              "*"
            ],
            "roots": [
              "{{FULCIO_KEYID}}"
            ]
          }
        }
      ]
    }
  },
  "roots": {
    "{{FULCIO_KEYID}}": {
      "certificate": "{{FULCIO_ROOT}}",
      "intermediates": [
        "{{FULCIO_INT}}"
      ]
    }
  },
  "timestampauthorities": {
    "freetsa": {
      "certificate": "{{FREETSA_ROOT}}"
    }
  }
}
EOF
```
You can save this to a file locally by copying the above code, pasting it into your terminal and pressing enter. This will create a file named `policy-template.json` in your current working directory.

#### Things to Note
There are a couple of fields to note in this template policy file:

In the template we have defined a single functionary for the `test` step. This functionary is of type `root`, which means that it will be verified against an X.509 Root CA (Fulcio):
```json
  "functionaries": [
    {
      "type": "root",
  ...
```
There is also a `certConstraint` field within the `type: root` functionary, which is used to define constraints on the certificate that is used to sign the attestation. In this case, we are requiring that the certificate be signed by the Fulcio Root CA (by referencing the KEYID) and that the certificate contains the email address
of the user that signed the attestation:
```json
  "certConstraint": {
    "commonname": "*",
    "dnsnames": ["*"],
    "emails": ["{{EMAIL}}"],
    "organizations": ["*"],
    "uris": ["*"],
    "roots": [
      "{{FULCIO_KEYID}}"
    ]
  }
  ...
```

Next, there is a `roots` field, which is where the details of the X.509 Root CA defined above will be stored. The Key ID will be the same as above (the sha256sum of the root certificate), and we are supplying the root and intermediate certificate of the CA that we expect has signed the certificate that was used to sign the artifact:

```json
  "roots": {
    "{{FULCIO_KEYID}}": {
      "certificate": "{{FULCIO_ROOT}}",
      "intermediates": [
        "{{FULCIO_INT}
      ]
    }
  },
```

Finally, there is a `timestampauthorities` field, which is where the details of the timestamp authority will be stored. The Key ID will again be the sha256sum of the root certificate, and we are supplying the certificate of the timestamp authority ([freetsa](https://freetsa.org/index_en.php)) that we expect was used to timestamp the artifact in base64 encoded form:
```json
  "timestampauthorities": {
    "freetsa": {
      "certificate": "{{FREETSA_ROOT}}"
    }
  }
```

It should be noted that the the Witness requires that the root and the intermidate be included in the policy file.  

### Templating the Policy
Before we can use the policy, we need to populate it with the base64 encoded certificates that belong to Fulcio and FreeTSA, their `sha256sum`'d Key IDs, and the email address that you used to authenticate with Sigstore through the web browser.
While it might be fun for some to do this manually (I'm looking at you VIM power users), we have provided a script to do this for you:

*Note: This script uses the shasum tool on MacOS and sha256sum on Linux. If you are using a different operating system, you may need to modify the script to use the appropriate tool. Contributions to make this script more portable are welcome!*

```
cat << 'EOF' > template-policy.sh

email="$1"
fulcio_root="$(cat fulcio.pem | jq -r '.chains.[0].certificates.[0]')"
fulcio_int="$(cat fulcio.pem | jq -r '.chains.[0].certificates.[1]')"
freetsa_root="$(cat freetsa.pem)"
fulcio_root_b64="$(echo "$fulcio_root" | openssl base64 -A)"
fulcio_int_b64="$(echo "$fulcio_int" | openssl base64 -A)"
freetsa_root_b64="$(echo "$freetsa_root" | openssl base64 -A)"

cp policy-template.json policy.json

# Use double quotes around variables in sed commands to preserve newlines
sed -i '' "s|{{FULCIO_ROOT}}|$fulcio_root_b64|g" policy.json
sed -i '' "s|{{FULCIO_INT}}|$fulcio_int_b64|g" policy.json
sed -i '' "s|{{FREETSA_ROOT}}|$freetsa_root_b64|g" policy.json
sed -i '' "s|{{EMAIL}}|$email|g" policy.json

# Calculate SHA256 hash (macOS and Linux compatible)
if [[ "$(uname)" == "Darwin" ]]; then
	fulcio_keyid="$(echo -n "$fulcio_root" | shasum -a 256 | awk '{print $1}')"
	sed -i '' "s|{{FULCIO_KEYID}}|$fulcio_keyid|g" policy.json
else
	fulcio_keyid="$(echo -n "$fulcio_root" | sha256sum | awk '{print $1}')"
	sed -i '' "s|{{FULCIO_KEYID}}|$fulcio_keyid|g" policy.json
fi
EOF
chmod +x template-policy.sh
```

Once again, you can save this to a file locally by copying the above code, pasting it into your terminal and pressing enter. This will create a file named template-policy.sh in your current working directory, but also make it executable (with `chmod +x`).

Now you can go ahead and run the script with a single argument which you must set to be the email address that you used to authenticate to Sigstore with in the web browser earlier, e.g.,:

```
./template-policy.sh witty@in-toto.io
```

This should create a file named `policy.json` in your current working directory. Nice!

### Sign the policy file

Create a keypair to sign the policy with.

```
openssl genpkey -algorithm ed25519 -outform PEM -out testkey.pem
openssl pkey -in testkey.pem -pubout > testpub.pem
```

Sign the policy file with the keypair.

```
witness sign -k testkey.pem -o policy-signed.json -f policy.json
```

### Verify the attestation

```
witness verify -p policy-signed.json -a test.json -k testpub.pem -f test.txt
```


### You did it! 🎉

