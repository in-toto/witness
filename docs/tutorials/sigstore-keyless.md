# Signing Attestations with Sigstore Keyless

><span style={{fontSize: '0.9em'}}>💡 Tip: If this is your first time using Witness, you might benefit from trying the [Getting Started](./getting-started.md) tutorial first!</span>

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
If you have tried any of our other tutorials, you might have a `test.txt` lying around (if not, then you can skip the following command).
It's important that you remove this as Witness will not record file hashes for products that exist in the filesystem before its invocation:

```
rm test.txt
```

## Let's Go!

### Run a build step and record the attestation
First, we want to run simple example step, wrapped with Witness. This will create attestations that will later help us verify that it was run safely: 
```
witness run -s test -o test.json --fulcio https://fulcio.sigstore.dev --fulcio-oidc-client-id https://oauth2.sigstore.dev/auth --fulcio-oidc-issuer sigstore --timestamp-servers https://freetsa.org/tsr -- echo "hello" > test.txt
```

Hold up a second, what's going on here? If you jumped 

### View the attestation data in the signed DSSE Envelope

```
cat test.json | jq -r .payload | base64 -d | jq
```

### Download the Fulcio Root CA

The Fulcio Root CA is used to verify the Fulcio certificate chain it is available at https://fulcio.sigstore.dev/api/v2/trustBundle.

### Create a Policy File

Create a policy file that defines the attestations that are required for a build step to be considered valid.  Add the Fulcio Root CA to the policy file and as a functionary on the build step.  You can define constraints on the certificate that is used to sign the build step.  In this example we are requiring that the certificate be signed by the Fulcio Root CA and that the user that signed the certificate is `cole@testifysec.com`.  The Fulcio API provides both a root certificate and an intermidate in the bundle.  The Witness API requires that the root and the intermidate be included in the policy file.  Additionally, since Fulcio's certs are short lived we must also include a root of trust for the Timestamp.  Future versions of Witness will support retrieving and verifying the embeded timestamp in the certificate provided by Fulcio.

- Make sure you replace my email with one that is associated with the account you used to sign the attestation.
- Notice the name and identifier in the `steps` section of the policy file.  This corresponds with the `step` name indicated in the `witness run` command and in the `payload` section of the attestation.

```
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
            "dnsnames": ["*"],
            "emails": ["cole@testifysec.com"],
            "organizations": ["*"],
            "uris": ["*"],
            "roots": [
              "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1"
            ]
          }
        }
      ]
    }
  },
  "roots": {
    "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1": {
      "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHakNDQWFHZ0F3SUJBZ0lVQUxuVmlWZm5VMGJySmFzbVJrSHJuL1VuZmFRd0NnWUlLb1pJemowRUF3TXdLakVWTUJNR0ExVUVDaE1NYzJsbmMzUnZjbVV1WkdWMk1SRXdEd1lEVlFRREV3aHphV2R6ZEc5eVpUQWVGdzB5TWpBME1UTXlNREEyTVRWYUZ3MHpNVEV3TURVeE16VTJOVGhhTURjeEZUQVRCZ05WQkFvVERITnBaM04wYjNKbExtUmxkakVlTUJ3R0ExVUVBeE1WYzJsbmMzUnZjbVV0YVc1MFpYSnRaV1JwWVhSbE1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFOFJWUy95c0grTk92dURaeVBJWnRpbGdVRjlObGFyWXBBZDlIUDF2QkJIMVU1Q1Y3N0xTUzdzMFppSDRuRTdIdjdwdFM2THZ2Ui9TVGs3OThMVmdNekxsSjRIZUlmRjN0SFNhZXhMY1lwU0FTcjFrUzBOL1JnQkp6LzlqV0NpWG5vM3N3ZVRBT0JnTlZIUThCQWY4RUJBTUNBUVl3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVIQXdNd0VnWURWUjBUQVFIL0JBZ3dCZ0VCL3dJQkFEQWRCZ05WSFE0RUZnUVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFlaRDh3SHdZRFZSMGpCQmd3Rm9BVVdNQWVYNUZGcFdhcGVzeVFvWk1pMENyRnhmb3dDZ1lJS29aSXpqMEVBd01EWndBd1pBSXdQQ3NRSzREWWlaWURQSWFEaTVIRktuZnhYeDZBU1NWbUVSZnN5bllCaVgyWDZTSlJuWlU4NC85RFpkbkZ2dnhtQWpCT3Q2UXBCbGM0Si8wRHh2a1RDcXBjbHZ6aUw2QkNDUG5qZGxJQjNQdTNCeHNQbXlnVVk3SWkyemJkQ2RsaWlvdz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==",
      "intermediates": [
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUI5ekNDQVh5Z0F3SUJBZ0lVQUxaTkFQRmR4SFB3amVEbG9Ed3lZQ2hBTy80d0NnWUlLb1pJemowRUF3TXcKS2pFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUkV3RHdZRFZRUURFd2h6YVdkemRHOXlaVEFlRncweQpNVEV3TURjeE16VTJOVGxhRncwek1URXdNRFV4TXpVMk5UaGFNQ294RlRBVEJnTlZCQW9UREhOcFozTjBiM0psCkxtUmxkakVSTUE4R0ExVUVBeE1JYzJsbmMzUnZjbVV3ZGpBUUJnY3Foa2pPUFFJQkJnVXJnUVFBSWdOaUFBVDcKWGVGVDRyYjNQUUd3UzRJYWp0TGszL09sbnBnYW5nYUJjbFlwc1lCcjVpKzR5bkIwN2NlYjNMUDBPSU9aZHhleApYNjljNWlWdXlKUlErSHowNXlpK1VGM3VCV0FsSHBpUzVzaDArSDJHSEU3U1hyazFFQzVtMVRyMTlMOWdnOTJqCll6QmhNQTRHQTFVZER3RUIvd1FFQXdJQkJqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCUlkKd0I1ZmtVV2xacWw2ekpDaGt5TFFLc1hGK2pBZkJnTlZIU01FR0RBV2dCUll3QjVma1VXbFpxbDZ6SkNoa3lMUQpLc1hGK2pBS0JnZ3Foa2pPUFFRREF3TnBBREJtQWpFQWoxbkhlWFpwKzEzTldCTmErRURzRFA4RzFXV2cxdENNCldQL1dIUHFwYVZvMGpoc3dlTkZaZ1NzMGVFN3dZSTRxQWpFQTJXQjlvdDk4c0lrb0YzdlpZZGQzL1Z0V0I1YjkKVE5NZWE3SXgvc3RKNVRmY0xMZUFCTEU0Qk5KT3NRNHZuQkhKCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0="
      ]
    }
  },
  "timestampauthorities": {
    "freetsa": {
      "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUgvekNDQmVlZ0F3SUJBZ0lKQU1IcGhoWU5xT21BTUEwR0NTcUdTSWIzRFFFQkRRVUFNSUdWTVJFd0R3WUQKVlFRS0V3aEdjbVZsSUZSVFFURVFNQTRHQTFVRUN4TUhVbTl2ZENCRFFURVlNQllHQTFVRUF4TVBkM2QzTG1aeQpaV1YwYzJFdWIzSm5NU0l3SUFZSktvWklodmNOQVFrQkZoTmlkWE5wYkdWNllYTkFaMjFoYVd3dVkyOXRNUkl3CkVBWURWUVFIRXdsWGRXVnllbUoxY21jeER6QU5CZ05WQkFnVEJrSmhlV1Z5YmpFTE1Ba0dBMVVFQmhNQ1JFVXcKSGhjTk1UWXdNekV6TURFMU1qRXpXaGNOTkRFd016QTNNREUxTWpFeldqQ0JsVEVSTUE4R0ExVUVDaE1JUm5KbApaU0JVVTBFeEVEQU9CZ05WQkFzVEIxSnZiM1FnUTBFeEdEQVdCZ05WQkFNVEQzZDNkeTVtY21WbGRITmhMbTl5Clp6RWlNQ0FHQ1NxR1NJYjNEUUVKQVJZVFluVnphV3hsZW1GelFHZHRZV2xzTG1OdmJURVNNQkFHQTFVRUJ4TUoKVjNWbGNucGlkWEpuTVE4d0RRWURWUVFJRXdaQ1lYbGxjbTR4Q3pBSkJnTlZCQVlUQWtSRk1JSUNJakFOQmdrcQpoa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQXRnS09EakF5OFJFUTJXVE5xVXVkQW5qaGxDcnBFNnFsCm1RZk5wcGVUbVZ2WnJINHp1dG4rTndUYUhBR3BqU0d2NC9XUnBaMXdaM0JSWjVtUFVCWnlMZ3EwWXJJZlE1RngKMHMvTVJaUHpjMXIzbEtXck1SOXNBUXg0bU40ejExeEZFTzUyOUwwZEZKalBGOU1EOEdwZDJmZVd6R3lwdGxlbApiK1BxVCsrK2ZPYTJvWTArTmFNTTdsL3hjTkhQT2FNejAvMm9sazBpMjJoYktlVmh2b2tQQ3FoRmh6c3VoS3NtCnE0T2Yvbyt0NmRJN3N4NWgwblBNbTRnR1NSaGZxK3o2QlRSZ0NycVFHMkZPTG9WRmd0NmlJbS9Cbk5mZlVyN1YKRFlkM3pabUl3Rk9qL0gzREtIb0dpay94SzNFODJZQTJadWxWT0ZSVy96ajRBcGpQYTVPRmJwSWtkMHBtenh6ZApFY0w0NzloU0E5ZEZpeVZtU3hQdFk1emUxUCtCRTliTVUxUFNjcFJ6dzhNSEZYeHlLcVcxM1F2N0xXdzRzYmszClNjaUI3R0FDYlFpVkd6Z2t2WEc2eTg1SE91dldOdkM1R0xTaXlQOUdsUEIwVjY4dGJ4ejRKVlRSZHcvWG4vWFQKRk56UkJNM2NxOGxCT0FWdC9QQVg1K3VGY3YxUzl3RkU4WWphQmZXQ1AxamRCaWwrYzRlKzB0ZHl3VDJvSm1ZQgpCRi9rRXQxd21Hd01tSHVuTkV1UU56aDFGdEpZNTRoYlVmaVdpMzhtQVNFN3hNdE1oZmovQzRTdmFwaUROODM3CmdZYVBmczh4M0taeGJYN0MzWUFzRm5KaW5sd0FVc3MxZmRLYXI4US9ZVnM3SC9uVTRjNEl4eHh6NGY2N2ZjVnEKTTJJVEtlbnRiQ01DQXdFQUFhT0NBazR3Z2dKS01Bd0dBMVVkRXdRRk1BTUJBZjh3RGdZRFZSMFBBUUgvQkFRRApBZ0hHTUIwR0ExVWREZ1FXQkJUNlZRMk1OR1pSUTB6MzU3T25iSld2ZXVha2x6Q0J5Z1lEVlIwakJJSENNSUcvCmdCVDZWUTJNTkdaUlEwejM1N09uYkpXdmV1YWtsNkdCbTZTQm1EQ0JsVEVSTUE4R0ExVUVDaE1JUm5KbFpTQlUKVTBFeEVEQU9CZ05WQkFzVEIxSnZiM1FnUTBFeEdEQVdCZ05WQkFNVEQzZDNkeTVtY21WbGRITmhMbTl5WnpFaQpNQ0FHQ1NxR1NJYjNEUUVKQVJZVFluVnphV3hsZW1GelFHZHRZV2xzTG1OdmJURVNNQkFHQTFVRUJ4TUpWM1ZsCmNucGlkWEpuTVE4d0RRWURWUVFJRXdaQ1lYbGxjbTR4Q3pBSkJnTlZCQVlUQWtSRmdna0F3ZW1HRmcybzZZQXcKTXdZRFZSMGZCQ3d3S2pBb29DYWdKSVlpYUhSMGNEb3ZMM2QzZHk1bWNtVmxkSE5oTG05eVp5OXliMjkwWDJOaApMbU55YkRDQnp3WURWUjBnQklISE1JSEVNSUhCQmdvckJnRUVBWUh5SkFFQk1JR3lNRE1HQ0NzR0FRVUZCd0lCCkZpZG9kSFJ3T2k4dmQzZDNMbVp5WldWMGMyRXViM0puTDJaeVpXVjBjMkZmWTNCekxtaDBiV3d3TWdZSUt3WUIKQlFVSEFnRVdKbWgwZEhBNkx5OTNkM2N1Wm5KbFpYUnpZUzV2Y21jdlpuSmxaWFJ6WVY5amNITXVjR1JtTUVjRwpDQ3NHQVFVRkJ3SUNNRHNhT1VaeVpXVlVVMEVnZEhKMWMzUmxaQ0IwYVcxbGMzUmhiWEJwYm1jZ1UyOW1kSGRoCmNtVWdZWE1nWVNCVFpYSjJhV05sSUNoVFlXRlRLVEEzQmdnckJnRUZCUWNCQVFRck1Da3dKd1lJS3dZQkJRVUgKTUFHR0cyaDBkSEE2THk5M2QzY3VabkpsWlhSellTNXZjbWM2TWpVMk1EQU5CZ2txaGtpRzl3MEJBUTBGQUFPQwpBZ0VBYUs5K3Y1T0ZZdTlNNnp0WUMrTDY5c3cxb21keWxpODlsWkFmcFdNTWg5Q1JtSmhNNktCcU0vaXB3b0x0Cm54eXhHc2JDUGhjUWp1VHZ6bSt5bE42VndUTW1JbFZ5VlNMS1laY2RTanQvZUNVTis0MUs3c0Q3R1ZteFpCQUYKSUxuQkRtVEdKbUxrclUwS3V1SXBqOGxJL0U2WjZObm11UDIrUkFRU0hzZkJRaTZzc3NuWE1vNEhPVzVndFBPNwpnRHJVcFZYSUQrKzFQNFhuZGtvS243U3Z3NW4welM5ZnYxaHhCY1lJSFBQUVV6ZTJ1MzBiQVF0MG4waUl5Ukx6CmFXdWh0cEF0ZDdmZndFYkFTZ3pCN0UrTkdGNHRwVjM3ZThLaUEyeGlHU1JxVDVuZHUyOGZncE9ZODdnRDNBcloKRGN0WnZ2VENmSGRBUzVrRU8zZ25HR2VaRVZMRG1mRXN2OFRHSmEzQWxqVmE1RTQwSVFEc1VYcFFMaThHK1VDNAoxRFdadThFVlQ0cm5ZYUN3MVZYN1NoT1IxUE5DQ3ZqYjhTOHRmZHVkZDl6aFUzZ0VCMHJ4ZGVUeTF0VmJOTFhXCjk5eTkweGN3cjFaSURVd00veFEvbm9POEZSaG0wTG9QQzczRWYrSjRaQmRydld3YXVGM3pKZTMzZDRpYnhFY2IKOC9wejVXekZrZWl4WU0ybnNIaHFIc0JLdzdKUG91S05YUm5sNUlBRTFlRm1xRHlDN0cvVlQ3T0Y2Njl4TTZoYgpVdDVHMjFKRTRjTks2Tk51Y1MrZnpnMUpQWDArM1Zoc1laamo3RDV1bGpSdlFYcko4aUhnci9NNmoyb0xIdlRBCkkyTUxkcTJxalpGRE9DWHN4QnhKcGJtTEdCeDlvdzZaZXJsVXh6d3MyQVd2MnBrPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"
    }
  }
}

```

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

