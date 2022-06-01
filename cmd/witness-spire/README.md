# SCRIBE

Scribe is a tool that attests and records events in a build environment.

## Running Scribe




## Registering Environments

Work in progress.

Authorized environments can be registered using the `register-env` command.  Environments can also be registed by visiting the [`/register`](judge/testifysec.com/register) page.

```
scribe --register-env
```

This command will open a browser window and ask you to authenticate with Judge.

## Registering Builders

Users must register a builder with Judge before they can use it.

### Register a builder container

The container can be specified using a tag but will be registered using the `IMAGEID` defined as the SHA256 hash of the image's JSON configuration object.

```
scribe --register-container <image>
```

### Register a binary
```
scribe --register-binary <path>
scribe --register-binary-sha256 <sha256 of binary>
```


## Selecting Node Attestors

Scribe can only use a single node attestor at a time and will try to select the best one for the given environment.  The order of preference is:

1. TPM Device
2. Cloud Service
3. [WIP] Kubernetes Projected Service Account Token
4. [WIP] Kubernetes Service Account

## Bare Metal Environment

### Seting up the TPM UDEV Rules.

TPM devices generally are not readable without special permissions.  Setting up UDEV rules wil ensure that the device is accessible.


Add the following to `/etc/udev/rules.d/70-tpm.rules`:

```
KERNEL=="tpm0", TAG+="systemd", MODE="0660", OWNER="tpm"
KERNEL=="tpmrm0", TAG+="systemd", MODE="0660", OWNER="tpm", GROUP="tpm"
```

You can use the following to add the build user to the `tpm` group:

```
usermod -a -G tpm $USER
```

If you are running scribe inside a container you must mount the TPM device to `/dev/tpmrm0`:

## Docker
```
docker container run -v /dev/tpmrm0:/dev/tpmrm0 scribe-builder:latest
```


### Kubernetes
```
apiVersion: v1
kind: Pod
metadata:
  name: scribe-builder
spec:
    containers:
    - name: scribe-builder
        image: scribe-builder:latest
        imagePullPolicy: Always
        volumeMounts:
        - name: tpmrm0
          mountPath: /dev/tpmrm0
    volumes:
    - name: tpmrm0
        hostPath:
        path: /dev/tpmrm0
```



## GCP Environment

Scribe uses the GCP instance metadata service to confirm the identity of the machine and workload performing the build. This can be forced by setting the flag `--node-attestor=gcp-iit` on the `scribe` command.


## AWS Environment

Scribe uses the AWS instance metadata service to confirm the identity of the machine and workload performing the build.

## Azure Environment
Work in progress.

Scribe uses the Azure instance metadata service to confirm the identity of the machine and workload performing the build.

## Kubernetes Environment
Work in progress.
