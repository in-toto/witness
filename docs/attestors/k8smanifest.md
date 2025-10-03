# Kubernetes Manifest Attestor

The Kubernetes Manifest Attestor normalizes and records Kubernetes manifest files, capturing the canonical representation of resources for deployment verification. It can perform server-side dry-runs to expand defaults, filter ephemeral fields, and record cluster information. Container images referenced in manifests are also captured as subjects for supply chain tracking.

## Use Cases

- Kubernetes deployment verification: Ensure deployed manifests match approved configurations
- GitOps validation: Verify that applied manifests match what is stored in git repositories
- Policy enforcement: Attest to the exact configuration deployed to clusters for compliance
- Container image tracking: Record all container images referenced in Kubernetes deployments

## Usage

Basic usage with local manifests:
```bash
witness run --step deploy -a k8smanifest -o attestation.json -- kubectl apply -f deployment.yaml
```

With server-side dry-run for normalization:
```bash
witness run --step deploy -a k8smanifest \
  --attestor-k8smanifest-server-side-dry-run \
  --attestor-k8smanifest-kubeconfig ~/.kube/config \
  --attestor-k8smanifest-context production \
  -o attestation.json -- kubectl apply -f deployment.yaml
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--attestor-k8smanifest-kubeconfig` | `$HOME/.kube/config` | Path to the kubeconfig file (used during server-side dry-run) |
| `--attestor-k8smanifest-context` | Current context | The Kubernetes context that this step applies to (if not set in the kubeconfig) |
| `--attestor-k8smanifest-server-side-dry-run` | `false` | Perform a server-side dry-run to normalize resource defaults before hashing |
| `--attestor-k8smanifest-record-cluster-information` | `true` | Record information about the cluster that the client has a connection to |
| `--attestor-k8smanifest-ignore-fields` | None | Additional ephemeral fields to remove (dot-separated), e.g., `metadata.annotations.myorg` |
| `--attestor-k8smanifest-ignore-annotations` | None | Additional ephemeral annotations to remove, e.g., `witness.dev/another-ephemeral` |

## Subjects

| Subject | Description |
| ------- | ----------- |
| Normalized manifest digests | SHA256 hashes of canonicalized Kubernetes manifests after filtering ephemeral fields |
| Container images | Digests and references of all container images specified in the manifests |
| Cluster information | Server URL and node information (when `record-cluster-information` is enabled) |

## Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/in-toto/go-witness/attestation/k8smanifest/attestor",
  "$ref": "#/$defs/Attestor",
  "$defs": {
    "Attestor": {
      "properties": {
        "serversidedryrun": {
          "type": "boolean"
        },
        "recordclusterinfo": {
          "type": "boolean"
        },
        "kubeconfig": {
          "type": "string"
        },
        "kubecontext": {
          "type": "string"
        },
        "ignorefields": {
          "items": {
            "type": "string"
          },
          "type": "array",
          "title": "ignorefields"
        },
        "ignoreannotations": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "recordeddocs": {
          "items": {
            "$ref": "#/$defs/RecordedObject"
          },
          "type": "array"
        },
        "clusterinfo": {
          "$ref": "#/$defs/ClusterInfo"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "clusterinfo"
      ]
    },
    "ClusterInfo": {
      "properties": {
        "server": {
          "type": "string"
        },
        "nodes": {
          "additionalProperties": {
            "$ref": "#/$defs/RecordedNode"
          },
          "type": "object"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "server",
        "nodes"
      ]
    },
    "NodeSwapStatus": {
      "properties": {
        "capacity": {
          "type": "integer"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "NodeSystemInfo": {
      "properties": {
        "machineID": {
          "type": "string"
        },
        "systemUUID": {
          "type": "string"
        },
        "bootID": {
          "type": "string"
        },
        "kernelVersion": {
          "type": "string"
        },
        "osImage": {
          "type": "string"
        },
        "containerRuntimeVersion": {
          "type": "string"
        },
        "kubeletVersion": {
          "type": "string"
        },
        "kubeProxyVersion": {
          "type": "string"
        },
        "operatingSystem": {
          "type": "string"
        },
        "architecture": {
          "type": "string"
        },
        "swap": {
          "$ref": "#/$defs/NodeSwapStatus"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "machineID",
        "systemUUID",
        "bootID",
        "kernelVersion",
        "osImage",
        "containerRuntimeVersion",
        "kubeletVersion",
        "kubeProxyVersion",
        "operatingSystem",
        "architecture"
      ]
    },
    "RecordedImage": {
      "properties": {
        "reference": {
          "type": "string"
        },
        "digest": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "reference",
        "digest"
      ]
    },
    "RecordedNode": {
      "properties": {
        "name": {
          "type": "string"
        },
        "labels": {
          "additionalProperties": {
            "type": "string"
          },
          "type": "object"
        },
        "nodeInfo": {
          "$ref": "#/$defs/NodeSystemInfo"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "name",
        "labels",
        "nodeInfo"
      ]
    },
    "RecordedObject": {
      "properties": {
        "filepath": {
          "type": "string"
        },
        "kind": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "data": true,
        "subjectkey": {
          "type": "string"
        },
        "recordedimages": {
          "items": {
            "$ref": "#/$defs/RecordedImage"
          },
          "type": "array"
        }
      },
      "additionalProperties": false,
      "type": "object",
      "required": [
        "filepath",
        "kind",
        "name",
        "data",
        "subjectkey",
        "recordedimages"
      ]
    }
  }
}
```
