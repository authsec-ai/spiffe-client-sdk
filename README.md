# spiffe-client-sdk
test-k8s
# SPIFFE Client SDK Installation

## Install from GitHub
```bash
pip install git+https://github.com/authsec-ai/spiffe-client-sdk.git
```

## Usage
```python
from spiffe_client_sdk import SpiffeSDK, Config

config = Config(
    service_name="my-service",
    socket_path="/run/spire/sockets/agent.sock",
    trust_domain="authsec.dev"
)

sdk = SpiffeSDK(config)
await sdk.initialize()
```
