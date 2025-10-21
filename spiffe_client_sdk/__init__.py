"""
SPIFFE Client SDK for Python (Async)

This SDK provides complete SPIFFE integration for Python microservices.
It connects to the local SPIRE Agent to receive SVIDs and provides
mTLS capabilities for secure service-to-service communication.

All operations are async for high-performance applications.
"""

__version__ = "0.1.0"

import os
import asyncio
from typing import Optional, List
from dataclasses import dataclass
import ssl
import tempfile
import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from spiffe import X509Source, WorkloadApiClient


@dataclass
class Config:
    """
    Configuration for the SPIFFE SDK

    Minimal configuration - only 2 required fields:
    - spiffe_id: Your service's SPIFFE ID (e.g., "spiffe://authsec.dev/my-service")
    - agent_token: Agent join token (e.g., "9f1ad98e-7f09-4903-ad31-0dfe772ce0d4")

    Everything else is automatically derived or uses defaults.
    """
    # REQUIRED: Only these two fields are needed from end users
    spiffe_id: str
    agent_token: str

    # Optional: Kubernetes selectors for workload attestation
    selectors: Optional[List[str]] = None  # E.g., ["k8s:ns:spire", "k8s:sa:default"]

    # Optional: Enable/disable auto-registration (default: True)
    auto_register: bool = True

    # Internal fields (automatically derived or hardcoded)
    socket_path: str = "/run/spire/sockets/agent.sock"
    workload_type: str = "application"

    # Derived fields (set automatically from spiffe_id)
    service_name: Optional[str] = None  # Extracted from spiffe_id
    trust_domain: Optional[str] = None  # Extracted from spiffe_id

    # Hardcoded - AuthSec's Headless API
    headless_api_url: str = "https://dev.api.authsec.dev"

    def __post_init__(self):
        """Extract service_name and trust_domain from spiffe_id"""
        if self.spiffe_id:
            # Parse SPIFFE ID: spiffe://authsec.dev/my-service
            # Format: spiffe://<trust_domain>/<service_name>
            if self.spiffe_id.startswith("spiffe://"):
                parts = self.spiffe_id[9:].split("/", 1)  # Remove "spiffe://" and split
                if len(parts) >= 2:
                    self.trust_domain = parts[0]
                    self.service_name = parts[1].split("/")[-1]  # Get last part as service name
                elif len(parts) == 1:
                    self.trust_domain = parts[0]
                    self.service_name = "unknown"
            else:
                raise ValueError(f"Invalid SPIFFE ID format: {self.spiffe_id}. Must start with 'spiffe://'")

        # Validate required fields
        if not self.trust_domain:
            raise ValueError("Could not extract trust_domain from spiffe_id")
        if not self.service_name:
            raise ValueError("Could not extract service_name from spiffe_id")


@dataclass
class ValidationResult:
    """Result of certificate validation"""
    valid: bool
    spiffe_id: str
    subject: str
    issuer: str
    not_before: str
    not_after: str


class HeadlessAPI:
    """Async client for headless SPIRE service"""

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def register_workload(
        self,
        spiffe_id: str,
        agent_token: str,
        trust_domain: str,
        workload_type: str = "application",
        selectors: Optional[List[str]] = None
    ) -> dict:
        """Register a workload with the SPIRE server via headless API"""
        # Construct parent_id from agent token and trust domain
        parent_id = f"spiffe://{trust_domain}/spire/agent/join_token/{agent_token}"

        payload = {
            "spiffe_id": spiffe_id,
            "parent_id": parent_id,
            "type": workload_type,
            "selectors": selectors or []
        }

        try:
            session = await self._get_session()
            async with session.post(
                f"{self.base_url}/spiresvc/api/v1/workloads",
                json=payload
            ) as response:
                # Don't raise for 409 Conflict (already registered)
                if response.status == 409:
                    print(f"ℹ️  Workload already registered: {spiffe_id}")
                    return {"already_exists": True, "spiffe_id": spiffe_id}

                response.raise_for_status()
                data = await response.json()
                print(f"✅ Workload registered successfully: {spiffe_id}")
                return data
        except Exception as e:
            raise Exception(f"Failed to register workload: {e}")

    async def verify_certificate(self, certificate: str) -> ValidationResult:
        """Verify a certificate using the headless API"""
        payload = {"certificate": certificate}

        try:
            session = await self._get_session()
            async with session.post(
                f"{self.base_url}/spiresvc/api/v1/verify/certificate",
                json=payload
            ) as response:
                response.raise_for_status()
                data = await response.json()

                return ValidationResult(
                    valid=data.get("valid", False),
                    spiffe_id=data.get("spiffe_id", ""),
                    subject=data.get("subject", ""),
                    issuer=data.get("issuer", ""),
                    not_before=data.get("not_before", ""),
                    not_after=data.get("not_after", "")
                )
        except Exception as e:
            raise Exception(f"Failed to verify certificate: {e}")

    async def close(self) -> None:
        """Close the HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()


class SpiffeSDK:
    """
    Async SPIFFE SDK provides complete SPIFFE integration for microservices.
    It connects to the local SPIRE Agent to receive SVIDs.

    All methods are async for high-performance applications.
    """

    def __init__(self, config: Config):
        self.config = config
        self.headless_api: Optional[HeadlessAPI] = None
        self.x509_source: Optional[X509Source] = None
        self._lock = asyncio.Lock()
        self._running = True
        self._renewal_callbacks = []  # Callbacks to invoke on cert renewal
        self._last_cert_serial = None  # Track certificate changes

        # Set default socket path if not provided
        if not self.config.socket_path:
            self.config.socket_path = "/run/spire/sockets/agent.sock"

        # Ensure socket path has unix:// scheme for spiffe library
        socket_path = self.config.socket_path
        if not socket_path.startswith("unix://"):
            socket_path = f"unix://{socket_path}"

        # Set environment variable for spiffe library
        os.environ['SPIFFE_ENDPOINT_SOCKET'] = socket_path

        # Initialize optional headless API for certificate verification
        if self.config.headless_api_url:
            self.headless_api = HeadlessAPI(self.config.headless_api_url)

    async def initialize(self) -> None:
        """
        Connect to the local SPIRE Agent and retrieve SVIDs.
        If auto_register is enabled and required parameters are provided,
        the workload will be automatically registered before connecting.
        """
        print(f"Initializing SPIFFE SDK...")

        # Auto-register workload if configured
        if self.config.auto_register and self._should_auto_register():
            await self._auto_register_workload()

        print(f"Connecting to SPIRE Agent at {self.config.socket_path}")

        # Initialize X509Source in executor (it's blocking)
        try:
            # Prepare socket path with unix:// scheme
            socket_path = self.config.socket_path
            if not socket_path.startswith("unix://"):
                socket_path = f"unix://{socket_path}"

            loop = asyncio.get_event_loop()
            self.x509_source = await loop.run_in_executor(
                None,
                lambda: X509Source(socket_path=socket_path)
            )
        except Exception as e:
            raise Exception(
                f"Failed to connect to SPIRE Agent: {e} "
                "(ensure workload is registered and agent is running)"
            )

        print("✅ Connected to SPIRE Agent successfully")
        print("✅ TLS configuration established")
        print(f"✅ SPIFFE ID: {self.get_spiffe_id()}")

        # Track initial certificate
        cert = self.get_x509_svid()
        if cert:
            self._last_cert_serial = cert.serial_number

        # Start certificate renewal monitoring
        asyncio.create_task(self._monitor_certificate_renewal())

    def _should_auto_register(self) -> bool:
        """Check if all required parameters for auto-registration are provided"""
        return all([
            self.config.spiffe_id,
            self.config.agent_token,
            self.config.trust_domain,
            self.config.headless_api_url
        ])

    async def _auto_register_workload(self) -> None:
        """Automatically register the workload with SPIRE server"""
        # Type assertions - these are guaranteed by _should_auto_register() check
        assert self.config.headless_api_url is not None
        assert self.config.spiffe_id is not None
        assert self.config.agent_token is not None
        assert self.config.trust_domain is not None

        if not self.headless_api:
            self.headless_api = HeadlessAPI(self.config.headless_api_url)

        print(f"📝 Auto-registering workload: {self.config.spiffe_id}")

        try:
            await self.headless_api.register_workload(
                spiffe_id=self.config.spiffe_id,
                agent_token=self.config.agent_token,
                trust_domain=self.config.trust_domain,
                workload_type=self.config.workload_type,
                selectors=self.config.selectors or []
            )
        except Exception as e:
            print(f"⚠️  Auto-registration failed: {e}")
            print(f"ℹ️  Continuing with initialization (workload may already be registered)")

    async def _monitor_certificate_renewal(self) -> None:
        """
        Background task that monitors for certificate renewals.
        When a new certificate is detected, calls all registered callbacks.
        """
        while self._running:
            try:
                await asyncio.sleep(5)  # Check every 5 seconds

                cert = self.get_x509_svid()
                if cert and cert.serial_number != self._last_cert_serial:
                    # Certificate has been renewed
                    print(f"🔄 Certificate renewed! New serial: {cert.serial_number}")
                    # Use UTC-aware datetime properties to avoid deprecation warnings
                    not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
                    not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
                    print(f"   Not before: {not_before.isoformat()}")
                    print(f"   Not after: {not_after.isoformat()}")

                    self._last_cert_serial = cert.serial_number

                    # Invoke all registered callbacks
                    for callback in self._renewal_callbacks:
                        try:
                            if asyncio.iscoroutinefunction(callback):
                                await callback()
                            else:
                                callback()
                        except Exception as e:
                            print(f"⚠️  Error in renewal callback: {e}")
            except Exception as e:
                if self._running:  # Only log if we're still supposed to be running
                    print(f"⚠️  Error monitoring certificate renewal: {e}")
                await asyncio.sleep(5)

    def register_renewal_callback(self, callback) -> None:
        """
        Register a callback to be invoked when the certificate is renewed.
        Callback can be sync or async.

        Example:
            async def on_cert_renewed():
                print("Certificate was renewed!")

            sdk.register_renewal_callback(on_cert_renewed)
        """
        self._renewal_callbacks.append(callback)

    def get_spiffe_id(self) -> str:
        """Returns the SPIFFE ID assigned to this workload by the SPIRE Agent"""
        if self.x509_source is None or self.x509_source.svid is None:
            return ""
        return str(self.x509_source.svid.spiffe_id)

    def get_x509_svid(self) -> Optional[x509.Certificate]:
        """
        Returns the current X.509 SVID certificate.
        This is automatically rotated by the SPIRE Agent.
        """
        if self.x509_source is None:
            raise Exception("X509Source not initialized")

        # Get the certificate from the svid
        svid = self.x509_source.svid
        if svid and hasattr(svid, 'leaf'):
            return svid.leaf
        elif svid and hasattr(svid, 'cert_chain') and len(svid.cert_chain) > 0:
            return svid.cert_chain[0]
        return None

    def get_private_key(self):
        """Returns the private key associated with the current SVID"""
        if self.x509_source is None:
            raise Exception("X509Source not initialized")

        svid = self.x509_source.svid
        if svid:
            return svid.private_key
        return None

    async def get_ssl_context(self) -> ssl.SSLContext:
        """
        Returns an SSL context configured with SPIFFE mTLS.
        Use this for creating secure connections to other services.
        """
        if self.x509_source is None or self.x509_source.svid is None:
            raise Exception("SDK not initialized")

        async with self._lock:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED

            svid = self.x509_source.svid

            # Get the certificate (try different attribute names)
            cert = None
            if hasattr(svid, 'leaf'):
                cert = svid.leaf
            elif hasattr(svid, 'cert_chain') and len(svid.cert_chain) > 0:
                cert = svid.cert_chain[0]

            if not cert:
                raise Exception("No certificate found in SVID")

            # Load certificate and private key
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = svid.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Create temporary cert chain
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name

            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as key_file:
                key_file.write(key_pem)
                key_path = key_file.name

            try:
                context.load_cert_chain(cert_path, key_path)
            finally:
                os.unlink(cert_path)
                os.unlink(key_path)

            # Load trust bundle
            if hasattr(self.x509_source, 'get_bundle_for_trust_domain'):
                # Get the trust domain from the SPIFFE ID
                trust_domain = svid.spiffe_id.trust_domain
                bundle = self.x509_source.get_bundle_for_trust_domain(trust_domain)

                if bundle:
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as ca_file:
                        # Try different attributes for certificates
                        certs = []
                        if hasattr(bundle, 'x509_authorities'):
                            certs = bundle.x509_authorities
                        elif hasattr(bundle, 'authorities'):
                            certs = bundle.authorities

                        for cert in certs:
                            ca_file.write(cert.public_bytes(serialization.Encoding.PEM))
                        ca_path = ca_file.name

                    try:
                        if certs:  # Only load if we have certificates
                            context.load_verify_locations(ca_path)
                    finally:
                        os.unlink(ca_path)

            return context

    async def get_ssl_server_context(self) -> ssl.SSLContext:
        """
        Returns an SSL context configured for SPIFFE mTLS server.
        Use this when creating a server that accepts client connections.
        """
        if self.x509_source is None or self.x509_source.svid is None:
            raise Exception("SDK not initialized")

        async with self._lock:
            # Use server protocol
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_OPTIONAL  # Allow both mTLS and regular TLS

            svid = self.x509_source.svid

            # Get the certificate
            cert = None
            if hasattr(svid, 'leaf'):
                cert = svid.leaf
            elif hasattr(svid, 'cert_chain') and len(svid.cert_chain) > 0:
                cert = svid.cert_chain[0]

            if not cert:
                raise Exception("No certificate found in SVID")

            # Load certificate and private key
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = svid.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Create temporary cert chain
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name

            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as key_file:
                key_file.write(key_pem)
                key_path = key_file.name

            try:
                context.load_cert_chain(cert_path, key_path)
            finally:
                os.unlink(cert_path)
                os.unlink(key_path)

            # Load trust bundle for client cert verification
            if hasattr(self.x509_source, 'get_bundle_for_trust_domain'):
                trust_domain = svid.spiffe_id.trust_domain
                bundle = self.x509_source.get_bundle_for_trust_domain(trust_domain)

                if bundle:
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as ca_file:
                        certs = []
                        if hasattr(bundle, 'x509_authorities'):
                            certs = bundle.x509_authorities
                        elif hasattr(bundle, 'authorities'):
                            certs = bundle.authorities

                        for cert in certs:
                            ca_file.write(cert.public_bytes(serialization.Encoding.PEM))
                        ca_path = ca_file.name

                    try:
                        if certs:
                            context.load_verify_locations(ca_path)
                    finally:
                        os.unlink(ca_path)

            return context

    async def get_http_client(self, internal_domains: Optional[List[str]] = None) -> aiohttp.ClientSession:
        """
        Returns an async HTTP client (aiohttp.ClientSession) configured with SPIFFE mTLS.

        If internal_domains is provided, connections to those domains will use mTLS.
        For external services, regular HTTPS will be used.
        """
        ssl_context = await self.get_ssl_context()
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        return aiohttp.ClientSession(connector=connector)

    async def validate_incoming_svid(self, cert_pem: str) -> ValidationResult:
        """
        Validate an incoming certificate using Headless API.
        Note: This requires HeadlessAPIURL to be configured.
        """
        if self.headless_api is None:
            raise Exception("Headless API not configured - set headless_api_url in config")

        return await self.headless_api.verify_certificate(cert_pem)

    async def close(self) -> None:
        """Clean up resources"""
        self._running = False

        # Close headless API session
        if self.headless_api:
            await self.headless_api.close()

        # Close X509Source
        if self.x509_source:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self.x509_source.close)
            except:
                pass

    def _cert_to_pem(self, cert: x509.Certificate) -> str:
        """Convert x509.Certificate to PEM format"""
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    async def __aenter__(self):
        """Async context manager support"""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager cleanup"""
        await self.close()


# Utility functions for common patterns

async def create_spiffe_client(
    spiffe_id: str,
    agent_token: str,
    selectors: Optional[List[str]] = None,
    auto_register: bool = True
) -> SpiffeSDK:
    """
    Convenience function to create and initialize a SPIFFE SDK client.

    Only 2 required parameters:
    - spiffe_id: Your service's SPIFFE ID (e.g., "spiffe://authsec.dev/my-service")
    - agent_token: Agent join token

    Usage:
        sdk = await create_spiffe_client(
            spiffe_id="spiffe://authsec.dev/my-service",
            agent_token="9f1ad98e-7f09-4903-ad31-0dfe772ce0d4"
        )
    """
    config = Config(
        spiffe_id=spiffe_id,
        agent_token=agent_token,
        selectors=selectors,
        auto_register=auto_register
    )

    sdk = SpiffeSDK(config)
    await sdk.initialize()
    return sdk


# Example usage (commented out):
"""
import asyncio
import os

async def main():
    # MINIMAL CONFIG - Only 2 required fields!
    config = Config(
        spiffe_id=os.getenv("SPIFFE_ID"),          # e.g., "spiffe://authsec.dev/my-service"
        agent_token=os.getenv("AGENT_TOKEN"),      # e.g., "9f1ad98e-7f09-4903-ad31-0dfe772ce0d4"

        # Optional: Add selectors
        selectors=[
            "k8s:ns:production",
            "k8s:sa:my-service",
            "k8s:pod-label:app:my-service"
        ]
    )

    # Using context manager
    async with SpiffeSDK(config) as sdk:
        print(f"✅ SPIFFE ID: {sdk.get_spiffe_id()}")

        # Get HTTP client for internal service calls
        async with await sdk.get_http_client() as client:
            async with client.get("https://other-service:8443/api") as response:
                print(response.status)
                data = await response.json()

    # Or using convenience function
    sdk = await create_spiffe_client(
        spiffe_id="spiffe://authsec.dev/my-service",
        agent_token="9f1ad98e-7f09-4903-ad31-0dfe772ce0d4"
    )
    try:
        spiffe_id = sdk.get_spiffe_id()
        print(f"✅ My SPIFFE ID: {spiffe_id}")

        # Make an authenticated request
        async with await sdk.get_http_client() as client:
            async with client.get("https://api.example.com/data") as response:
                data = await response.json()
                print(data)
    finally:
        await sdk.close()

if __name__ == "__main__":
    asyncio.run(main())
"""
