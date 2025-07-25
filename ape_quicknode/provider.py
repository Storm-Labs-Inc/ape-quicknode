import os
from typing import TYPE_CHECKING, Any, Optional

from ape.api import ReceiptAPI, TraceAPI, TransactionAPI, UpstreamProvider
from ape.exceptions import (
    APINotImplementedError,
    ContractLogicError,
    ProviderError,
    VirtualMachineError,
)
from ape.logging import logger
from ape_ethereum.provider import Web3Provider
from eth_pydantic_types import HexBytes
from eth_typing import HexStr
from pydantic import BaseModel
from requests import HTTPError
from web3 import HTTPProvider, Web3
from web3.exceptions import ContractLogicError as Web3ContractLogicError
from web3.gas_strategies.rpc import rpc_gas_price_strategy

try:
    from web3.middleware import ExtraDataToPOAMiddleware  # type: ignore
except ImportError:
    from web3.middleware import geth_poa_middleware as ExtraDataToPOAMiddleware  # type: ignore

from web3.types import RPCEndpoint

from .constants import QUICKNODE_NETWORKS
from .exceptions import MissingAuthTokenError, QuickNodeFeatureNotAvailable, QuickNodeProviderError
from .trace import QuickNodeTransactionTrace

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ape.types import BlockID
    from ape_ethereum.transactions import AccessList

DEFAULT_ENVIRONMENT_VARIABLE_NAMES = ("QUICKNODE_SUBDOMAIN", "QUICKNODE_AUTH_TOKEN")

NETWORKS_SUPPORTING_WEBSOCKETS = ("ethereum", "arbitrum", "base", "optimism", "polygon")

# Flashbots will try to publish private transactions for 25 blocks.
PRIVATE_TX_BLOCK_WAIT = 25


class QuickNode(Web3Provider, UpstreamProvider, BaseModel):
    name: str = "QuickNode"

    def __init__(self, network: Any, name: str = "QuickNode", **data):
        super().__init__(network=network, name=name, **data)
        self._web3 = None
        self.network_uris = {}

    @property
    def provider_name(self) -> str:
        return self.name

    network_uris: dict[tuple, str] = {}

    @property
    def uri(self):
        """
        QuickNode RPC URI, including the subdomain and auth token.
        """
        ecosystem_name = self.network.ecosystem.name
        network_name = self.network.name
        if (ecosystem_name, network_name) in self.network_uris:
            return self.network_uris[(ecosystem_name, network_name)]

        subdomain = os.environ.get("QUICKNODE_SUBDOMAIN")
        auth_token = os.environ.get("QUICKNODE_AUTH_TOKEN")

        if not subdomain or not auth_token:
            raise MissingAuthTokenError(DEFAULT_ENVIRONMENT_VARIABLE_NAMES)

        if (
            ecosystem_name not in QUICKNODE_NETWORKS
            or network_name not in QUICKNODE_NETWORKS[ecosystem_name]
        ):
            raise ProviderError(f"Unsupported network: {ecosystem_name} - {network_name}")

        uri_template = QUICKNODE_NETWORKS[ecosystem_name][network_name]
        uri = uri_template.format(subdomain=subdomain, auth_token=auth_token)
        self.network_uris[(ecosystem_name, network_name)] = uri
        return uri

    @property
    def http_uri(self) -> str:
        return self.uri

    @property
    def ws_uri(self) -> Optional[str]:
        ecosystem_name = self.network.ecosystem.name
        if ecosystem_name not in NETWORKS_SUPPORTING_WEBSOCKETS:
            return None

        # NOTE: Overriding `Web3Provider.ws_uri` implementation
        return "ws" + self.uri[4:]  # Remove `http` in default URI w/ `ws`

    @property
    def priority_fee(self) -> int:
        if self.network.ecosystem.name == "polygon-zkevm":
            raise APINotImplementedError()
        return super().priority_fee

    @property
    def connection_str(self) -> str:
        return self.uri

    def connect(self):
        self._web3 = Web3(HTTPProvider(self.uri))
        try:
            if self.network.ecosystem.name in ["optimism", "base", "polygon"]:
                self._web3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

            self._web3.eth.set_gas_price_strategy(rpc_gas_price_strategy)
        except Exception as err:
            raise ProviderError(f"Failed to connect to QuickNode.\n{repr(err)}") from err

    def disconnect(self):
        self._web3 = None

    def _get_prestate_trace(self, transaction_hash: str) -> dict:
        return self.make_request(
            "debug_traceTransaction", [transaction_hash, {"tracer": "prestateTracer"}]
        )

    def get_transaction_trace(self, transaction_hash: str, **kwargs) -> TraceAPI:
        if not transaction_hash.startswith("0x"):
            raise QuickNodeProviderError(
                "Transaction hash must be a hexadecimal string starting with '0x'"
            )

        return QuickNodeTransactionTrace(transaction_hash=transaction_hash, provider=self, **kwargs)

    def get_virtual_machine_error(self, exception: Exception, **kwargs) -> VirtualMachineError:
        txn = kwargs.get("txn")
        if not hasattr(exception, "args") or not len(exception.args):
            return VirtualMachineError(base_err=exception, txn=txn)

        args = exception.args
        message = args[0]
        if (
            not isinstance(exception, Web3ContractLogicError)
            and isinstance(message, dict)
            and "message" in message
        ):
            return VirtualMachineError(message["message"], txn=txn)

        elif not isinstance(message, str):
            return VirtualMachineError(base_err=exception, txn=txn)

        message_prefix = "execution reverted"
        if message.startswith(message_prefix):
            message = message.replace(message_prefix, "")

            if ":" in message:
                message = message.split(":")[-1].strip()
                return ContractLogicError(revert_message=message, txn=txn)
            else:
                return ContractLogicError(txn=txn)

        return VirtualMachineError(message=message, txn=txn)

    def create_access_list(
        self, transaction: TransactionAPI, block_id: Optional["BlockID"] = None
    ) -> list["AccessList"]:
        if self.network.ecosystem.name == "polygon-zkevm":
            raise APINotImplementedError()

        return super().create_access_list(transaction, block_id=block_id)

    def make_request(self, rpc: str, parameters: Optional["Iterable"] = None) -> Any:
        parameters = parameters or []
        try:
            result = self.web3.provider.make_request(RPCEndpoint(rpc), parameters)
        except HTTPError as err:
            response_data = err.response.json() if err.response else {}
            if "error" not in response_data:
                raise QuickNodeProviderError(str(err)) from err

            error_data = response_data["error"]
            message = (
                error_data.get("message", str(error_data))
                if isinstance(error_data, dict)
                else error_data
            )
            cls = (
                QuickNodeFeatureNotAvailable
                if "is not available" in message
                else QuickNodeProviderError
            )
            raise cls(message) from err

        return result["result"] if isinstance(result, dict) and "result" in result else result

    def send_private_transaction(self, txn: TransactionAPI, **kwargs) -> ReceiptAPI:
        """
        See `QuickNode's marketplace page
        <https://marketplace.quicknode.com/add-on/flashbots-protect>`__
        for more information on using the Flashbots add-on.
        For more information on the API itself, see its
        `REST reference <https://www.quicknode.com/docs/ethereum/eth_sendPrivateTransaction>`__.

        Args:
            txn: (:class:`~ape.api.transactionsTransactionAPI`): The transaction.
            **kwargs: Kwargs here are used for private-transaction "preferences".

        Returns:
            :class:`~ape.api.transactions.ReceiptAPI`
        """
        max_block_number = kwargs.pop("max_block_number", None)

        params: dict[str, Any] = {
            "tx": HexBytes(txn.serialize_transaction()).hex(),
        }
        if max_block_number:
            params["maxBlockNumber"] = max_block_number

        if kwargs:
            if "fast" not in kwargs:
                # If sending preferences, `fast` must be present.
                kwargs["fast"] = False
            params["preferences"] = kwargs

        try:
            txn_hash = self.make_request("eth_sendPrivateTransaction", [params])
        except (ValueError, Web3ContractLogicError) as err:
            vm_err = self.get_virtual_machine_error(err, txn=txn)
            raise vm_err from err

        # Since Flashbots will attempt to publish for 25 blocks,
        # we add 25 * block_time to the timeout.
        timeout = (
            PRIVATE_TX_BLOCK_WAIT * self.network.block_time
            + self.network.transaction_acceptance_timeout
        )

        receipt = self.get_receipt(
            txn_hash,
            required_confirmations=(
                txn.required_confirmations
                if txn.required_confirmations is not None
                else self.network.required_confirmations
            ),
            timeout=timeout,
        )
        logger.info(
            f"Confirmed {receipt.txn_hash} (private) (total fees paid = {receipt.total_fees_paid})"
        )
        self.chain_manager.history.append(receipt)
        return receipt

    def get_receipt(
        self,
        txn_hash: str,
        required_confirmations: int = 0,
        timeout: Optional[int] = None,
        **kwargs,
    ) -> ReceiptAPI:
        if not required_confirmations and not timeout:
            data = self.web3.eth.get_transaction_receipt(HexStr(txn_hash))
            txn = dict(self.web3.eth.get_transaction(HexStr(txn_hash)))
            return self.network.ecosystem.decode_receipt(
                {
                    "provider": self,
                    "required_confirmations": required_confirmations,
                    **txn,
                    **data,
                }
            )
        return super().get_receipt(
            txn_hash,
            required_confirmations=required_confirmations,
            timeout=timeout,
            **kwargs,
        )
