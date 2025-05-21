import pytest
from ape.api import TraceAPI
from ape.exceptions import ContractLogicError, ProviderError, VirtualMachineError
from ape.types import LogFilter
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import ContractLogicError as Web3ContractLogicError

from ape_quicknode.exceptions import MissingAuthTokenError, QuickNodeProviderError
from ape_quicknode.trace import QuickNodeTransactionTrace

TXN_HASH = "0x3cef4aaa52b97b6b61aa32b3afcecb0d14f7862ca80fdc76504c37a9374645c4"


@pytest.fixture
def log_filter():
    return LogFilter(
        address=["0xF7F78379391C5dF2Db5B66616d18fF92edB82022"],
        fromBlock="0x3",
        toBlock="0x3",
        topics=[
            "0x1a7c56fae0af54ebae73bc4699b9de9835e7bb86b050dff7e80695b633f17abd",
            [
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            ],
        ],
    )


@pytest.fixture
def block():
    return {
        "transactions": [],
        "hash": HexBytes("0xae1960ba0513948a507b652def457305d490d24bc0dd131d8d02be56564a3ee2"),
        "number": 0,
        "parentHash": HexBytes(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ),
        "size": 517,
        "timestamp": 1660338772,
        "gasLimit": 30029122,
        "gasUsed": 0,
        "baseFeePerGas": 1000000000,
        "difficulty": 131072,
        "totalDifficulty": 131072,
    }


@pytest.fixture
def receipt():
    return {
        "blockNumber": 15329094,
        "data": b"0xa9059cbb00000000000000000000000016b308eb4591d9b4e34034ca2ff992d224b9927200000000000000000000000000000000000000000000000000000000030a32c0",
        "gasLimit": 79396,
        "gasPrice": 14200000000,
        "gasUsed": 65625,
        "logs": [
            {
                "blockHash": HexBytes(
                    "0x141a61b8c738c0f1508728116049a0d4a6ff41ee1180d956148880f32ae99215"
                ),
                "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "logIndex": 213,
                "data": HexBytes(
                    "0x00000000000000000000000000000000000000000000000000000000030a32c0"
                ),
                "removed": False,
                "topics": [
                    HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
                    HexBytes("0x000000000000000000000000958f973513f723f2cb9b47abe5e903695ab93e36"),
                    HexBytes("0x00000000000000000000000016b308eb4591d9b4e34034ca2ff992d224b99272"),
                ],
                "blockNumber": 15329094,
                "transactionIndex": 132,
                "transactionHash": HexBytes(
                    "0x9e4be62c1a16caacaccd9d8c7706b75dc17a957ec6c5dea418a137a5c3a197c5"
                ),
            }
        ],
        "nonce": 16,
        "receiver": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "sender": "0x958f973513F723f2cB9b47AbE5e903695aB93e36",
        "status": 1,
        "hash": TXN_HASH,
        "value": 0,
    }


@pytest.fixture
def mock_transaction_api(mocker):
    mock = mocker.MagicMock()
    mock.signature = "0x123abc"
    mock.serialize_transaction.return_value = "123abc"
    mock.max_fee = None
    mock.max_priority_fee = None
    mock.max_block_number = None
    mock.required_confirmations = 1
    return mock


@pytest.fixture
def mock_receipt_api(mocker):
    mock = mocker.MagicMock()
    mock.transaction_hash = TXN_HASH
    return mock


@pytest.fixture
def mock_web3(mocker):
    mock = mocker.MagicMock() # Keep it simple, or use spec=True if strictness is needed later

    # Explicitly create mock.eth and mock.provider as MagicMocks
    mock.eth = mocker.MagicMock()
    mock.provider = mocker.MagicMock()

    def make_request_side_effect(rpc_method, params):
        if rpc_method == "eth_sendPrivateTransaction":
            return TXN_HASH
        elif rpc_method == "eth_chainId":
            return "0x1"  # Example chain ID
        elif rpc_method == "eth_getTransactionReceipt":
            return { 
                "blockHash": "0x" + "0"*64,
                "blockNumber": 1,
                "contractAddress": None,
                "cumulativeGasUsed": 100000,
                "from": "0x" + "1"*40,
                "gasUsed": 50000,
                "logs": [],
                "logsBloom": "0x" + "0"*512,
                "status": 1,
                "to": "0x" + "2"*40,
                "transactionHash": params[0] if params and params[0] else TXN_HASH, 
                "transactionIndex": 0,
            }
        elif rpc_method == "eth_getTransactionByHash":
             return { 
                "blockHash": "0x" + "0"*64,
                "blockNumber": 1,
                "from": "0x" + "1"*40,
                "gas": 21000,
                "gasPrice": 10**10,
                "hash": params[0] if params and params[0] else TXN_HASH,
                "input": "0x",
                "nonce": 0,
                "to": "0x" + "2"*40,
                "transactionIndex": 0,
                "value": 0,
                "type": "0x0",
                "v": 27,
                "r": "0x" + "f"*64,
                "s": "0x" + "f"*64,
            }
        elif rpc_method == "eth_blockNumber": # Added for tests like test_get_transaction_trace
            return 12345 # Example block number
        elif rpc_method == "debug_traceTransaction": # Added for test_get_transaction_trace
            return {
                "output": "0x",
                "gasUsed": "0x5208",
                "revertReason": None,
            }
        elif rpc_method == "eth_estimateGas": # Added for estimate_gas tests
            return 100000 # Example gas estimate
        elif rpc_method == "eth_sendRawTransaction": # Added for send_transaction tests
             return TXN_HASH
        elif rpc_method == "eth_getLogs": # Added for test_get_contract_logs
            return []
        elif rpc_method == "eth_getBlockByNumber": # Added for test_get_contract_logs
            return { # Return a mock block similar to the block fixture
                "transactions": [],
                "hash": HexBytes("0xae1960ba0513948a507b652def457305d490d24bc0dd131d8d02be56564a3ee2"),
                "number": 0,
                "parentHash": HexBytes(
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                ),
                "size": 517,
                "timestamp": 1660338772,
                "gasLimit": 30029122,
                "gasUsed": 0,
                "baseFeePerGas": 1000000000,
                "difficulty": 131072,
                "totalDifficulty": 131072,
            }

        raise NotImplementedError(f"Mocked make_request not implemented for {rpc_method} with params {params}")

    mock.provider.make_request.side_effect = make_request_side_effect
    mock.eth.block_number = 12345  # Set block_number on the eth mock
    mock.eth.chain_id = 1      # Set chain_id on the eth mock
    mock.eth.estimate_gas.side_effect = lambda txn: mock.provider.make_request("eth_estimateGas", [txn])
    mock.eth.send_raw_transaction.side_effect = lambda txn_bytes: mock.provider.make_request("eth_sendRawTransaction", [txn_bytes])
    mock.eth.get_block.side_effect = lambda block_identifier, full_transactions=False: mock.provider.make_request("eth_getBlockByNumber" if block_identifier != "latest" else "eth_getBlockByNumber", [block_identifier, full_transactions])
    mock.eth.get_logs.side_effect = lambda log_filter: mock.provider.make_request("eth_getLogs", [log_filter])
    mock.eth.wait_for_transaction_receipt.side_effect = lambda tx_hash, timeout=None, poll_latency=None: mock.provider.make_request("eth_getTransactionReceipt", [tx_hash])

    return mock


def test_when_no_auth_token_raises_error(missing_token, quicknode_provider):
    with pytest.raises(MissingAuthTokenError) as excinfo:
        quicknode_provider.connect()
    assert "QUICKNODE_SUBDOMAIN" in str(excinfo.value)
    assert "QUICKNODE_AUTH_TOKEN" in str(excinfo.value)


def test_send_transaction_reverts(token, quicknode_provider, mock_web3, transaction):
    expected_revert_message = "EXPECTED REVERT MESSAGE"
    mock_web3.eth.send_raw_transaction.side_effect = Web3ContractLogicError(
        f"execution reverted : {expected_revert_message}"
    )
    quicknode_provider._web3 = mock_web3

    with pytest.raises(ContractLogicError, match=expected_revert_message):
        quicknode_provider.send_transaction(transaction)


def test_send_transaction_reverts_no_message(token, quicknode_provider, mock_web3, transaction):
    mock_web3.eth.send_raw_transaction.side_effect = Web3ContractLogicError("execution reverted")
    quicknode_provider._web3 = mock_web3

    with pytest.raises(ContractLogicError, match="Transaction failed."):
        quicknode_provider.send_transaction(transaction)


def test_estimate_gas_would_revert(token, quicknode_provider, mock_web3, transaction):
    expected_revert_message = "EXPECTED REVERT MESSAGE"
    mock_web3.eth.estimate_gas.side_effect = Web3ContractLogicError(
        f"execution reverted : {expected_revert_message}"
    )
    quicknode_provider._web3 = mock_web3

    with pytest.raises(ContractLogicError, match=expected_revert_message):
        quicknode_provider.estimate_gas_cost(transaction)


def test_estimate_gas_would_revert_no_message(token, quicknode_provider, mock_web3, transaction):
    mock_web3.eth.estimate_gas.side_effect = Web3ContractLogicError("execution reverted")
    quicknode_provider._web3 = mock_web3

    with pytest.raises(ContractLogicError, match="Transaction failed."):
        quicknode_provider.estimate_gas_cost(transaction)


def test_get_contract_logs(networks, quicknode_provider, mock_web3, block, log_filter):
    _ = quicknode_provider.chain_id  # Make sure this has been called _before_ setting mock.
    mock_web3.eth.get_block.return_value = block
    quicknode_provider._web3 = mock_web3
    networks.active_provider = quicknode_provider
    actual = [x for x in quicknode_provider.get_contract_logs(log_filter)]

    assert actual == []


def test_unsupported_network(quicknode_provider, monkeypatch):
    monkeypatch.setenv("QUICKNODE_SUBDOMAIN", "test_subdomain")
    monkeypatch.setenv("QUICKNODE_AUTH_TOKEN", "test_token")
    quicknode_provider.network.ecosystem.name = "unsupported_ecosystem"
    quicknode_provider.network.name = "unsupported_network"

    with pytest.raises(ProviderError, match="Unsupported network:"):
        quicknode_provider.uri


def test_quicknode_provider_error(quicknode_provider, mock_web3):
    error_message = "QuickNode API error"
    mock_web3.provider.make_request.side_effect = QuickNodeProviderError(error_message)
    quicknode_provider._web3 = mock_web3

    with pytest.raises(QuickNodeProviderError, match=error_message):
        quicknode_provider.make_request("eth_blockNumber", [])


def test_get_transaction_trace(networks, quicknode_provider, mock_web3, receipt):
    tx_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    mock_trace_data = {
        "output": "0x",
        "gasUsed": "0x5208",
        "revertReason": None,
    }
    mock_web3.provider.make_request.return_value = mock_trace_data
    mock_web3.eth.wait_for_transaction_receipt.return_value = receipt
    quicknode_provider._web3 = mock_web3
    networks.active_provider = quicknode_provider

    trace = quicknode_provider.get_transaction_trace(tx_hash)

    assert isinstance(trace, QuickNodeTransactionTrace)
    assert isinstance(trace, TraceAPI)
    assert trace.transaction_hash == tx_hash


def test_send_private_transaction_success_no_preferences(
    token, quicknode_provider, mock_web3, mock_transaction_api, mock_receipt_api, mocker
):
    # mock_web3.provider.make_request.return_value = TXN_HASH # Now handled by side_effect
    quicknode_provider._web3 = mock_web3
    mock_get_receipt = mocker.patch("ape_quicknode.provider.QuickNode.get_receipt", return_value=mock_receipt_api)
    # Mock chain_manager.history.append to prevent it from actually appending and triggering chain_id access
    mocker.patch.object(quicknode_provider.chain_manager.history, "append")

    tx_receipt = quicknode_provider.send_private_transaction(mock_transaction_api)

    assert tx_receipt.transaction_hash == TXN_HASH
    # Ensure the correct call to eth_sendPrivateTransaction
    private_tx_call = next(c for c in mock_web3.provider.make_request.call_args_list if c[0][0] == "eth_sendPrivateTransaction")
    assert private_tx_call[0][0] == "eth_sendPrivateTransaction"
    assert private_tx_call[0][1] == [{"tx": "123abc"}]

    expected_timeout = 25 * quicknode_provider.network.block_time + quicknode_provider.network.transaction_acceptance_timeout
    mock_get_receipt.assert_called_once_with(TXN_HASH, required_confirmations=1, timeout=expected_timeout)
    quicknode_provider.chain_manager.history.append.assert_called_once_with(mock_receipt_api)


def test_send_private_transaction_success_with_preferences_fast_true(
    token, quicknode_provider, mock_web3, mock_transaction_api, mock_receipt_api, mocker
):
    # mock_web3.provider.make_request.return_value = TXN_HASH # Now handled by side_effect
    quicknode_provider._web3 = mock_web3
    mock_get_receipt = mocker.patch("ape_quicknode.provider.QuickNode.get_receipt", return_value=mock_receipt_api)
    mocker.patch.object(quicknode_provider.chain_manager.history, "append")

    preferences = {"fast": True}
    tx_receipt = quicknode_provider.send_private_transaction(
        mock_transaction_api, **preferences
    )

    assert tx_receipt.transaction_hash == TXN_HASH
    private_tx_call = next(c for c in mock_web3.provider.make_request.call_args_list if c[0][0] == "eth_sendPrivateTransaction")
    assert private_tx_call[0][0] == "eth_sendPrivateTransaction"
    assert private_tx_call[0][1] == [{"tx": "123abc", "preferences": preferences}]

    expected_timeout = 25 * quicknode_provider.network.block_time + quicknode_provider.network.transaction_acceptance_timeout
    mock_get_receipt.assert_called_once_with(TXN_HASH, required_confirmations=1, timeout=expected_timeout)
    quicknode_provider.chain_manager.history.append.assert_called_once_with(mock_receipt_api)

def test_send_private_transaction_with_max_block_number(
    token, quicknode_provider, mock_web3, mock_transaction_api, mock_receipt_api, mocker
):
    # mock_web3.provider.make_request.return_value = TXN_HASH # Now handled by side_effect
    quicknode_provider._web3 = mock_web3
    mock_get_receipt = mocker.patch("ape_quicknode.provider.QuickNode.get_receipt", return_value=mock_receipt_api)
    mocker.patch.object(quicknode_provider.chain_manager.history, "append")

    tx_receipt = quicknode_provider.send_private_transaction(mock_transaction_api, max_block_number="0x3039")

    assert tx_receipt.transaction_hash == TXN_HASH
    private_tx_call = next(c for c in mock_web3.provider.make_request.call_args_list if c[0][0] == "eth_sendPrivateTransaction")
    assert private_tx_call[0][0] == "eth_sendPrivateTransaction"
    assert private_tx_call[0][1] == [{"tx": "123abc", "maxBlockNumber": "0x3039"}]

    expected_timeout = 25 * quicknode_provider.network.block_time + quicknode_provider.network.transaction_acceptance_timeout
    mock_get_receipt.assert_called_once_with(TXN_HASH, required_confirmations=1, timeout=expected_timeout)
    quicknode_provider.chain_manager.history.append.assert_called_once_with(mock_receipt_api)


def test_send_private_transaction_value_error(
    token, quicknode_provider, mock_web3, mock_transaction_api
):
    # Configure make_request to specifically raise ValueError for eth_sendPrivateTransaction
    def value_error_side_effect(rpc_method, params):
        if rpc_method == "eth_sendPrivateTransaction":
            raise ValueError("Invalid params")
        elif rpc_method == "eth_chainId":
            return "0x1"
        raise NotImplementedError(f"Mocked make_request not implemented for {rpc_method}")
    mock_web3.provider.make_request.side_effect = value_error_side_effect
    quicknode_provider._web3 = mock_web3

    with pytest.raises(VirtualMachineError) as excinfo:
        quicknode_provider.send_private_transaction(mock_transaction_api)
    assert "Invalid params" in str(excinfo.value)


def test_send_private_transaction_contract_logic_error(
    token, quicknode_provider, mock_web3, mock_transaction_api
):
    revert_message = "Execution reverted by contract"
    # Configure make_request to specifically raise Web3ContractLogicError for eth_sendPrivateTransaction
    def contract_logic_error_side_effect(rpc_method, params):
        if rpc_method == "eth_sendPrivateTransaction":
            raise Web3ContractLogicError(f"execution reverted: {revert_message}")
        elif rpc_method == "eth_chainId":
            return "0x1"
        raise NotImplementedError(f"Mocked make_request not implemented for {rpc_method}")
    mock_web3.provider.make_request.side_effect = contract_logic_error_side_effect
    quicknode_provider._web3 = mock_web3

    with pytest.raises(ContractLogicError, match=revert_message):
        quicknode_provider.send_private_transaction(mock_transaction_api)
