// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";

/// @title OracleGate
/// @notice Users sign a ForwardRequest (any target, any calldata) and hand it to Croft.
///         The oracle simulates and scores the whole transaction; only if it is judged safe does the
///         oracle's relayer submit it here. While the request executes, a transient flag marks the
///         transaction as gated, so protected protocols (see `Gated`) accept calls anywhere inside it,
///         including from the user's own contracts, and reject every transaction that skipped the oracle.
/// @dev The sender is appended to calldata (ERC-2771) so gated targets called directly can recover the
///      signer; other targets ignore the trailing 20 bytes.
contract OracleGate is EIP712, Nonces {
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 nonce;
        uint48 deadline;
        bytes data;
    }

    bytes32 public constant FORWARD_REQUEST_TYPEHASH = keccak256(
        "ForwardRequest(address from,address to,uint256 value,uint256 nonce,uint48 deadline,bytes data)"
    );

    bytes32 private constant ACTIVE_SLOT = keccak256("security-oracle.gate.active");

    address public immutable relayer;

    event Forwarded(address indexed from, address indexed to, uint256 nonce, bool success);

    error NotRelayer();
    error Expired();
    error BadValue();
    error BadSignature();
    error Reentered();

    constructor(address relayer_) EIP712("OracleGate", "1") {
        relayer = relayer_;
    }

    /// @notice Execute a request the oracle approved. Only the oracle relayer may call this.
    function execute(ForwardRequest calldata req, bytes calldata signature)
        external
        payable
        returns (bytes memory result)
    {
        if (msg.sender != relayer) revert NotRelayer();
        if (block.timestamp > req.deadline) revert Expired();
        if (msg.value != req.value) revert BadValue();
        if (ECDSA.recover(_hashTypedDataV4(hashRequest(req)), signature) != req.from) revert BadSignature();
        _useCheckedNonce(req.from, req.nonce);
        if (isGated()) revert Reentered();

        _setActive(true);
        (bool ok, bytes memory ret) = req.to.call{value: req.value}(abi.encodePacked(req.data, req.from));
        _setActive(false);

        emit Forwarded(req.from, req.to, req.nonce, ok);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        return ret;
    }

    /// @notice True only while an oracle-approved request is executing in this transaction.
    function isGated() public view returns (bool active) {
        bytes32 slot = ACTIVE_SLOT;
        assembly {
            active := tload(slot)
        }
    }

    function hashRequest(ForwardRequest calldata req) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                FORWARD_REQUEST_TYPEHASH, req.from, req.to, req.value, req.nonce, req.deadline, keccak256(req.data)
            )
        );
    }

    function digest(ForwardRequest calldata req) external view returns (bytes32) {
        return _hashTypedDataV4(hashRequest(req));
    }

    function _setActive(bool active) private {
        bytes32 slot = ACTIVE_SLOT;
        assembly {
            tstore(slot, active)
        }
    }
}

interface IOracleGate {
    function isGated() external view returns (bool);
}

/// @notice Inherit to put a protocol behind Croft.
abstract contract Gated {
    IOracleGate public immutable gate;

    error NotGated();

    constructor(address gate_) {
        gate = IOracleGate(gate_);
    }

    modifier onlyGated() {
        if (!gate.isGated()) revert NotGated();
        _;
    }

    /// @dev ERC-2771: when the gate calls us directly, the real sender is appended to calldata.
    function _msgSender() internal view virtual returns (address) {
        if (msg.sender == address(gate) && msg.data.length >= 20) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        }
        return msg.sender;
    }
}
