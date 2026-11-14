// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Gated} from "../OracleGate.sol";

/// Demo-only token: anyone can mint.
contract MockToken is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// Constant-product pool for COL/USD with a 0.3% fee. Its spot price is (deliberately) used as the
/// lending pool's oracle, the classic flash-loan price-manipulation setup.
contract SimpleAMM {
    IERC20 public immutable col;
    IERC20 public immutable usd;
    uint256 public reserveCol;
    uint256 public reserveUsd;

    event Swap(address indexed sender, address indexed tokenIn, uint256 amountIn, uint256 amountOut, address to);
    event Sync(uint256 reserveCol, uint256 reserveUsd);

    constructor(IERC20 col_, IERC20 usd_) {
        col = col_;
        usd = usd_;
    }

    /// @notice USD per COL, 1e18-scaled.
    function spotPrice() public view returns (uint256) {
        return reserveUsd * 1e18 / reserveCol;
    }

    function getAmountOut(address tokenIn, uint256 amountIn) public view returns (uint256) {
        (uint256 rIn, uint256 rOut) = tokenIn == address(col) ? (reserveCol, reserveUsd) : (reserveUsd, reserveCol);
        uint256 inWithFee = amountIn * 997;
        return inWithFee * rOut / (rIn * 1000 + inWithFee);
    }

    /// @notice Input needed to receive `amountOut` of the other token.
    function getAmountIn(address tokenIn, uint256 amountOut) public view returns (uint256) {
        (uint256 rIn, uint256 rOut) = tokenIn == address(col) ? (reserveCol, reserveUsd) : (reserveUsd, reserveCol);
        return rIn * amountOut * 1000 / ((rOut - amountOut) * 997) + 1;
    }

    function swap(address tokenIn, uint256 amountIn, uint256 minOut, address to) external returns (uint256 out) {
        require(tokenIn == address(col) || tokenIn == address(usd), "bad token");
        out = getAmountOut(tokenIn, amountIn);
        require(out >= minOut, "slippage");
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        (tokenIn == address(col) ? usd : col).transfer(to, out);
        _sync();
        emit Swap(msg.sender, tokenIn, amountIn, out, to);
    }

    /// @notice Reserves follow balances; liquidity is added by transferring tokens in, then syncing.
    function sync() external {
        _sync();
    }

    function _sync() private {
        reserveCol = col.balanceOf(address(this));
        reserveUsd = usd.balanceOf(address(this));
        emit Sync(reserveCol, reserveUsd);
    }
}

interface IFlashBorrower {
    function onFlashLoan(IERC20 token, uint256 amount, bytes calldata data) external;
}

/// Zero-fee flash lender (stands in for Aave/Balancer).
contract FlashLender {
    event FlashLoan(address indexed borrower, address indexed token, uint256 amount);

    function flashLoan(IERC20 token, uint256 amount, bytes calldata data) external {
        uint256 before = token.balanceOf(address(this));
        token.transfer(msg.sender, amount);
        IFlashBorrower(msg.sender).onFlashLoan(token, amount, data);
        require(token.balanceOf(address(this)) >= before, "flash loan not repaid");
        emit FlashLoan(msg.sender, address(token), amount);
    }
}

/// Over-collateralized lending: deposit COL, borrow USD up to 80% LTV. Vulnerable on purpose: it
/// prices collateral with the AMM's spot price. Every state-changing entry point is gated.
contract LendingPool is Gated {
    IERC20 public immutable col;
    IERC20 public immutable usd;
    SimpleAMM public immutable amm;
    uint256 public constant LTV_BPS = 8000;

    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    event Deposit(address indexed account, uint256 amount);
    event Borrow(address indexed account, uint256 amount);
    event Repay(address indexed account, uint256 amount);
    event Withdraw(address indexed account, uint256 amount);

    constructor(address gate_, IERC20 col_, IERC20 usd_, SimpleAMM amm_) Gated(gate_) {
        col = col_;
        usd = usd_;
        amm = amm_;
    }

    function price() public view returns (uint256) {
        return amm.spotPrice();
    }

    function maxBorrow(address account) public view returns (uint256) {
        return collateralOf[account] * price() / 1e18 * LTV_BPS / 10_000;
    }

    function depositCollateral(uint256 amount) external onlyGated {
        address account = _msgSender();
        col.transferFrom(account, address(this), amount);
        collateralOf[account] += amount;
        emit Deposit(account, amount);
    }

    function borrow(uint256 amount) external onlyGated {
        address account = _msgSender();
        debtOf[account] += amount;
        require(debtOf[account] <= maxBorrow(account), "undercollateralized");
        usd.transfer(account, amount);
        emit Borrow(account, amount);
    }

    function repay(uint256 amount) external onlyGated {
        address account = _msgSender();
        usd.transferFrom(account, address(this), amount);
        debtOf[account] -= amount;
        emit Repay(account, amount);
    }

    function withdrawCollateral(uint256 amount) external onlyGated {
        address account = _msgSender();
        collateralOf[account] -= amount;
        require(debtOf[account] <= maxBorrow(account), "undercollateralized");
        col.transfer(account, amount);
        emit Withdraw(account, amount);
    }
}
