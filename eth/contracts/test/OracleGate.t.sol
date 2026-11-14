// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {OracleGate, Gated} from "../src/OracleGate.sol";
import {MockToken, SimpleAMM, FlashLender, LendingPool} from "../src/demo/Protocol.sol";
import {Exploiter, Strategy} from "../src/demo/Strategies.sol";

contract OracleGateTest is Test {
    OracleGate gate;
    MockToken col;
    MockToken usd;
    SimpleAMM amm;
    FlashLender lender;
    LendingPool pool;

    address relayer = makeAddr("relayer");
    uint256 aliceKey = 0xA11CE;
    address alice = vm.addr(aliceKey);
    uint256 attackerKey = 0xBAD;
    address attacker = vm.addr(attackerKey);

    function setUp() public {
        gate = new OracleGate(relayer);
        col = new MockToken("Collateral", "COL");
        usd = new MockToken("US Dollar", "USD");
        amm = new SimpleAMM(col, usd);
        lender = new FlashLender();
        pool = new LendingPool(address(gate), col, usd, amm);

        col.mint(address(amm), 1_000e18);
        usd.mint(address(amm), 2_000_000e18); // COL = $2,000
        amm.sync();
        usd.mint(address(lender), 10_000_000e18);
        usd.mint(address(pool), 3_000_000e18);
    }

    function _forward(uint256 key, address to, bytes memory data) internal {
        address from = vm.addr(key);
        OracleGate.ForwardRequest memory req = OracleGate.ForwardRequest({
            from: from, to: to, value: 0, nonce: gate.nonces(from), deadline: uint48(block.timestamp + 60), data: data
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, gate.digest(req));
        vm.prank(relayer);
        gate.execute(req, abi.encodePacked(r, s, v));
    }

    function test_directCallRejected() public {
        vm.prank(alice);
        vm.expectRevert(Gated.NotGated.selector);
        pool.borrow(1);
    }

    function test_onlyRelayerCanExecute() public {
        OracleGate.ForwardRequest memory req = OracleGate.ForwardRequest({
            from: alice, to: address(pool), value: 0, nonce: 0, deadline: uint48(block.timestamp + 60), data: ""
        });
        vm.expectRevert(OracleGate.NotRelayer.selector);
        gate.execute(req, "");
    }

    function test_gatedDepositAndBorrowUseSigner() public {
        col.mint(alice, 10e18);
        vm.prank(alice);
        col.approve(address(pool), type(uint256).max);
        _forward(aliceKey, address(pool), abi.encodeCall(LendingPool.depositCollateral, (10e18)));
        _forward(aliceKey, address(pool), abi.encodeCall(LendingPool.borrow, (8_000e18)));
        assertEq(pool.collateralOf(alice), 10e18);
        assertEq(usd.balanceOf(alice), 8_000e18);
        assertFalse(gate.isGated());
    }

    function test_replayRejected() public {
        col.mint(alice, 10e18);
        vm.prank(alice);
        col.approve(address(pool), type(uint256).max);
        OracleGate.ForwardRequest memory req = OracleGate.ForwardRequest({
            from: alice, to: address(pool), value: 0, nonce: 0, deadline: uint48(block.timestamp + 60),
            data: abi.encodeCall(LendingPool.depositCollateral, (1e18))
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, gate.digest(req));
        vm.startPrank(relayer);
        gate.execute(req, abi.encodePacked(r, s, v));
        vm.expectRevert();
        gate.execute(req, abi.encodePacked(r, s, v));
        vm.stopPrank();
    }

    function test_exploitDrainsPoolWhenApproved() public {
        vm.prank(attacker);
        Exploiter ex = new Exploiter(pool, lender);
        col.mint(address(ex), 100e18);

        // without the gate the attack cannot even run
        vm.prank(attacker);
        vm.expectRevert();
        ex.attack(6_000_000e18, 100e18, 10_000, 1, true);

        uint256 poolBefore = usd.balanceOf(address(pool));
        _forward(attackerKey, address(ex), abi.encodeCall(Exploiter.attack, (6_000_000e18, 100e18, 10_000, 1, true)));
        uint256 stolen = poolBefore - usd.balanceOf(address(pool));
        assertGt(stolen, 2_000_000e18, "pool drained");
        assertGt(usd.balanceOf(attacker), 2_000_000e18, "attacker profits");
    }

    function test_benignStrategiesRunThroughGate() public {
        vm.prank(alice);
        Strategy st = new Strategy(pool, lender);
        usd.mint(address(st), 200_000e18);
        _forward(aliceKey, address(st), abi.encodeCall(Strategy.zap, (100_000e18, 5_000)));
        assertGt(pool.debtOf(address(st)), 0);
        _forward(aliceKey, address(st), abi.encodeCall(Strategy.deleverage, ()));
        assertEq(pool.debtOf(address(st)), 0);
    }
}
