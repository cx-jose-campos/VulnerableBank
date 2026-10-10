pragma solidity ^0.7.6;
// NOTE: pragma <0.8.0 intentionally chosen so arithmetic is NOT checked by
// default (Solidity 0.8+ reverts on over/underflow automatically, which
// would mask CWE-190 for this test case).

/**
 * VulnerableBank.sol
 * ------------------------------------------------------------------
 * Intentionally vulnerable contract for SAST tool validation ONLY.
 * Do NOT deploy. Contains:
 *
 *  - CWE-190: Integer Overflow or Wraparound
 *      See: deposit(), batchCredit()
 *  - CWE-362: Concurrent Execution using Shared Resource with
 *             Improper Synchronization ("Race Condition" / reentrancy)
 *      See: withdraw()
 * ------------------------------------------------------------------
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    // ---------------------------------------------------------------
    // CWE-190: Integer Overflow / Wraparound
    // ---------------------------------------------------------------
    // `amount` is attacker-controlled. On Solidity <0.8.0 there is no
    // automatic overflow check, so balances[msg.sender] + amount can
    // wrap around past type(uint256).max, and totalSupply can overflow
    // independently of the per-user balance, letting an attacker
    // mint an artificially large or wrapped-to-small balance.
    function deposit(uint256 amount) external payable {
        balances[msg.sender] += amount;   // <-- unchecked addition
        totalSupply += amount;            // <-- unchecked addition
        emit Deposit(msg.sender, amount);
    }

    // A second, more direct overflow sink: crediting multiple accounts
    // in a loop with a user-supplied amount multiplied by count.
    function batchCredit(address[] calldata users, uint256 amountEach) external {
        uint256 total = amountEach * users.length; // <-- unchecked multiplication
        require(balances[msg.sender] >= total, "insufficient");
        balances[msg.sender] -= total;             // <-- unchecked subtraction (also underflow-prone)
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] += amountEach;      // <-- unchecked addition
        }
    }

    // ---------------------------------------------------------------
    // CWE-362: Race Condition (classic reentrancy / TOCTOU)
    // ---------------------------------------------------------------
    // The external call to msg.sender happens BEFORE the balance is
    // zeroed out. A malicious contract's fallback/receive function can
    // re-enter withdraw() while the first call is still mid-execution,
    // observing the stale (pre-update) balance and draining funds
    // before state is synchronized -- a textbook check-then-act race
    // on the shared `balances` mapping.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance"); // CHECK
        (bool success, ) = msg.sender.call{value: amount}("");           // ACT (external call)
        require(success, "transfer failed");
        balances[msg.sender] -= amount;                                  // STATE UPDATE (too late)
        emit Withdraw(msg.sender, amount);
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
