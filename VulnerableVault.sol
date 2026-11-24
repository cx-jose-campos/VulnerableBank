pragma solidity ^0.7.6;

/**
 * VulnerableVault.sol
 * ------------------------------------------------------------------
 * Intentionally vulnerable contract for SAST tool validation ONLY.
 * Do NOT deploy. Contains:
 *
 *  - CWE-477 / SWC-115: Authorization through tx.origin
 *      See: transferOwnership(), emergencyWithdraw()
 *  - CWE-284 / SWC-106: Unprotected SELFDESTRUCT
 *      See: destroy()
 *  - CWE-829 / SWC-112: Delegatecall to untrusted callee
 *      See: execute(), upgrade()
 *  - CWE-252 / SWC-104: Unchecked return value of low-level call / send
 *      See: payout(), refundAll()
 *  - CWE-400 / SWC-128: DoS with unbounded loop / block gas limit
 *      See: refundAll()
 *  - CWE-284 / SWC-105: Missing access control on sensitive setter
 *      See: setFeeCollector(), setWithdrawLimit()
 *  - CWE-798: Hard-coded credentials (secret in storage is public)
 *      See: adminPassword, adminLogin()
 * ------------------------------------------------------------------
 */
contract VulnerableVault {
    address public owner;
    address public feeCollector;
    address public implementation;
    uint256 public withdrawLimit = 1 ether;

    // "private" does not hide data on-chain; anyone can read storage.
    bytes32 private adminPassword = keccak256(abi.encodePacked("SuperSecret123!"));
    string private apiKey = "API-KEY-HARDCODED-1234567890";

    mapping(address => uint256) public deposits;
    address[] public depositors;

    event Deposited(address indexed user, uint256 amount);
    event Executed(address indexed target, bytes data);

    constructor() {
        owner = msg.sender;
        feeCollector = msg.sender;
    }

    // ---------------------------------------------------------------
    // tx.origin authorization (phishing via intermediary contract)
    // ---------------------------------------------------------------
    modifier onlyOwnerOrigin() {
        require(tx.origin == owner, "not owner"); // <-- should be msg.sender
        _;
    }

    function transferOwnership(address newOwner) external onlyOwnerOrigin {
        owner = newOwner;
    }

    function emergencyWithdraw(address payable to) external onlyOwnerOrigin {
        to.transfer(address(this).balance);
    }

    // ---------------------------------------------------------------
    // Hard-coded credential based login
    // ---------------------------------------------------------------
    function adminLogin(string calldata password) external {
        if (keccak256(abi.encodePacked(password)) == adminPassword) {
            owner = msg.sender; // anyone reading storage slot can become owner
        }
    }

    // ---------------------------------------------------------------
    // Deposits
    // ---------------------------------------------------------------
    function deposit() external payable {
        if (deposits[msg.sender] == 0) {
            depositors.push(msg.sender); // unbounded growth
        }
        deposits[msg.sender] += msg.value; // unchecked (pre-0.8)
        emit Deposited(msg.sender, msg.value);
    }

    // ---------------------------------------------------------------
    // Unchecked return values
    // ---------------------------------------------------------------
    function payout(address payable to, uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        require(amount <= withdrawLimit, "limit");
        deposits[msg.sender] -= amount;
        to.send(amount);                       // <-- return value ignored
        feeCollector.call{value: amount / 100}(""); // <-- return value ignored
    }

    // ---------------------------------------------------------------
    // DoS: unbounded loop over attacker-growable array + unchecked send
    // ---------------------------------------------------------------
    function refundAll() external {
        for (uint256 i = 0; i < depositors.length; i++) {
            address payable user = payable(depositors[i]);
            uint256 amt = deposits[user];
            deposits[user] = 0;
            user.send(amt); // <-- ignored failure; funds silently lost
        }
    }

    // ---------------------------------------------------------------
    // Missing access control
    // ---------------------------------------------------------------
    function setFeeCollector(address newCollector) external {
        feeCollector = newCollector; // anyone can redirect fees
    }

    function setWithdrawLimit(uint256 newLimit) external {
        withdrawLimit = newLimit; // anyone can lift the limit
    }

    // ---------------------------------------------------------------
    // Delegatecall to user-supplied address
    // ---------------------------------------------------------------
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data); // <-- arbitrary storage write
        require(ok, "delegatecall failed");
        emit Executed(target, data);
        return ret;
    }

    function upgrade(address newImpl) external {
        implementation = newImpl; // no access control
    }

    fallback() external payable {
        // Forwards every unknown call to an attacker-settable implementation
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }

    receive() external payable {}

    // ---------------------------------------------------------------
    // Unprotected selfdestruct
    // ---------------------------------------------------------------
    function destroy(address payable recipient) external {
        selfdestruct(recipient); // <-- anyone can kill the contract
    }
}
