pragma solidity ^0.7.6;

/**
 * VulnerableLottery.sol
 * ------------------------------------------------------------------
 * Intentionally vulnerable contract for SAST tool validation ONLY.
 * Do NOT deploy. Contains:
 *
 *  - CWE-330 / SWC-120: Weak sources of randomness from chain attributes
 *      See: draw(), luckyNumber()
 *  - CWE-829 / SWC-116: Block timestamp dependence
 *      See: buyTicket(), draw()
 *  - CWE-362 / SWC-114: Transaction order dependence (front-running)
 *      See: submitAnswer(), setPrize()
 *  - CWE-347 / SWC-117/121: Signature malleability & replay
 *      See: claimWithSignature()
 *  - CWE-682: Incorrect calculation (division before multiplication)
 *      See: payoutShare()
 *  - CWE-400 / SWC-113: DoS with failed call (push payment)
 *      See: bid()
 *  - CWE-665 / SWC-109: Uninitialized / dangling state assumptions
 *      See: initialize()
 * ------------------------------------------------------------------
 */
contract VulnerableLottery {
    address public owner;
    bool public initialized;

    address[] public players;
    uint256 public ticketPrice = 0.1 ether;
    uint256 public roundEnd;
    uint256 public prize;

    // puzzle / front-running
    bytes32 public answerHash;
    uint256 public puzzleReward;

    // auction / push-payment DoS
    address payable public highestBidder;
    uint256 public highestBid;

    address public signer;
    mapping(address => uint256) public claimed;

    event Winner(address indexed player, uint256 amount);

    // ---------------------------------------------------------------
    // Re-initializable "constructor" (anyone can call, multiple times)
    // ---------------------------------------------------------------
    function initialize(address _signer) external {
        // missing: require(!initialized)
        owner = msg.sender;
        signer = _signer;
        roundEnd = block.timestamp + 1 days;
        initialized = true;
    }

    // ---------------------------------------------------------------
    // Timestamp dependence
    // ---------------------------------------------------------------
    function buyTicket() external payable {
        require(msg.value == ticketPrice, "wrong price");
        require(block.timestamp < roundEnd, "round over"); // miner-adjustable
        players.push(msg.sender);
        prize += msg.value;
    }

    // ---------------------------------------------------------------
    // Weak randomness: predictable / miner-influenced
    // ---------------------------------------------------------------
    function draw() external {
        require(block.timestamp >= roundEnd, "not yet");
        require(players.length > 0, "no players");

        uint256 rand = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.difficulty, blockhash(block.number - 1), players.length))
        );
        address winner = players[rand % players.length];

        uint256 amount = prize;
        prize = 0;
        delete players;
        roundEnd = block.timestamp + 1 days;

        payable(winner).transfer(amount);
        emit Winner(winner, amount);
    }

    function luckyNumber() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100; // predictable
    }

    function instantWin() external payable {
        require(msg.value == 0.05 ether, "pay 0.05");
        if (luckyNumber() == 7) {
            msg.sender.transfer(address(this).balance);
        }
    }

    // ---------------------------------------------------------------
    // Front-running: plaintext answer visible in mempool
    // ---------------------------------------------------------------
    function setPuzzle(bytes32 _answerHash) external payable {
        answerHash = _answerHash;   // no access control
        puzzleReward = msg.value;
    }

    function submitAnswer(string calldata answer) external {
        require(keccak256(abi.encodePacked(answer)) == answerHash, "wrong");
        uint256 reward = puzzleReward;
        puzzleReward = 0;
        msg.sender.transfer(reward); // first-seen tx can be copied with higher gas
    }

    function setPrize(uint256 newPrice) external {
        // owner can sandwich buyers by changing price mid-block; also no auth
        ticketPrice = newPrice;
    }

    // ---------------------------------------------------------------
    // Signature replay + malleability (no nonce, no chainId, ecrecover 0)
    // ---------------------------------------------------------------
    function claimWithSignature(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, amount)); // no nonce / domain
        address recovered = ecrecover(digest, v, r, s);                   // no s-range check
        require(recovered == signer, "bad sig");                           // signer may be address(0)
        claimed[msg.sender] += amount;
        msg.sender.transfer(amount);                                       // replayable forever
    }

    // ---------------------------------------------------------------
    // Precision loss: division before multiplication
    // ---------------------------------------------------------------
    function payoutShare(uint256 shares, uint256 totalShares) public view returns (uint256) {
        return (prize / totalShares) * shares; // truncates; also div-by-zero if totalShares == 0
    }

    // ---------------------------------------------------------------
    // DoS with failed call: a contract that rejects ETH locks the auction
    // ---------------------------------------------------------------
    function bid() external payable {
        require(msg.value > highestBid, "too low");
        if (highestBidder != address(0)) {
            require(highestBidder.send(highestBid), "refund failed"); // push payment
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    receive() external payable {}
}
