// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal interfaces — just the functions this contract calls.
/// Works against any standard-compliant ERC-721 or ERC-1155 token.
interface IERC721Minimal {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

interface IERC1155Minimal {
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external;
}

/// @title NFTSwap
/// @notice Peer-to-peer swap of one or more NFTs for one or more NFTs.
///         Nothing leaves either wallet until executeSwap runs. That one
///         call transfers every item on both sides; if any single
///         transfer fails, the whole transaction reverts and neither
///         side's items move.
/// @dev    This contract never takes custody of tokens. It only ever
///         acts as an approved operator (via setApprovalForAll) moving
///         tokens directly between the two parties' wallets.
contract NFTSwap {
    enum Standard {
        ERC721,
        ERC1155
    }

    struct Item {
        address token;
        uint256 tokenId;
        uint256 amount; // always 1 for ERC-721
        Standard standard;
    }

    struct Trade {
        address initiator;
        address counterparty;
        bytes32 secretHash;
        bool initiatorSubmitted;
        bool counterpartySubmitted;
        bool initiatorConfirmed;
        bool counterpartyConfirmed;
        bool executed;
        bool cancelled;
    }

    uint256 private nextTradeId = 1;

    mapping(uint256 => Trade) private trades;
    mapping(uint256 => mapping(address => Item[])) private manifests;

    bool private locked;

    event TradeCreated(uint256 indexed tradeId, address indexed initiator, bytes32 secretHash);
    event TradeJoined(uint256 indexed tradeId, address indexed counterparty);
    event ManifestSet(uint256 indexed tradeId, address indexed party, uint256 itemCount);
    event ManifestConfirmed(uint256 indexed tradeId, address indexed party);
    event SwapExecuted(uint256 indexed tradeId);
    event TradeCancelled(uint256 indexed tradeId, address indexed by);

    modifier nonReentrant() {
        require(!locked, "Reentrancy blocked");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyParty(uint256 tradeId) {
        Trade storage t = trades[tradeId];
        require(msg.sender == t.initiator || msg.sender == t.counterparty, "Not a party to this trade");
        _;
    }

    modifier tradeActive(uint256 tradeId) {
        Trade storage t = trades[tradeId];
        require(t.initiator != address(0), "Trade does not exist");
        require(!t.executed, "Trade already executed");
        require(!t.cancelled, "Trade was cancelled");
        _;
    }

    /// @notice Starts a new trade. Pass keccak256 of a secret you generate
    ///         off-chain (32 random bytes is plenty). Share the secret
    ///         itself — never the hash — with whoever you want to trade
    ///         with; they need it to join.
    /// @dev    The secret is revealed in calldata the moment joinTrade is
    ///         called, so treat it as an invite code, not a load-bearing
    ///         security secret. See the front-running note below.
    function createTrade(bytes32 secretHash) external returns (uint256 tradeId) {
        require(secretHash != bytes32(0), "Secret hash required");
        tradeId = nextTradeId++;
        Trade storage t = trades[tradeId];
        t.initiator = msg.sender;
        t.secretHash = secretHash;
        emit TradeCreated(tradeId, msg.sender, secretHash);
    }

    /// @notice Joins an existing trade by presenting the secret that
    ///         hashes to the trade's stored secretHash.
    function joinTrade(uint256 tradeId, bytes32 secret) external tradeActive(tradeId) {
        Trade storage t = trades[tradeId];
        require(t.counterparty == address(0), "Trade already has a counterparty");
        require(msg.sender != t.initiator, "Initiator cannot join their own trade");
        require(keccak256(abi.encodePacked(secret)) == t.secretHash, "Wrong secret");
        t.counterparty = msg.sender;
        emit TradeJoined(tradeId, msg.sender);
    }

    /// @notice Records or replaces the caller's offer for this trade.
    ///         This only stores what will be transferred later — it does
    ///         not move any tokens. Call setApprovalForAll(this contract,
    ///         true) on every collection you're offering from before
    ///         executeSwap runs, or that leg will fail and the whole
    ///         swap will revert.
    /// @dev    Replacing a manifest clears both sides' confirmations —
    ///         nobody should stay "confirmed" against terms that changed
    ///         under them.
    function setManifest(
        uint256 tradeId,
        address[] calldata tokens,
        uint256[] calldata tokenIds,
        uint256[] calldata amounts,
        uint8[] calldata standards
    ) external tradeActive(tradeId) onlyParty(tradeId) {
        require(
            tokens.length == tokenIds.length &&
                tokens.length == amounts.length &&
                tokens.length == standards.length,
            "Array length mismatch"
        );
        require(tokens.length > 0, "Offer must include at least one item");

        Trade storage t = trades[tradeId];
        Item[] storage manifest = manifests[tradeId][msg.sender];
        delete manifest;

        for (uint256 i = 0; i < tokens.length; i++) {
            require(tokens[i] != address(0), "Invalid token address");
            require(standards[i] <= uint8(Standard.ERC1155), "Invalid standard code");
            Standard std = Standard(standards[i]);
            uint256 amount = amounts[i];
            if (std == Standard.ERC721) {
                require(amount == 1, "ERC-721 amount must be 1");
            } else {
                require(amount > 0, "ERC-1155 amount must be greater than 0");
            }
            manifest.push(Item({token: tokens[i], tokenId: tokenIds[i], amount: amount, standard: std}));
        }

        if (msg.sender == t.initiator) {
            t.initiatorSubmitted = true;
        } else {
            t.counterpartySubmitted = true;
        }

        t.initiatorConfirmed = false;
        t.counterpartyConfirmed = false;

        emit ManifestSet(tradeId, msg.sender, tokens.length);
    }

    /// @notice Confirms you agree to both manifests exactly as they
    ///         currently stand. Both sides must have submitted an offer
    ///         first.
    function confirmManifest(uint256 tradeId) external tradeActive(tradeId) onlyParty(tradeId) {
        Trade storage t = trades[tradeId];
        require(t.initiatorSubmitted && t.counterpartySubmitted, "Both sides must submit an offer first");

        if (msg.sender == t.initiator) {
            t.initiatorConfirmed = true;
        } else {
            t.counterpartyConfirmed = true;
        }
        emit ManifestConfirmed(tradeId, msg.sender);
    }

    /// @notice Executes the swap. Transfers every item on both sides in
    ///         this single transaction. If any transfer reverts — a
    ///         missing approval, a token that changed hands, whatever —
    ///         the entire transaction reverts and nothing moves.
    function executeSwap(uint256 tradeId) external nonReentrant tradeActive(tradeId) onlyParty(tradeId) {
        Trade storage t = trades[tradeId];
        require(t.initiatorConfirmed && t.counterpartyConfirmed, "Both sides must confirm first");

        // Checks-effects-interactions: mark executed before any external
        // calls so this can't be re-entered or run twice.
        t.executed = true;

        _transferManifest(tradeId, t.initiator, t.counterparty);
        _transferManifest(tradeId, t.counterparty, t.initiator);

        emit SwapExecuted(tradeId);
    }

    function _transferManifest(uint256 tradeId, address from, address to) private {
        Item[] storage items = manifests[tradeId][from];
        for (uint256 i = 0; i < items.length; i++) {
            Item storage item = items[i];
            if (item.standard == Standard.ERC721) {
                IERC721Minimal(item.token).safeTransferFrom(from, to, item.tokenId);
            } else {
                IERC1155Minimal(item.token).safeTransferFrom(from, to, item.tokenId, item.amount, "");
            }
        }
    }

    /// @notice Cancels a trade before it executes. Does not touch any
    ///         approvals you've granted the contract — revoke those
    ///         separately from your wallet if you want to fully undo a
    ///         trade you're walking away from.
    function cancelTrade(uint256 tradeId) external tradeActive(tradeId) onlyParty(tradeId) {
        Trade storage t = trades[tradeId];
        t.cancelled = true;
        emit TradeCancelled(tradeId, msg.sender);
    }

    function getTrade(uint256 tradeId)
        external
        view
        returns (
            address initiator,
            address counterparty,
            bool initiatorSubmitted,
            bool counterpartySubmitted,
            bool initiatorConfirmed,
            bool counterpartyConfirmed,
            bool executed,
            bool cancelled
        )
    {
        Trade storage t = trades[tradeId];
        return (
            t.initiator,
            t.counterparty,
            t.initiatorSubmitted,
            t.counterpartySubmitted,
            t.initiatorConfirmed,
            t.counterpartyConfirmed,
            t.executed,
            t.cancelled
        );
    }

    function getManifest(uint256 tradeId, address party)
        external
        view
        returns (
            address[] memory tokens,
            uint256[] memory tokenIds,
            uint256[] memory amounts,
            uint8[] memory standards
        )
    {
        Item[] storage items = manifests[tradeId][party];
        uint256 len = items.length;
        tokens = new address[](len);
        tokenIds = new uint256[](len);
        amounts = new uint256[](len);
        standards = new uint8[](len);
        for (uint256 i = 0; i < len; i++) {
            tokens[i] = items[i].token;
            tokenIds[i] = items[i].tokenId;
            amounts[i] = items[i].amount;
            standards[i] = uint8(items[i].standard);
        }
    }
}
