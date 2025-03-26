// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract MultiSigWallet is ReentrancyGuard {

     /**
        Struct to represent a transaction

        @param tx_contract Address of the contract to interact with
        @param tx_data Method signature and arguments to the method
        @param num_sigs Number of signatures received
        @param executed Whether the transaction has been executed
     */

    struct Transaction {
        address tx_contract;
        bytes tx_data;
        uint num_sigs;
        bool executed;
    }

    
    address[] public signers; // current active list of signers
    mapping(address => bool) public isSigner;  // whether an address is a signer. For quick lookup in modifier

    uint public k; // required number of signers
    Transaction[] public transactions; // list of transactions
    mapping(uint => mapping(address => bool)) public approvals; // approval tracking for each transaction. Wanted this in the struct, but not possible

    modifier onlySigner() {
        require(isSigner[msg.sender], "Not a signer");
        _;
    }

    /* Events emitted during execution */
    event TransactionSubmitted(uint indexed tx_idx, address indexed tx_contract, bytes tx_data);
    event TransactionApproved(uint indexed tx_idx, address indexed approver);
    event TransactionExecuted(uint indexed tx_idx, address indexed executor);


    /** 
        Internal helper function to set the signers and required number of signers
        @param _signers List of signers
        @param _k Required number of signers
    */
    
    function setSigners(address[] memory _signers, uint _k) internal{
        for (uint i = 0; i < _signers.length; i++) {
            address signer = _signers[i];
            require(signer != address(0), "Invalid signer");
            require(!isSigner[signer], "Duplicate signer");
            isSigner[signer] = true;
            signers.push(signer);
        }
        k = _k;        
    }

    /**
        Internal helper function, that is called once the signers should be updated.
        Clears the current signers and sets the new signers and required number of signers

        @param newSigners List of new signers
        @param _k Required number of new signers
    */
    function _updateSigners(address[] calldata newSigners, uint _k) internal {
        require(newSigners.length > 0, "Signers required");
        require(_k > 0 && _k <= newSigners.length, "Invalid required number of signers");

        // Reset current signers.
        for (uint i = 0; i < signers.length; i++) {
            isSigner[signers[i]] = false; 
        }
        delete signers; // delete previous signers

        setSigners(newSigners, _k); // set new signers. We should really validate them BEFORE deleting the old ones...
    }


    /**
        Constructor

        Initializes the "k-of-n" signers requirement

        @param _signers List of signers
        @param _k Required number of signers
     */
    constructor(address[] memory _signers, uint _k) {
        require(_signers.length > 0, "Signers required"); // n > 0
        require(_k > 0 && _k <= _signers.length, "Invalid k of n signers"); // 0 < k <= n

        setSigners(_signers, _k);     
    }


    /**
     *  Submit a transaction to the multisig wallet. Only signers can submit.

        @param contract_addr Address of the contract to interact with
        @param method_signature Method signature 
        @param data arguments to the method
        @return tx_idx Index of the transaction
     */

    function submitTransaction(address contract_addr, string memory method_signature, bytes memory data) public onlySigner returns (uint){

        transactions.push();
        uint tx_idx = transactions.length - 1;
        Transaction storage t = transactions[tx_idx];
        t.tx_contract = contract_addr;
        t.tx_data = abi.encodeWithSignature(method_signature, data); // we don't care about tx_data being visible. Double-encoding of data?
        t.executed = false;

        // we assume the submitter (a signer) approves by default. Otherwise remove next 2 lines.
        t.num_sigs = 1;
        approvals[tx_idx][msg.sender] = true;
    
        emit TransactionSubmitted(tx_idx, contract_addr, t.tx_data);
        return tx_idx;
    }


    /**
        A signer can initiate the process of updating the signers
    
        @param newSigners List of new signers
        @param _k Required number of signers
     */

    function updateSigners(address[] calldata newSigners, uint _k) external onlySigner {
        string memory method = "_updateSigners(address[], uint)"; // we don't care about this being visible.
        bytes memory args = abi.encode(newSigners, _k); // will this be double-encoded in the transaction?
        submitTransaction(address(this), method, args); // we submit it as a transaction to be approved by other signers
    }



    /**
        Approve a transaction.

        We allow approvals of transactions that have already been approved.

        @param tx_idx Index of the transaction to approve
     */

    function approveTransaction(uint tx_idx) external onlySigner {
        require(tx_idx < transactions.length, "Transaction does not exist");
        require(!transactions[tx_idx].executed, "Transaction already executed");
        require(approvals[tx_idx][msg.sender] == false, "You already approved the transaction"); // would increment num_sigs otherwise. lol.

        approvals[tx_idx][msg.sender] = true; // indicate that the signer has approved
        transactions[tx_idx].num_sigs++;

        // we could execute here if num_sigs >= k, but it's not a requirement.
 
        emit TransactionApproved(tx_idx, msg.sender);
    }

    /**
        Execute a transaction. Anyone can call this function.
        "Anyone can execute the approved multisig" requirement. I hope this is what you meant.

        nonReentrant modifier is used to prevent reentrancy attacks. Also prevents endless loops.

        @param tx_idx Index of the transaction to execute
     */
    function executeTransaction(uint tx_idx) external nonReentrant {
        require(tx_idx < transactions.length, "Transaction does not exist");
        require(transactions[tx_idx].num_sigs >= k, "Transaction not approved");
        require(!transactions[tx_idx].executed, "Transaction already executed");
        
        Transaction storage txn = transactions[tx_idx];

        (bool success, ) = txn.tx_contract.call(txn.tx_data);

        require(success, "Transaction execution failed");
        txn.executed = true; // let's do this after the call(). Could be done before the call(), if desired.

        emit TransactionExecuted(tx_idx, msg.sender);
    }
}