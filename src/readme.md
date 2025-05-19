# Implementation

This folder contains the core implementation of the consensus protocol proof-of-concept. It is structured to separate networking, blockchain logic, and utility components for modularity and clarity.

- [Requirements](#requirements)
- [Structure](#folder-structure)
- [Testing](#testing)

## Requirements

The implementation has been written in python, specifically python3.10. Additional python modules have been included in the `requirements.txt` file.

The requirements are as follows:

- Python:
  - `python3.10`
  - `pycryptodome` ver 3.22.0
  - `eth_keys` ver 0.7.0
  - `eth_utils` ver 5.3.0
  - `rlp` ver 4.1.0
  - `trie` ver 3.1.0
- ZoKrates:
  - installed and operational
  - exported in the `$PATH` variable as to be reachable from anywhere
  - standard libraries have to be located in `~/.zokrates/stdlib`.

## Folder Structure

- `blockchain`
  Folder, containing modules for Blockchain logic.
  - `account.py` Contains account logic and supplementary classes (`RegisterData`, `AffiliateMedia`) used in the registration processes as TXn payloads.
  - `block.py` Contains the block class, block verification functions and the Attestation class.
  - `blockchain.py` Main logic of the blockchain. Consists of a `Blockchain` class (a main process), handling network and user input, generating blocks, delegating verification and more.
  - `consensus.py` Houses the `PoSC` class, facilitating leader election mechanism.
  - `randao.py` Implements a Randao-inspired randomness beacon.
  - `state.py` Contains a `StateTrie` class used to take care of the account state. Implements transaction validation and execution functions over the account state.
  - `transaction.py` Denotes Txn and TxMeta structure.
  - `utils.py` Introduces logging function and `Genesis` class, providing initial state of te blockchain.
  - `zkp_manager.py` Is a high-level wrapper, creating a simple interface to *ZKP* generation and verification.
- `chainlogger/logger.py` Implements functions that set up a `logging.Log` object and provide an event handler.

- `config`
  - `config.json` Configuration file of the blockchian, Contains required constatns required for correct function.
  - `digital_passport_vc.json` Is a mock digital passport *Verifiable Credential* that could be used in the future with a similar structure, to prove identity.
- `contracts` Unused folder. Smart contracts are not implemented.

- `middleware` Communication middleware between the *Node* and *Blockchain* processes.
  - `middleware.py` Implements the class `Postman`, allowing `multiprocessing.Queue`-powered full-duplex comunication
  - `rpc.py` Denotes a standardized communication schema.

- `network` Process handling peer and network management.
  - `message.py` Creates a standardized structure of a message schema, sent via network.
  - `peer.py` Provides a class for storage and manipulation of peer data
  - `node.py` Contains the **Node** class responsible for peer-to-peer networking, message propagation, and asynchronous communication using `asyncio` (overall *Node* logic).

- `storage/` Directory where blockchain data is persisted in binary format, organized by node ID.
  - `zkp/` Temporary runtime folder containing intermediary *ZKP* generation and verification files.

- `zkp` Directory, that contains the ID ZKP circuit
  - `verifyVC.zok` ZoKrates circuit used to prove valid and unique ID.
  - `zk_handler.py` Low-level wrapper for the circuit, facilitating system calls.
- `bootstrapper.py` Class, tying *Node* and *Blockchain* processes together.
- `populator.py` A custom script to simulate a local peer-to-peer network by spawning multiple logical nodes. Useful for testing and experimentation on a single machine.

## Testing

The testing setup focuses on simulating a distributed environment with multiple nodes communicating locally.

### Local Simulation

- Manupulation of the `populator.py` script is needed to adjust node count (def. 4 nodes). Adjusting node count requires extending the `styles` list, as it contains mock behavior patterns for each node.
- Run `populator.py` to spawn multiple node processes on a single machine.
- Each node runs independently, communicates over IPC and networking protocols.
- Enables rapid testing of consensus, message propagation, and fault tolerance.
- Local output can be found in `/src/log.log` (every node outputs to the same file)

### Multi-Machine Testing

- The system has been tested with 2 computers on a local network.
- Each computer runs 10 node processes, verifying network scalability and synchronization.

### How to Run a Test

1. Ensure all dependencies are installed (`asyncio`, `rlp`, etc.).
2. Adjust `populator.py` scripts to your desired network size.
3. Execute the populator script:

```bash
$ python3 populator.py
```
