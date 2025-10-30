# Privacy-Preserving Consensus Protocol Based on Social Capital

- **Author:** Bc. Juraj Mariani  
- **Supervisor:** doc. Ing. Ivan Homoliak, Ph.D.

![logo](./Excel@FIT/nahled.png)

## Table of Contents

- [Thesis Information](#thesis-information)  
- [Excel@FIT Resources](#excelfit-resources)  
- [Implementation](#implementation)  
- [Additional Information](#additional-information)

### Thesis Information

This Master's thesis presents a custom blockchain consensus protocol that uses **social capital** as an alternative to stake. Inspired by Proof-of-Stake (PoS) mechanisms, the protocol introduces a privacy-preserving system where validators are selected based on their *reputation*, *influence*, and *fame*, rather than a financial stake or hardware speed.

Key components of the proposed protocol include:

- **Privacy-Preserving Identity Verification**, ensuring that sensitive real-world identity of users remains confidential, but verifiable.
- **Social Capital Scaling**, to promote decentralization and fairness among content creators and ensure fairness.
- **Whisk-like leader election**, implmenting fair Whisk-inspired mechanism, disabling leader DoS attack vector.
- **Stake Representation through Social Capital**, where validator *fame* is derived from direct endorsements from other users, creating a dynamic and active environment.

#### The idea

- replace Ethereum’s current protocol – Proof-of-Stake (PoS)
- Ethereum requires minimum capital of at least 32 ETH to stake and have a chance to become a block leader
- Stake or Hardware (PoW) is expensive
- Social media influence can be inexpensive to gain

#### Our system

We propose a system in which the ability of a
verifier node to become a leader and to verify other blocks does not depend on the amount
of capital in its possession but rather on the amount of another value that is not implicitly
monetized so far – the Social Capital or fame.

This idea is more in line with the way modern social media platforms function.
There are influencers (verifyers nodes) that gather social capital from their followers or fans (who
are regular users). They can then "stake" this social capital to become a leader, create a
block, and ultimately claim the transaction fees. A blockchain user would be created with
a pre-selected number of social capital tokens that they could split between the influencers
they follow. This would be done either manually or by automatically
adjusting the influence score based on the user’s engagement towards the creator. These
changes would be registered on the blockchain as special transactions.

### Excel@FIT resources

This thesis has been presented on a student conference [Excel@FIT 2025](https://excel.fit.vutbr.cz/).
Along with a short digest of the thesis, there is a poster (2 versions) that has been submitted to this conference and is available in the materials of this project.
The resources can be found in [this folder](/Excel@FIT/).

### Implementation (Legacy)

This project adopts a microservice-inspired architecture at the local node level by splitting each logical node into two independent processes:

- ***Node*** – Handles peer-to-peer networking and gossip-based message propagation using asyncio.

- ***Blockchain*** – Maintains the blockchain state, validates blocks, and processes transactions.

These processes run concurrently and communicate via a non-blocking message-passing middleware using Python’s `multiprocessing.Queue`, ensuring modularity and clean separation of concerns.

#### Technologies Used

- **Python 3.10** – Chosen for rapid prototyping and rich standard libraries.
- **RLP Serialization** – Most classes extend `rlp.Serializable` for compact, network-friendly data encoding.
- **Asynchronous** Networking – Implemented with `asyncio` for non-blocking peer communication.
- **Inter-process Communication** – Achieved with `multiprocessing.Queue` to avoid shared state and ensure scalability.
- **Zero-Knowledge Proofs** – Integrated using `ZoKrates`, a Rust-based zkSNARK toolbox.

#### Testing & Simulation

A custom script (`/src/populator.py`) enables simulation of a peer-to-peer network on a single physical machine by spawning multiple logical nodes.

Multi-machine tests were also conducted, running 10 processes per device across two networked computers.

## Additional Information

Information regarding implementation can be found in the text of the thesis. The actual implementation can be found in the [implementation folder](/Legacy/src/readme.md) or on [GitHub](https://github.com/JurajMariani/scap/tree/main).
