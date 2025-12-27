# PVSS-BFT: Efficient and Secure Sleepy Model for BFT Consensus

A Go implementation of the PVSS-BFT consensus protocol based on the paper "Efficient and Secure Sleepy Model for BFT Consensus" by Ren et al [[1]](#references).

## Architecture

```
pvss-bft/
├── cmd/
│   └── examples/            # examples with simulated network and scenario
│       └── ......
├── pkg/
│   ├── crypto/              # cryptographic algorithms
│   │   ├── pvss.go
│   │   ├── vrf.go
│   │   └── signatures.go
│   ├── network/             # network layer implementation
│   │   ├── in_mem_network.go
│   │   └── tcp_network.go
│   ├── protocol/            # implementation of the PVSS-BFT protocol
│   │   ├── handlers.go
│   │   ├── interface.go
│   │   ├── node_core.go
│   │   ├── phases.go
│   │   ├── sync.go
│   │   └── utils.go
│   └── types/
│       └── types.go         # data structures
├── go.mod
└── README.md
```


## Example

```bash
# clone this repository
git clone https://github.com/lrx0014/pvss-bft.git
cd pvss-bft

# dependencies
go mod download

# run example (in-memory simulation)
go run ./cmd/examples/local_network

# run example (sleep/awake simulation)
go run ./cmd/examples/sleepy_demo

# run example (tcp network)
go run ./cmd/examples/tcp_network
```

## References

- Ren, P., Dong, H., Tari, Z., & Zhang, P. (2025, September). Efficient and Secure Sleepy Model for BFT Consensus. In European Symposium on Research in Computer Security (pp. 314-333). Cham: Springer Nature Switzerland. 
https://doi.org/10.48550/arXiv.2509.03145

