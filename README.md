# PVSS-BFT: Efficient and Secure Sleepy Model for BFT Consensus

A Go implementation of the PVSS-BFT consensus protocol based on the paper "Efficient and Secure Sleepy Model for BFT Consensus" by Ren et al [[1]](#references).

## Architecture

```
pvss-bft/
├── cmd/
│   └── example_network/
│       └── main.go          # an easy example with a simulated network
├── pkg/
│   ├── crypto/
│   │   ├── pvss.go          # implementation of PVSS
│   │   ├── vrf.go           # implementation of VRF
│   │   └── signatures.go    # signatures and hashing
│   ├── network/
│   │   └── network.go       # a network layer implementation
│   ├── protocol/
│   │   └── node.go          # implementation of the PVSS-BFT protocol
│   └── types/
│       └── types.go         # type definitions
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

# run example
go run ./cmd/example_network/main.go
```

## References

- Ren, P., Dong, H., Tari, Z., & Zhang, P. (2025, September). Efficient and Secure Sleepy Model for BFT Consensus. In European Symposium on Research in Computer Security (pp. 314-333). Cham: Springer Nature Switzerland. 
https://doi.org/10.48550/arXiv.2509.03145

