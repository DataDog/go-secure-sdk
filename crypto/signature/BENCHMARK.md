# Benchmark(s)

> Runs on a ARM64 M1 PRO 10 core / Go 1.19.3

## Signers

```
goos: darwin
goarch: arm64
pkg: github.com/DataDog/go-secure-sdk/crypto/signature
BenchmarkECDSASigner/P-256/1-10       	   58228	     20029 ns/op	   0.05 MB/s	    3395 B/op	      47 allocs/op
BenchmarkECDSASigner/P-256/32-10      	   58756	     19948 ns/op	   1.60 MB/s	    3395 B/op	      47 allocs/op
BenchmarkECDSASigner/P-256/64-10      	   59956	     20005 ns/op	   3.20 MB/s	    3395 B/op	      47 allocs/op
BenchmarkECDSASigner/P-256/1k-10      	   50931	     23550 ns/op	  43.48 MB/s	    3395 B/op	      47 allocs/op
BenchmarkECDSASigner/P-256/32k-10     	    8893	    133615 ns/op	 245.24 MB/s	    3409 B/op	      47 allocs/op
BenchmarkECDSASigner/P-256/64k-10     	    4774	    247467 ns/op	 264.83 MB/s	    3449 B/op	      47 allocs/op
BenchmarkECDSASigner/P-384/1-10       	    6417	    185659 ns/op	   0.01 MB/s	    6524 B/op	      73 allocs/op
BenchmarkECDSASigner/P-384/32-10      	    6438	    185771 ns/op	   0.17 MB/s	    6524 B/op	      73 allocs/op
BenchmarkECDSASigner/P-384/64-10      	    6436	    185817 ns/op	   0.34 MB/s	    6525 B/op	      73 allocs/op
BenchmarkECDSASigner/P-384/1k-10      	    6318	    189500 ns/op	   5.40 MB/s	    6525 B/op	      73 allocs/op
BenchmarkECDSASigner/P-384/32k-10     	    3968	    299543 ns/op	 109.39 MB/s	    6557 B/op	      73 allocs/op
BenchmarkECDSASigner/P-384/64k-10     	    2871	    412692 ns/op	 158.80 MB/s	    6616 B/op	      73 allocs/op
BenchmarkECDSASigner/P-521/1-10       	    2344	    511067 ns/op	   0.00 MB/s	    8269 B/op	      75 allocs/op
BenchmarkECDSASigner/P-521/32-10      	    2348	    518879 ns/op	   0.06 MB/s	    8266 B/op	      75 allocs/op
BenchmarkECDSASigner/P-521/64-10      	    2347	    510219 ns/op	   0.13 MB/s	    8268 B/op	      75 allocs/op
BenchmarkECDSASigner/P-521/1k-10      	    2332	    513438 ns/op	   1.99 MB/s	    8269 B/op	      75 allocs/op
BenchmarkECDSASigner/P-521/32k-10     	    1917	    623133 ns/op	  52.59 MB/s	    8337 B/op	      75 allocs/op
BenchmarkECDSASigner/P-521/64k-10     	    1618	    738538 ns/op	  88.74 MB/s	    8430 B/op	      75 allocs/op
BenchmarkEd25519Signer/1-10           	   72111	     16659 ns/op	   0.06 MB/s	      64 B/op	       1 allocs/op
BenchmarkEd25519Signer/32-10          	   72156	     16620 ns/op	   1.93 MB/s	      64 B/op	       1 allocs/op
BenchmarkEd25519Signer/64-10          	   70156	     17095 ns/op	   3.74 MB/s	      64 B/op	       1 allocs/op
BenchmarkEd25519Signer/1k-10          	   50480	     23821 ns/op	  42.99 MB/s	      64 B/op	       1 allocs/op
BenchmarkEd25519Signer/32k-10         	    4870	    243059 ns/op	 134.82 MB/s	      90 B/op	       1 allocs/op
BenchmarkEd25519Signer/64k-10         	    2532	    470409 ns/op	 139.32 MB/s	     167 B/op	       1 allocs/op
PASS
ok  	github.com/DataDog/go-secure-sdk/crypto/signature	39.034s
```

## Verifiers

```
goos: darwin
goarch: arm64
pkg: github.com/DataDog/go-secure-sdk/crypto/signature
BenchmarkECDSAVerifier/P-256/1-10       	   21078	     56411 ns/op	   0.02 MB/s	    1633 B/op	      25 allocs/op
BenchmarkECDSAVerifier/P-256/32-10      	   21296	     56396 ns/op	   0.57 MB/s	    1649 B/op	      25 allocs/op
BenchmarkECDSAVerifier/P-256/64-10      	   21304	     56411 ns/op	   1.13 MB/s	    1665 B/op	      25 allocs/op
BenchmarkECDSAVerifier/P-256/1k-10      	   20038	     59978 ns/op	  17.07 MB/s	    1633 B/op	      25 allocs/op
BenchmarkECDSAVerifier/P-256/32k-10     	    6950	    169877 ns/op	 192.89 MB/s	    1652 B/op	      25 allocs/op
BenchmarkECDSAVerifier/P-256/64k-10     	    4142	    283875 ns/op	 230.86 MB/s	    1713 B/op	      25 allocs/op
BenchmarkECDSAVerifier/P-384/1-10       	    1981	    601108 ns/op	   0.00 MB/s	    2918 B/op	      45 allocs/op
BenchmarkECDSAVerifier/P-384/32-10      	    1982	    602137 ns/op	   0.05 MB/s	    2918 B/op	      45 allocs/op
BenchmarkECDSAVerifier/P-384/64-10      	    1978	    604273 ns/op	   0.11 MB/s	    2918 B/op	      45 allocs/op
BenchmarkECDSAVerifier/P-384/1k-10      	    1975	    604886 ns/op	   1.69 MB/s	    2903 B/op	      45 allocs/op
BenchmarkECDSAVerifier/P-384/32k-10     	    1666	    715923 ns/op	  45.77 MB/s	    2997 B/op	      45 allocs/op
BenchmarkECDSAVerifier/P-384/64k-10     	    1417	    828631 ns/op	  79.09 MB/s	    3103 B/op	      45 allocs/op
BenchmarkECDSAVerifier/P-521/1-10       	     645	   1856468 ns/op	   0.00 MB/s	    4068 B/op	      49 allocs/op
BenchmarkECDSAVerifier/P-521/32-10      	     644	   1857190 ns/op	   0.02 MB/s	    3876 B/op	      47 allocs/op
BenchmarkECDSAVerifier/P-521/64-10      	     644	   1853168 ns/op	   0.03 MB/s	    3681 B/op	      45 allocs/op
BenchmarkECDSAVerifier/P-521/1k-10      	     640	   1884797 ns/op	   0.54 MB/s	    3685 B/op	      45 allocs/op
BenchmarkECDSAVerifier/P-521/32k-10     	     607	   1981915 ns/op	  16.53 MB/s	    4074 B/op	      47 allocs/op
BenchmarkECDSAVerifier/P-521/64k-10     	     573	   2081024 ns/op	  31.49 MB/s	    4524 B/op	      49 allocs/op
BenchmarkEd25519Verifier/1-10           	   36686	     32469 ns/op	   0.03 MB/s	       0 B/op	       0 allocs/op
BenchmarkEd25519Verifier/32-10          	   37291	     32689 ns/op	   0.98 MB/s	       0 B/op	       0 allocs/op
BenchmarkEd25519Verifier/64-10          	   36362	     33592 ns/op	   1.91 MB/s	       0 B/op	       0 allocs/op
BenchmarkEd25519Verifier/1k-10          	   32368	     36933 ns/op	  27.73 MB/s	       0 B/op	       0 allocs/op
BenchmarkEd25519Verifier/32k-10         	    7890	    153826 ns/op	 213.02 MB/s	      16 B/op	       0 allocs/op
BenchmarkEd25519Verifier/64k-10         	    4329	    274952 ns/op	 238.35 MB/s	      60 B/op	       0 allocs/op
PASS
ok  	github.com/DataDog/go-secure-sdk/crypto/signature	42.916s
```
