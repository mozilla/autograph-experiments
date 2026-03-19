# Post Quantum Testing Results

# Problem Threshold

To determine if a post-quantum signature algorithm is a viable replacement for our current algorithms, we will need to evaluate them across our criteria:

* Client-side signature verification speed  
* Server-side signature generation speed  
* Increased cost

## Performance Criteria

* **Signature Verification (Client-side):** Our main concern is users that are on older hardware, that is \>10 years old, which may have performance issues with quantum-safe verification. We have to be certain that the verification performance across various hardware doesn’t have a steep performance drop compared to our currently used algorithms.

* **Signature Generation (Server-side):** For signature generation we want to ensure that our signing operations don’t take significantly longer compared to current algorithms. We will test signing both sequentially and in parallel to mimic a real server side scenario.

## Candidate Algorithms

We want to evaluate the performance of our post-quantum algorithm choices and compare them against our current algorithms for both code and content signing. The algorithms chosen were the ones with the most efficient combination of bandwidth usage and verification speed. See our comparison table here for details: [Autograph PQ Algorithm Specs](./pq-algorithm-specs.csv)

| Use Case | Current Algorithm | Post-quantum Algorithm |
| :---- | :---- | :---- |
| **Content Signing** | ECDSA-384 | FN-DSA-512 (Falcon) |
| **Code signing** | RSA-4096 | ML-DSA-65 (Dilithium) |

# Conclusions

## ML-DSA-65

**Recommendation:** We should switch to ML-DSA for code signing because it is already well supported and optimized for most existing hardware. Its performance and cost are also well within the acceptable range.

* **Client-side:** ML-DSA and RSA have equivalent verification speed for small payloads, but ML-DSA is slower by 45% on medium payloads. ML-DSA is only slower than RSA on older hardware that is over 10 years old. **This difference is negligible**, an extra 2ms wouldn’t affect our code signing verification time since the operation occurs infrequently.  
* **Server-side:** For signature generation, small payload ML-DSA is faster than RSA by 40%, while medium payload ML-DSA is faster by 10%.  
* **Cost:** Due to larger certificate and signature sizes, this could increase the bandwidth needed for signatures by 6-7x. This would be a significant amount for content signing, where data can change daily. But for code signing this is less of an impact.  
* **Conclusion:** Switching to ML-DSA for code signing will add post-quantum security to autograph, in exchange for negligible user impact and slightly increased costs.

## FN-DSA-512

**Recommendation:** We should switch to FN-DSA for content signing and root/intermediate certificates because it is expected to receive NIST approval soon, has good performance, and lower bandwidth requirements.

* **Client-side:** FN-DSA has around 20x faster signature verification speed than ECDSA on small payloads. For medium payloads, FN-DSA is 44% slower than ECDSA, mainly on hardware that is over 10 years old. This difference is very small (around 2ms), so it will not affect users.  
* **Server-side:** For signature generation, small payload FN-DSA has equivalent speeds to ECDSA, but for medium payload FN-DSA is 2x faster than ECDSA. Thus, our server side signing will have a positive impact on its speed.  
* **Cost:** Our weekly bandwidth for content signing goes from 3TB to 17TB, which will not increase costs significantly.  
* **Conclusion:** Switching to FN-DSA for content signing will add post-quantum security for Autograph, but will increase costs and add a bit of verification latency to older devices.

# General Performance Analysis

## Signature Verification Average Time Per Operation

| Algorithm | Small Payload (4 bytes) | Medium Payload (2MB) |
| :---- | :---- | :---- |
| RSA-4096 | 0.1628 ms | 4.9700 ms |
| ML-DSA-65 | 0.1643 ms | 7.1814 ms |
| ECDSA-384 | 0.9736 ms | 4.9682 ms |
| FN-DSA-512 | 0.0545 ms | 7.1921 ms |

From this table, we can tell that FN-DSA is around 20x faster than ECDSA for small payloads. On the other hand, FN-DSA is slower by 45% for medium payload, which will slow down the verification process.

For the code signing we compare the average signing time for RSA and ML-DSA. In this case, ML-DSA is 20x faster than RSA for small payloads and 44% slower than RSA for medium payloads. The difference between medium payloads is 2ms which shouldn’t negatively affect our users.

## Signature Generation Average Time Per Operation

These are the results after running our server-side signature generation testing program in parallel on GCP servers. This gets rid of any authorization overhead and gives us the closest comparison to production level signing.

```shell

Small Payload FN-DSA-512: 0.053 ms
Small Payload ECDSA-384: 0.061 ms
Small Payload RSA-4096: 1.751 ms
Small Payload ML-DSA-65: 1.272 ms

Medium Payload FN-DSA-512: 0.783 ms
Medium Payload ECDSA-384: 1.254 ms
Medium Payload RSA-4096: 1.483 ms
Medium Payload ML-DSA-65: 1.386 ms
```

For content signing, we can see that FN-DSA has similar signature generation time to ECDSA for small payloads. FN-DSA is around 40% faster than ECDSA for medium payloads as well. Switching to FN-DSA will not negatively affect signature generation latency for Autograph.

For code signing, ML-DSA is 50% faster for smaller payloads compared to RSA, and ML-DSA is slightly faster for medium payloads as well. Thus, ML-DSA is an improvement over RSA for code signing and will increase signing speeds.

In conclusion, we should switch to our post-quantum candidates because they have better signature generation speeds than our current algorithms.

# Detailed Performance Analysis

## Signature Verification Testing Graphs

Note: FN-DSA-512 is the NIST name of FALCON-512

### Algorithm Performance \- CPU Cores

![][image1]  
![][image2]  
The CPU core graph doesn’t show a strong correlation between the number of CPU cores and performance. In the data, the 8-core CPU has slower verification performance than the 6-core, so we can conclude that signature verification with our library ([OQS](https://github.com/open-quantum-safe/liboqs)) is not a parallel workload.

31% of our users are on 4 core CPUs and 28% are on 2 cores ([link](https://data.firefox.com/dashboard/hardware)). Our graphs show slow verification performance for 2 core CPUs because they are generally old and have outdated architecture, leading to slow single core performance. The actual verification performance drop is around 6ms which is not concerning for us.

### Algorithm Performance \- Total RAM

![][image3]  
![][image4]  
For both payload types, having more RAM doesn’t guarantee better signature verification speeds. For all 4 algorithms, machines with 16GB of ram outperformed those with 24GB. This shows that the algorithm performance isn’t affected by memory capacity and instead depends on if the CPU can pull data out of the RAM efficiently and keep its cache fed. There are a few hardware issues that can bottleneck the performance.  
**Hardware Limitations:**

* Running memory in single-channel mode due to non-matching ram sticks  
* BIOS configuration errors  
* Undetected faulty memory stick

When we look at user data, 11% of users have 4GB RAM and 30% have 8GB ([link](https://data.firefox.com/dashboard/hardware)), which means they will be most impacted when we switch to post-quantum algorithms. But, the actual performance difference is within 2-4ms which will be negligible for real world signature verification. Therefore, RAM is not a hardware aspect that we should be concerned about.

### Algorithm Performance \- Operating System

![][image5]![][image6]  
From this graph we can see that there is no noticeable performance degradation in a specific operating system that we tested: MacOS, Windows, Linux. The variation in performance between them is mainly due to the hardware constraints of the machine. The 3 operating systems we tested make up 92% of [users](https://data.firefox.com/dashboard/hardware).

### Algorithm Performance \- CPU Model

| CPU Model (Older) | Release Year |
| :---- | :---- |
| Intel Core i5-2520M | 2011 |
| Intel Core i7-2670QM | 2011 |
| Intel Core i7-3667U | 2012 |
| AMD FX-8300 | 2012 |
| Intel Core i5-4200M | 2013 |
| Intel Core i7-4790K | 2014 |
| Intel Core i7-7700HQ | 2017 |
| AMD Ryzen 7 1700 | 2017 |
| Intel Core i5-8250U | 2017 |
| Apple M1 Max | 2021 |
| AMD Ryzen 5 5600 | 2022 |
| AMD Ryzen 7 7800X3D | 2023 |
| AMD Ryzen 5 7640U | 2023 |
| Apple M3 Pro | 2023 |

![][image7]  
![][image8]  
In the CPU Model graphs, we see that modern CPUs consistently perform better than older generation CPUs. In our tests, CPUs that were older than 10 years have performance that is at least 2x slower. This is due to architectural constraints, with some processors having shared FPUs (like the AMD fx-8300) which can slow down signature verification. This combined with low core counts and poor single core performance leads to older generation CPUs performing significantly worse. 

Although older CPUs perform slower, there is at most a 7ms difference in verification speed which will be negligible for our users. Based on this data, we can conclude that switching to the post-quantum algorithms ML-DSA and FN-DSA will not significantly degrade the performance for our end users.

## Small (4B) vs Medium (2MB) Payload

In the small payload graphs, we can observe that ECDSA is extremely slow (\>3x) compared to any of the other algorithms. If we want to switch to a better algorithm for small payloads then FN-DSA is the clear choice, as it is 20x faster than ECDSA which is used for small-payload content-signing. For code signing, ML-DSA has similar verification performance to RSA so the performance will stay the same. In the context of small payloads we should switch because the post-quantum algorithms provide greater security and performance than our current algorithms, so there is no downside to switching.

When we look at medium payloads we see a slight drop in performance as FN-DSA and ML-DSA are 45% slower than ECDSA and RSA respectively. Even though 45% is a significant amount, the real world time difference is 2ms which is negligible. Thus, even for medium payloads it is best to switch to post-quantum signature algorithms for increased security even at the small cost of performance.

## Signature Generation Testing Results

We tested our server side signature generation program to see how fast we can generate signatures and compare the post quantum algorithm signing times to current algorithms.

Note that the ECDSA-384 and FN-DSA-512 algorithms are used for content signing, and due to a lack of a KMS implementation for FN-DSA we decided to implement both of them locally to get a better comparison. RSA-4096 and ML-DSA-65 are used for code signing and both were implemented with Google KMS.

## Signing Operations on Local Build

The local build signing operations were tested on a MacOS M3 Pro device with 36GB RAM.

### Sequential Tests

The program runs 100 signing operations sequentially, and returns the average time per operation.

```shell
Small Payload Falcon-512: 0.125 ms
Small Payload ECDSA-384: 0.135 ms
Small Payload RSA-4096: 406.587 ms
Small Payload ML-DSA-65: 391.105 ms

Medium Payload Falcon-512: 1.565 ms
Medium Payload ECDSA-384: 1.570 ms
Medium Payload RSA-4096: 400.628 ms
Medium Payload ML-DSA-65: 369.019 ms
```

### Parallel Tests

The program ran the signing operations for each algorithm in parallel using Goroutines and waitgroups. This test was to find out how performant the signing is when the hardware is under load. We took the average time per operation of 100 tests running in parallel.

```shell
Small Payload FN-DSA-512: 0.021 ms
Small Payload ECDSA-384: 0.019 ms
Small Payload RSA-4096: 5.601 ms
Small Payload ML-DSA-65: 6.443 ms

Medium Payload FN-DSA-512: 0.452 ms
Medium Payload ECDSA-384: 0.311 ms
Medium Payload RSA-4096: 5.722 ms
Medium Payload ML-DSA-65: 6.530 ms
```

## Signing Operations on GCP

This was tested on GCP and was done to verify if there is network latency or authorization overhead that alters the test results.

### Sequential Tests

The program runs 100 signing operations sequentially, and returns the average time per operation.

```shell
Small Payload Falcon-512: 0.247 ms
Small Payload ECDSA-384: 0.245 ms
Small Payload RSA-4096: 40.807 ms
Small Payload ML-DSA-65: 26.594 ms

Medium Payload Falcon-512: 3.240 ms
Medium Payload ECDSA-384: 4.653 ms
Medium Payload RSA-4096: 30.518 ms
Medium Payload ML-DSA-65: 24.872 ms
```

### Parallel Tests

The program ran all the signing operations for each algorithm in parallel using Goroutines and waitgroups. This test was to find out how performant the signing is when the hardware is under load. We took the average time per operation of 100 tests running in parallel.

```shell
Small Payload FN-DSA-512: 0.053 ms
Small Payload ECDSA-384: 0.061 ms
Small Payload RSA-4096: 1.751 ms
Small Payload ML-DSA-65: 1.272 ms

Medium Payload FN-DSA-512: 0.783 ms
Medium Payload ECDSA-384: 1.254 ms
Medium Payload RSA-4096: 1.483 ms
Medium Payload ML-DSA-65: 1.386 ms
```

From the signature generation testing results, we can conclude that the post quantum algorithms outperform our current algorithms in most cases. In the other case, the performance difference is \~1 ms which is negligible for our use case. Thus, our chosen algorithms will not be problematic for signature generation.

## Conclusion

We should switch to our candidate post-quantum signature algorithms ML-DSA and FN-DSA because they provide enhanced security against quantum computers. Our verification speed will go up around 5ms for older hardware but this difference is negligible and will not affect the performance of our end users.

# Limitations

## Hardware Age and Architecture

We have noticed that hardware with older architecture (around 10+ years) performs significantly worse for signature verification than modern hardware. Referring to the CPU age graph, there is a drop in CPU performance for the processors that are older than 2017\. This drop in performance is due to architectural constraints such as shared FPUs like the AMD fx-8300 and lack of modern instruction sets like AVX2, which our post quantum algorithms rely on to speed up the verification process.

## Mobile Testing

We have decided to disregard mobile testing because phones have a shorter life span than computers and people will tend to change them more often. Very few users will be running a phone older than currently sold models in 2029 when we are expecting to make this switch.

## Hardware Comparisons

Our testing data for different hardware is biased because it is tested with different measurements. For example, when we compare 16GB vs 32GB RAM performance, the 32 GB machine might have a less powerful CPU which will cause the comparison to favour the 16GB machine. We will follow-up on this by testing algorithms with emulated hardware to isolate variables.

## Testing Very Large Payloads

Large payload signing happens every few weeks, so a little variation in time will not affect our users. We will test the larger payload sizes for code-signing.

# Future Considerations

## Further testing

We would want to further test the hardware more uniformly to reduce bias in our testing results. For example, we would want to test different RAM amounts on a machine with the same specifications (CPU, OS, Cores) to reduce inaccuracies. We could use virtual machines to isolate variables, so the virtual hardware would change but the underlying silicon would stay consistent between runs. This would eliminate architecture oddities from test variables while keeping instruction set limitations and CPU frequency the same.

# References

* Post Quantum Research Document: [Autograph Post Quantum Research ](./pq-algorithm-research.md)   
* Post Quantum Algorithm Spreadsheet: [Autograph PQ Algorithm Specs](./pq-algorithm-specs.csv)  
* Firefox Desktop Hardware Survey: [https://data.firefox.com/dashboard/hardware](https://data.firefox.com/dashboard/hardware)

[image1]: ./images/image1.png
[image2]: ./images/image2.png
[image3]: ./images/image3.png
[image4]: ./images/image4.png
[image5]: ./images/image5.png
[image6]: ./images/image6.png
[image7]: ./images/image7.png
[image8]: ./images/image8.png
