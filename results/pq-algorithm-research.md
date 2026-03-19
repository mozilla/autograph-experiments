# Autograph \- Post Quantum Research

# Research

Below is the research process to help us determine which post quantum signature algorithms provide the best specifications for our use case.

## Metrics to Measure

Some of the key metrics that we will use are public keys and signature sizes along with the NIST security category to find a good balance between them that supports our needs.

Private Key size is not an important deciding factor since it will be stored by Autograph and will not affect implementation cost or complexity.

### Weekly Estimated Bandwidth

1. Assume 500M active users each week  
   1. This is more than our actual weekly active users number because of:  
      1. Automation accounts that will hit remote-settings prod  
      2. Cloned profiles  
      3. Users that have telemetry disabled but still query remote settings  
      4. Firefox forks that have telemetry disabled but query remote-settings  
2. For each user, the public key will need to be downloaded once  
3. For each user, a signature will need to be downloaded for each collection update  
   1. Let’s estimate this at 50 times per week per user. Some weeks will be higher, some weeks lower. Some collections get updated multiple times per week

The weekly estimated bandwidth (TB) will help us understand the cost of using the algorithms, and will be a significant deciding factor. The lower bandwidth will indicate the corresponding algorithm is more **cost efficient**.

The Weekly Verification Performance (Cycles) metric will help us understand the relative speed of the algorithms and will assist us in finding the most **time efficient** algorithm. The cycles (Cycles) are clock cycles on x86 architecture with AVX2.

## Limitations to Consider

We need to consider the support provided to Post Quantum algorithms by our offline HSM Enstrust nShield F3 USB. As of Sep 22, 2025, the offline HSM in Toronto has been updated to Security World 13.9.0 and supports FIPS-204 ML-DSA \[[link](https://nshielddocs.entrust.com/security-world-docs/release-notes/release-notes.html#mldsa-pkcs11)\], FIPS-203 ML-KEM \[[link](https://nshielddocs.entrust.com/security-world-docs/release-notes/release-notes.html#_ml_kem_post_quantum_algorithm_firmware_support_nse_48335)\], and FIPS-205 SLH-DSA \[[link](https://nshielddocs.entrust.com/security-world-docs/release-notes/release-notes.html#_slh_dsa_post_quantum_algorithm_firmware_support_nse_48338)\].

The support provided by Google KMS needs to be considered as well \[[link](https://cloud.google.com/kms/docs/algorithms)\]. Some ML-DSA and SLH-DSA algorithms are in pre-GA right now, and may be subject to change.

## Algorithms Types

We start off by going through and researching the major post quantum algorithm types and ruling out the types that are not favourable for Autograph. Note that we will only be focusing on the differences that will affect Mozilla’s Autograph. For additional details, this [article](https://en.wikipedia.org/wiki/Post-quantum_cryptography#Algorithms) contains information on the various types of algorithms.

1. Lattice-based  
   1. Algorithms  
      1. FALCON  
         1. Falcon has a better combination of lower bandwidth and faster performance than scale better than most other algorithms at security category 1 and 5  
         2. Has a small signature and key size  
         3. Relies on floating point arithmetic, which is not favourable since floating point arithmetic is handled [differently](https://falcon-sign.info/falcon.pdf#page=20) across various types of hardware and can cause inconsistencies/security [issues](https://eprint.iacr.org/2024/1709.pdf#page=2)  
      2. DILITHIUM (ML-DSA)  
         1. First standardized lattice based post quantum (PQ) signature with slightly larger key sizes than standard RSA algorithms, but secure even against large quantum computers  
      3. Hawk  
         1. Similar to Falcon in terms of key \+ signature sizes  
         2. Does not rely on floating point arithmetic, meaning that we will have consistent results even across various hardware \[[link](https://hawk-sign.info/)\]  
   2. Most of the lattice-based algorithms are efficient and are standardized  
2. Multivariate  
   1. Algorithms  
      1. Rainbow ([Unbalanced Oil and Vinegar](https://www.uovsig.org/))  
         1. Rainbow algorithm has been ruled out since some security categories have been vulnerable to [attacks](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-3/official-comments/RAINBOW-round3-official-comment.pdf)  
      2. MAYO  
         1. Offers a middle security category choice, good [specs](https://openquantumsafe.org/liboqs/algorithms/sig/mayo.html) in terms of signature size (0.4kb-1kb) and public key size (1kb-5kb)  
3. Hash-based  
   1. These algorithms use hash functions to ensure quantum safe signing  
      1. Hash functions transform data to code that cannot be deciphered, it is a one-way process  
   2. Algorithms  
      1. SPHINCS+ (SLH-DSA) standardized algorithm  
         1. Has larger signature and keys sizes, making them less efficient and more computationally expensive than lattice-based \[[link](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf#page=53)\]  
         2. The bandwidth requirements are very large and range from 200TB-700TB which will be costly  
      2. XMSS and LMS \- hash based stateful algorithms  
         1. Complex implementation for autograph service, stateful algorithms rely on state management so we would need to track the number of keys  
         2. If state is not properly tracked, it could lead to security breaches \[[link](https://blog.cloudflare.com/another-look-at-pq-signatures/)\]  
4. Code-based  
   1. Algorithms  
      1. CROSS  
         1. Has very large key sizes (100kB to 1mB for secure keys)  
         2. Will not be viable for autograph post-quantum due to extremely [large](https://openquantumsafe.org/liboqs/algorithms/sig/cross.html) signature sizes for all security categories  
   2. It will be better to rule this type out due to bandwidth limitations  
5. Isogeny-based  
   1. Algorithms  
      1. SQIsign  
         1. Small key and signature sizes, outperforming other PQ algorithms \[[link](https://sqisign.org/)\]  
         2. Has higher signing and verification [times](https://blog.cloudflare.com/another-look-at-pq-signatures/) compared to ML-DSA, it is up to 143 times slower  
         3. Computationally expensive to verify the signatures  
   2. It will be better to rule this type out due to client performance  
6. Symmetric key quantum resistance  
   1. As long as the key size is sufficiently large, it will be quantum safe  
      1. Moving from 128 to 256 bytes reduces security risks  
   2. Not sufficient for our use case since public keys are required for signature algorithms  
      

We will first rule out Code-based types (including CROSS) due to the high weekly bandwidth (300TB-1.3TB) and slow verification times (600K-2M cycles) which will increase costs \[[link](https://openquantumsafe.org/liboqs/algorithms/sig/cross.html)\].

The Isogeny-based type can also be ruled out due to the extensive signing and verification times of up to 143 times [slower](https://blog.cloudflare.com/another-look-at-pq-signatures/) than ML-DSA which can slow down autograph performance.

The SPHINCS+ algorithm will also be ruled out for high weekly bandwidth and slow verification times compared to other algorithms, thereby increasing the cost.

We will rule out XMSS and LMS because they are stateful algorithms, requiring us to manage state by making sure our one time keys are tracked and never reused which can lead to [security vulnerabilities](https://blog.cloudflare.com/another-look-at-pq-signatures/).

We proceed with ML-DSA, Falcon, Hawk, and MAYO. These algorithms are well documented with relatively fast signing and verification time, along with a good balance between key sizes and security categories that we can look into.

## Algorithm Specifications

Post-Quantum specification sheet: [Autograph PQ Algorithm Specs](./pq-algorithm-specs.csv)

After looking at the specifications, we can break down the advantages and disadvantages of the shortlisted algorithms ML-DSA, Falcon, Hawk, MAYO.

1. ML-DSA  
   1. Pros  
      1. Has a middle security category (level 3\) which has experimental support in [Google KMS](https://cloud.google.com/kms/docs/algorithms)  
      2. Has experimental offline HSM support  
      3. Has the fastest verification performance compared to the other algorithms for each security category  
   2. Cons  
      1. Has the largest weekly bandwidth out of all the shortlisted algorithms (60TB-116TB) \[[link](./pq-algorithm-specs.csv)\]  
2. Falcon  
   1. Pros  
      1. Second lowest weekly bandwidth usage  
      2. Standardized by NIST, possible Google KMS support in future  
      3. Fast verification performance  
   2. Cons  
      1. Not supported by [Google KMS](https://cloud.google.com/kms/docs/algorithms) at this time  
      2. Relies on floating point arithmetic  
3. Hawk  
   1. Pros  
      1. Weekly bandwidth very low, similar to Falcon  
      2. Does not rely on floating point arithmetic, performance will be similar across hardware  
   2. Cons  
      1. Not standardized  
      2. Verification performance around 45% slower than Falcon  
4. MAYO  
   1. Pros  
      1. Offers the lowest weekly bandwidth  
      2. Has a middle security category (MAYO-3)  
   2. Cons  
      1. Verification performance slowest out of all shortlisted algorithms (3 times slower than ML-DSA)  
      2. Not supported by Google KMS at this time  
      3. Similar multivariate types like Rainbow (UOV scheme) have known security [vulnerabilities](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-3/official-comments/RAINBOW-round3-official-comment.pdf)

## Signature Algorithm Security

### Security Category

For our selected algorithms we need to decide on a good balance between the security category and performance/bandwidth. [Security Categories](https://csrc.nist.gov/glossary/term/security_category) are a number associated with the security strength of a post-quantum cryptographic algorithm, as specified by NIST. Categories range from 1-5, and a higher security Category indicates a more secure algorithm.

We need to decide on a security category that is at least equivalent to the ones that we are currently using in our Signature Algorithms. We currently use ECDSA-384 for Content signing and RSA-4096 for code signing. These provide security categories [equivalent](https://postquantum.com/post-quantum/nist-pqc-security-categories/) to NIST category 3, thus we should at least aim for category 3 security to retain a comparable amount of security.

Security category 4 and 5 are better suited as [future proofing](https://postquantum.com/post-quantum/nist-pqc-security-categories/) options because they have around 2 times slower verification performance compared to security category 3 implementations.

Autograph should focus on NIST security category 3 implementations when available such as with MAYO and ML-DSA. If not available, like in HAWK and Falcon, we would need to consider the use case and how often we rotate the keys. If we need long term key storage then we should consider category 5, if it is short term we can consider category 1\.

### Post Quantum vs Current Algorithms

Current algorithms that are used by Autograph, like RSA and ECDSA are recommended to be deprecated by 2030 and disallowed by 2035 according to [NIST](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf#page=20).

These algorithms are threatened by the advancement in quantum computing. By 2030, algorithms like RSA-2048 might be able to be [broken](https://nvlpubs.nist.gov/nistpubs/ir/2016/NIST.IR.8105.pdf#page=11) in a matter of hours by a quantum computer. In comparison, a classical computer would take up to a billion years to [break](https://www.btq.com/blog/how-far-away-is-the-quantum-threat) the same algorithm. Quantum safe algorithms are made to be resistant to quantum computer attacks and will take a long time to break unless groundbreaking advancements are made in quantum computing.

## Code vs Content Signing

Currently Autograph uses separate signature algorithms for code signing and content signing.

With content signing we can rotate the content keys quickly and have short lived certificates, whereas with code signing we would like to store the keys for a longer period of time. We can apply something similar and use separate signature algorithms during our Post Quantum migration.

Falcon and HAWK have lower weekly bandwidth \[[link](./pq-algorithm-specs.csv)\] compared to the other shortlisted algorithms, which makes them promising candidates for content signing. Since [Google KMS](https://cloud.google.com/kms/docs/algorithms) does not support these algorithms, we will have to store the keys outside of KMS. This is alright for content signing since we can rotate the keys frequently and have short lived certificates.

For code signing, we want to store the keys for an extended period of time. For this, Google KMS and offline HSM support would be best to have so that keys can be stored securely long term. Thus, ML-DSA is best suited, as it offers experimental support for Google KMS for the NIST security category 3\.

## Conclusion

We can rule out HAWK because of the performance limitations compared to Falcon. HAWK has approximately equal weekly bandwidth to Falcon, but is around 45% slower in terms of verification performance. HAWK is also not standardized. Thus, it would make more sense to proceed with Falcon. 

MAYO was ruled out for code signing because it doesn't have Google KMS support, which is preferred for long term key storage. Moreover, similar [UOV](https://www.uovsig.org/) based multivariate schemes like Rainbow have known security [vulnerabilities](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-3/official-comments/RAINBOW-round3-official-comment.pdf), making MAYO risky to implement long term. The verification performance of MAYO-3 (category 3 security) is 340% slower than ML-DSA-65, thus we can rule out MAYO.

The most promising algorithm for the Autograph Post Quantum code signing is the [ML-DSA-65](https://openquantumsafe.org/liboqs/algorithms/sig/ml-dsa), which is the NIST security category 3 implementation. This implementation is standardized by FIPS and receives support from Google KMS. It provides the fastest verification performance of its security category relative to other algorithms. The downside is that it requires a large weekly bandwidth (80TB).

The best algorithm for content signing is Falcon-512, which is the NIST security category 1 implementation. The downgrade in security from a category 3 equivalent to category 1 is worth it for the performance increase, since we rotate keys frequently. It provides us with a low bandwidth (17TB) which minimizes cost, and is standardized by NIST. The verification performance and small signature size makes Falcon well suited for frequent key rotations. The downside is the lack of support from Google KMS, but we can store the keys inside Google Cloud storage since they are short lived. When implementing Falcon in Autograph we need to ensure we deal with floating point inconsistencies.

## Definitions

### Research Stage

No implementation found in GitHub

### Standardized

More documentations and implementations, submitted to NIST

### Estimated Weekly Bandwidth

1. Assume 500M active users each week  
   1. This is more than our actual weekly active users number because of:  
      1. Automation accounts that will hit remote-settings prod  
      2. Cloned profiles  
      3. Users that have telemetry disabled but still query remote settings  
      4. Firefox forks that have telemetry disabled but query remote-settings

2\. For each user, the public key will need to be downloaded once  
3\. For each user, a signature will need to be downloaded for each collection update

1. Let’s estimate this at 50 times per week per user. Some weeks will be higher, some weeks lower. Some collections get updated multiple times per week

### Estimated Verification Performance

Stated in Clock Cycles on x86 architecture with AVX2

### Security Category

| Security Category | Attack Type | Example |
| :---- | ----- | ----- |
| 1 | Key search on block cipher with 128 bit key | AES-128 |
| 2 | Collision search on 256 bit hash function | SHA-256 |
| 3 | Key search on block cipher with 192 bit key | AES-192 |
| 4 | Collision search on 384 bit hash function | SHA3-384 |
| 5 | Key search on block cipher with 256 bit key | AES-256 |

## References

* NIST Selected Algorithms  
  * [https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms)  
* FIPS 204 (ML-DSA)  
  * [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)  
  * [https://csrc.nist.gov/csrc/media/Presentations/2022/high-performance-hardware-implementation-of-lattic/images-media/session-4-beckwith-high-performance-hardware-pqc2022.pdf](https://csrc.nist.gov/csrc/media/Presentations/2022/high-performance-hardware-implementation-of-lattic/images-media/session-4-beckwith-high-performance-hardware-pqc2022.pdf)  
* FIPS 205 (SLH-DSA)  
  * [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)  
* FALCON  
  * [https://falcon-sign.info/](https://falcon-sign.info/)  
* HAWK  
  * [https://hawk-sign.info/](https://hawk-sign.info/)  
* RSA and ECDSA Specification  
  * [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-5.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-5.pdf)  
  * [https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154986/SECP256R1+Support](https://lf-hyperledger.atlassian.net/wiki/spaces/BESU/pages/22154986/SECP256R1+Support)  
  * [https://nvlpubs.nist.gov/nistpubs/ir/2016/NIST.IR.8105.pdf\#page=11](https://nvlpubs.nist.gov/nistpubs/ir/2016/NIST.IR.8105.pdf#page=11)  
* Comparing Hash based algorithms  
  * [https://eprint.iacr.org/2017/349.pdf](https://eprint.iacr.org/2017/349.pdf)  
* Standardization candidates  
  * [https://blog.cloudflare.com/another-look-at-pq-signatures/](https://blog.cloudflare.com/another-look-at-pq-signatures/)  
* Algorithm types  
  * [https://en.wikipedia.org/wiki/Post-quantum\_cryptography\#Algorithms](https://en.wikipedia.org/wiki/Post-quantum_cryptography#Algorithms)  
  * [https://www.paloaltonetworks.ca/cyberpedia/what-is-post-quantum-cryptography-pqc](https://www.paloaltonetworks.ca/cyberpedia/what-is-post-quantum-cryptography-pqc)  
* Rainbow Algorithm Security Issue  
  * [https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-3/official-comments/RAINBOW-round3-official-comment.pdf](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-3/official-comments/RAINBOW-round3-official-comment.pdf)  
* Code-based algorithms  
  * [https://www.redhat.com/en/blog/post-quantum-cryptography-code-based-cryptography](https://www.redhat.com/en/blog/post-quantum-cryptography-code-based-cryptography)  
* SQIsign  
  * [https://en.wikipedia.org/wiki/SQIsign](https://en.wikipedia.org/wiki/SQIsign)  
  * [https://sqisign.org/](https://sqisign.org/)  
* Algorithm Specs  
  * [https://openquantumsafe.org/liboqs/algorithms/](https://openquantumsafe.org/liboqs/algorithms/)  
* Estimated Performance  
  * [https://openquantumsafe.org/benchmarking/](https://openquantumsafe.org/benchmarking/)  
* NIST Security Category  
  * [https://postquantum.com/post-quantum/nist-pqc-security-categories/](https://postquantum.com/post-quantum/nist-pqc-security-categories/)  
  * [https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf\#page=19](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf#page=19)
