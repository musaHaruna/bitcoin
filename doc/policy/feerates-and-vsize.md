# Policy: Fee Rates and Virtual Size

Bitcoin Core needs a reliable method to estimate how much “block space” each transaction will consume when building block templates and enforcing mempool policies. While BIP‑141 defines the concept of *virtual transaction size* (vsize) based strictly on block weight, the mempool policy introduces a *sigop adjustment* to account for potential denial‑of‑service vectors from transactions with unusually high signature‑operation counts. This document explains the definitions, how they are calculated, how they are exposed through RPC, and provides guidance for users and integrators.

## Weight, Virtual Size, and Sigop‑Adjusted Size
**Transaction weight** is defined in BIP‑141 as the sum of four times the stripped transaction size plus the witness data size. This weight metric is what consensus rules use to enforce the maximum block weight of 4 000 000 units.  
**BIP‑141 virtual size** (sometimes referred to as `vsize_bip141`) is simply the block weight divided by four, rounded up. This value represents the consensus‑level “size” of a transaction without any consideration of signature operations.  
To protect against “2D‑Knapsack” attacks that exploit a combination of block weight and high sigop counts, the mempool applies a **sigop‑adjusted size**. This value is the maximum of the pure BIP‑141 vsize and a sigop‑based calculation (sigop count multiplied by a configurable `bytesPerSigOp` parameter, which defaults to 20 vbytes per sigop). The sigop adjustment is used internally for mempool admission, eviction, fee estimation, and mining template construction.

## RPC Field Exposures
In mempool‑related RPCs (`getrawmempool`, `getmempoolentry`, `testmempoolaccept`, and `submitpackage`), the field named `vsize` represents the **sigop‑adjusted size**, reflecting the policy‑adjusted estimate of block space usage. These same RPCs also provide a field called `vsize_bip141` which exposes the pure BIP‑141 virtual size without sigop adjustment. When querying a transaction via `getrawtransaction`, the reported `vsize` is the BIP‑141 value; sigop adjustment is not applied in that context by default.

## Guidance for Users
When performing fee estimation and building block templates, **always use the sigop‑adjusted `vsize`** from the mempool RPCs, as this reflects how Bitcoin Core internally prioritizes transactions. For consensus‑level weight calculations, refer instead to `vsize_bip141`. If you need to inspect the raw BIP‑141 size of a transaction not yet in the mempool, use `getrawtransaction`; but if you need the policy‑adjusted size, use `getmempoolentry` or `getrawmempool`. Node operators should be cautious when changing the `-bytespersigop` parameter, as it can affect fee estimation accuracy and block utilization without impacting consensus rules.

## Rationale & Compatibility
Updating documentation to clarify that the existing `vsize` field in mempool RPCs is sigop‑adjusted avoids breaking changes for clients relying on that behavior. Introducing the new `vsize_bip141` field is additive and non‑breaking, allowing integrators to opt into the pure BIP‑141 metric. Future enhancements, such as adding a `sigopsize` field to expose raw sigop counts or adjusted values directly, can be introduced without disrupting existing RPC contracts.
