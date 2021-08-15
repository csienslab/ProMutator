# ProMutator

ProMutator: Detecting Vulnerable Price Oracles in DeFi by Mutated Transactions

S.-H. Wang, C.-C. Wu, Y.-C. Liang, L.-H. Hsieh and H.-C. Hsiao

To appear in IEEE Workshop on Security & Privacy on the Blockchain (co-located with IEEE Euro S&P), September 2021.

# Implementation

We will open-source ProMutator after our paper is officially published.

# Evaluation

* We applied ProMutator to analyze the transactions from block 11,090,000 to 11,490,000 (Oct.– Dec. 2020) on the Ethereum Mainnet.
* We collected 5,964 contracts and randomly picked four transactions for each contract. If a contract called any of the AMM price-related functions listed in Table 3 of our paper, whether directly or indirectly, this contract was identified as using AMM price feeds and evaluated in our experiment.

## Results

* ProMutator identified a total of 219 potentially vulnerable price oracles, with 27 of them confirmed vulnerable by manual examination.
* We manually evaluated all potential vulnerabilities built on Curve and Kyber and 10% of those built on Uniswap to determine whether they are true or false positives. See [evaluation_results.csv](evaluation_results.csv) for more details.

## Responsible Disclosure

* All details of the newly discovered vulnerabilities in this paper should remain confidential until the developers of the vulnerable protocols confirmed the vulnerabilities are patched or do not cause any significant risk.
* In cases where the developers are unreachable after 30 days of our first attempt to contact, we will announce the discovery of the vulnerabilities to urge users to remove funds from the vulnerable protocols at least 10 days before publishing any technical details.
* If you find any 0-day vulnerabilities using ProMutator, please contact us immediately and follow a responsible disclosure guideline.
