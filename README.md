# InfectTest

## Abstract
The global market's reach of Android devices makes the system a prime target for cyber criminals. In 2023 mobile malware attacks were reported by Kaspersky at a staggering 33.8 million, with a year over year increase of 52%. The Android operating system sustained the impact of these attacks accounting for 92% and being the primary victim. Outdated cybersecurity tools, relying on signature-based checks, struggle to detect polymorphic malware that skillfully evades static analysis.

This paper proposes a solution based on hybrid malware detection that integrates both static and dynamic analysis with artificial intelligence. We utilize AndroPyTool to execute applications within a safeguarded sandbox partitioned environment extracting runtime opcodes, API calls and permission which are executed. These outputs are used as input into a Random Forest for Multi classification which may accurately identify and categorize variants of malware with there families which includes adwares, SMSware and ransomware.
