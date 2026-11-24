# Manual review notes 24/11/2026:

1. Ask agent to clearly outline what historical access means in this implementation as well as what the design is for data recovery and key revocation in case of a ransomware or an attack.
2. Also, ask it to clearly outline which folder goes where (i.e. on which server/endpoint) in the overall design of the system.
3. Ask agent to pay attention to the designed tests to verify that they are well-designed and that the correct functionality has been implemented and is being tested. Also verify that individual README files match the implemented code.
4. Have to clean up any redundant or unnecessary files/folders. But only at the end. There is a bit of file disorganization with how compose.yaml is set-up. postgres and kubo set-up is together while besu=qbft is seperate. 
5. Also TECHNICAL_SPECIFICATIONS.md can be moved into docs/specifications.
6. Why is the code for services like gateway and indexer in their own folder but also some of the functionality they execute are in the files in the crates folder?
7. README.md should be rewritten to only include the project overview and architecture (based on the TECHNICAL_SPECIFICATIONS.md and the adr docs). A category for current progress and existing limitations will be included at the bottom and rewritten anytime significant changes are made. Progress notes will be shifted to the progress_report.md and should be dated. 
8. Flag instances where inter-dependency or duplication occurs so that system comptability is ensured in any future development.
9. In decisions folder, grounded justification for why certain languages, encryption standards and design, tech stacks, etc were used should be provided, along with a brief note on limitations. TECHNICAL_SPECIFICATIONS.md can be used as a reference for this.