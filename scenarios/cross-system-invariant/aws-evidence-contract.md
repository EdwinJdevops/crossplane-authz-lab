# AWS evidence contract

This adapter deliberately distinguishes an AWS API result from the stronger claim the experiment wants to make.

## IAM

For a role-to-S3 claim, IAM SimulatePrincipalPolicy is accepted as useful policy evidence, not as proof of live effective access.

AWS documents two limitations relevant here: simulator results can differ from the live environment, and resource-based policy simulation is not supported for IAM roles. Therefore:

- explicit/implicit deny -> DENIED evidence;
- allowed -> UNKNOWN for the stronger claim "this role can effectively read this exact protected object in the live system."

The experiment must obtain additional resource-side and service-side evidence before promoting that claim.

## Network

A successfully completed Reachability Analyzer result with NetworkPathFound=true is accepted as PROVEN network-path evidence for the exact analyzed endpoints/protocol/port represented by the analysis.

An unfinished or malformed analysis is UNKNOWN.

## Consequence

The cross-plane graph may now contain strong Kubernetes identity edges and AWS network-path evidence while still refusing to claim effective protected-data access.

That is intentional. Evidence strength is property-specific; a vendor API returning "allowed" does not erase documented scope limitations.
