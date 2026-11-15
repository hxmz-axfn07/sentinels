# Bidirectional flow engine

## What a network flow represents

A network flow summarizes packets exchanged by two endpoints using the same transport protocol. A one-way packet sequence splits a conversation into separate records; treating both directions as one bidirectional flow makes request and response traffic comparable and gives later analysis a stable unit of work.

For TCP and UDP, SENTINEL identifies a flow from the IP version, transport protocol, and the two endpoint pairs `(address, port)`. For protocols without ports, such as ICMP, the endpoint is the IP address alone. The two endpoints are ordered deterministically by IP version, numeric IP address, then port. Reversing a packet therefore preserves the key. The key is serialized canonically and hashed with SHA-256; Python's process-randomized `hash()` is not used. The analysis ID is included in the digest so two captures with identical traffic remain separate.

Endpoint A and endpoint B define direction: A-to-B is forward, B-to-A is backward. This is a deterministic canonical direction, not a claim about client/server roles or the first packet seen. The original source and destination of the earliest capture-index packet are retained separately for display and investigation.

TCP/UDP packets missing either endpoint address or either port are isolated by packet index. Grouping unknown ports could merge unrelated conversations. Invalid address and port values are not exposed as valid flow endpoints; invalid ports become null. Non-port protocols can still form a bidirectional flow when both endpoint addresses are valid. Packets with incomplete or inconsistent IP/protocol metadata are isolated rather than combined. Unknown transport labels include their IP protocol number in the key, preventing distinct protocol numbers with the same label from colliding. ICMP flows use endpoint pair and protocol; this does not distinguish ICMP message type/code or echo identifier.

## Statistics and definitions

Packet records are read from the database in batches; the original capture is not parsed again. Each flow's packet lengths use Welford's online algorithm for a numerically stable mean and population standard deviation:

`mean = Σ(lengthᵢ) / n`

`population_stddev = sqrt(Σ(lengthᵢ − mean)² / n)`

The implementation keeps the running statistics in memory for one flow at a time. Minimum, maximum, mean, and standard deviation are stored. A flow cannot be created from an empty packet set. A one-packet flow has packet-length deviation zero.

For packets with timestamps, duration is `max(timestamp) − min(timestamp)`. Packets are traversed chronologically within the flow (capture packet index breaks timestamp ties), and inter-arrival times are successive non-negative timestamp differences. The inter-arrival mean and population deviation are calculated over those differences. Missing timestamps do not contribute. If timestamps are unavailable, first/last timestamps and duration are null; if fewer than two timestamps exist, inter-arrival statistics are null. Out-of-order capture record timestamps are sorted for these timing features, while packet direction totals still follow packet identity.

The engine stores total and directional packet and byte counts, packet-length statistics, timing statistics, TCP flag bit counts, and rates. Duration is null when the flow has no usable timestamps. Packet and byte rates are `total_packets / duration` and `total_bytes / duration`; rates are null when duration is zero or unavailable. TCP flag counts are null if no TCP flag metadata was present; otherwise each count is the number of packets where that flag bit is set. Flags can co-occur in one packet. Inter-arrival features are null when no interval is available. These rules avoid division by zero and avoid persisting invented values.

## Why the features matter

Flow counts and directional bytes describe conversation volume and imbalance. Duration and packet rates describe activity over time. Packet-length and inter-arrival distributions provide compact behavioral summaries. TCP flag counts preserve connection-control patterns. These measurements can later feed independently tested rules or machine-learning preprocessing; this milestone computes and stores features but does not detect attacks or classify flows.

## Persistence and API behavior

Flow generation is synchronous and operates only on a completed packet analysis. The service stamps stable flow IDs and canonical direction onto packet metadata, aggregates an ordered database stream, and inserts flow rows in the same transaction. A failure rolls back packet stamps and flow rows, then records a generic failed status. A repeated generation request returns the existing result without inserting duplicates. The analysis row is locked while generation is claimed, with a unique `(analysis_id, flow_id)` constraint as a final duplicate guard.

Revision `0003_bidirectional_flows` adds analysis generation status, packet flow-key/direction fields and indexes, and the `network_flows` table. Its downgrade removes generated flow rows, packet assignments, and analysis generation state; it is data-destructive and must not be run against a database whose Day 3 results should be kept.

See [PCAP ingestion](pcap-ingestion.md) for the packet metadata input and [README](../../README.md) for API routes.
