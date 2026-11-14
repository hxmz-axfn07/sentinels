# PCAP ingestion and packet metadata

## Capture formats and validation

PCAP is the classic packet-capture format. A global header identifies the file format, byte order, timestamp precision, link type, and snapshot length; packet records follow with timestamps and captured/original lengths. SENTINEL currently accepts version 2.4 captures using the standard microsecond and nanosecond magic values in either byte order. It rejects unsupported versions, invalid timestamp fractions, impossible record lengths, truncation, and captures with no packet records.

PCAPNG is a block-oriented format. A Section Header Block defines byte order and section version; Interface Description Blocks describe capture interfaces, and packet blocks carry captured frames. SENTINEL currently accepts version 1.0 sections and validates block boundaries, lengths, matching trailers, interface references, and packet lengths for the supported packet block types. Files with unsupported section versions or structurally invalid blocks are rejected. These supported subsets are explicit implementation limits, not a claim to accept every extension or future variant.

Validation uses the bytes on disk. Extensions and MIME types are retained only as untrusted client metadata and do not select the parser. Structural validation limits malformed input before Scapy reads packets; it cannot prove packet payloads are semantically valid.

## Packet structure and Scapy parsing

A captured frame may contain link-layer headers, an IPv4 or IPv6 network header, and zero or more transport/application layers. Packets can be truncated, non-IP, or lack a recognized transport layer. Scapy's `PcapReader` reads the capture incrementally, preserving record order and capture timestamps without loading the entire capture into memory.

The extraction service creates a typed metadata record per packet. It stores the one-based packet index, timestamp, captured packet length, network protocol, available addresses and protocol number, transport protocol, available TCP/UDP ports, TCP flags, and ICMP type/code. IPv4 and IPv6 addresses are stored in textual form. ARP addresses are retained when present. Missing values remain null; the service does not invent ports for ICMP, ARP, or other packets.

## Storage and privacy

The API streams multipart file content to a temporary file in the configured private storage directory in bounded chunks. It enforces the configured maximum at the HTTP body and file layers, rejects empty/unsupported/malformed captures, and assigns a random server-side storage key after validation. Client filenames are sanitized for display only. Temporary files are removed on rejection or failure before the analysis record is established. The capture is never executed.

Packet payload bytes are not stored. Only the metadata fields above are persisted in `packet_metadata`, linked to an analysis and ordered by a unique analysis/index pair. This still exposes sensitive network identifiers and timing information, so the database and capture storage require appropriate access controls and retention practices.

## Processing behavior and limits

Processing is synchronous in the upload request. Packet rows are inserted in batches of 500 to bound application memory. If later processing fails after some batches were committed, the failure handler clears partial packet rows, resets the count, and stores a generic failure message without exposing paths or packet data. The validated capture stays attached to the failed analysis. This milestone does not aggregate bidirectional flows, extract flow features, or detect threats. It also does not perform live packet capture and requires no elevated capture privileges.

See the [README](../../README.md) for local setup, API routes, and verification commands.
