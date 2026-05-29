// DDD role: ValueObject
package schemas

// #CollectorName enumerates all valid collector identifiers.
#CollectorName: "rtnetlink" | "traffic_control" | "conntrack" | "nftables" | "sock_diag" | "ethtool"

// #LogLevel enumerates supported tracing filter levels.
#LogLevel: "trace" | "debug" | "info" | "warn" | "error"

// #LogFormat enumerates supported log output formats.
#LogFormat: "json" | "text"

// #ListenAddr is a non-empty string in "host:port" SocketAddr notation.
#ListenAddr: =~"^.+:[0-9]+$"

// #Port is a valid non-privileged TCP port (1024-65535).
#Port: >=1024 & <=65535

// #ScrapetimeoutMs is the per-full-scrape wall-clock budget in milliseconds.
// Must be between 1000 ms and 30000 ms inclusive.
#ScrapetimeoutMs: >=1000 & <=30000

// #NetlinkRecvBufBytes is the SO_RCVBUF size for all netlink sockets.
// Bounded to 64 KiB minimum and 32 MiB maximum to prevent ENOBUFS on busy nodes.
#NetlinkRecvBufBytes: >=65536 & <=33554432

// #ExporterConfig is the top-level configuration value object for the nft_exporter binary.
// All fields are sourced from environment variables (NFT_EXPORTER_* prefix) and/or
// CLI flags. The domain core treats this as an immutable value after startup.
#ExporterConfig: {
	// listen is the HTTP listen address for /metrics, /healthz, /ready.
	// Env: NFT_EXPORTER_LISTEN. CLI: --listen. Default: "0.0.0.0:9456".
	listen: #ListenAddr

	// scrape_timeout_ms is the per-full-scrape wall-clock timeout in milliseconds.
	// Env: NFT_EXPORTER_SCRAPE_TIMEOUT_MS. CLI: --scrape-timeout-ms. Default: 9800.
	scrape_timeout_ms: #ScrapetimeoutMs

	// collectors is the non-empty ordered list of enabled subsystem collectors.
	// Env: NFT_EXPORTER_COLLECTORS (comma-separated). CLI: --collectors.
	// Default: all six subsystems.
	collectors: [...#CollectorName] & [_, ...]

	// log_level controls the tracing filter level.
	// Env: NFT_EXPORTER_LOG_LEVEL. CLI: --log-level. Default: "info".
	log_level: #LogLevel

	// log_format selects JSON or human-readable text log output.
	// Env: NFT_EXPORTER_LOG_FORMAT. CLI: --log-format. Default: "json".
	log_format: #LogFormat

	// netlink_recv_buf_bytes is the SO_RCVBUF size set on all netlink sockets.
	// Increase on high-traffic nodes to reduce ENOBUFS errors.
	// Env: NFT_EXPORTER_NETLINK_RECV_BUF_BYTES. CLI: --netlink-recv-buf-bytes.
	// Default: 4194304 (4 MiB).
	netlink_recv_buf_bytes: #NetlinkRecvBufBytes
}

// #DefaultExporterConfig documents the production default values.
// Used in config validation tests and documentation generation.
#DefaultExporterConfig: #ExporterConfig & {
	listen:                 "0.0.0.0:9456"
	scrape_timeout_ms:      9800
	collectors:             ["rtnetlink", "traffic_control", "conntrack", "nftables", "sock_diag", "ethtool"]
	log_level:              "info"
	log_format:             "json"
	netlink_recv_buf_bytes: 4194304
}
