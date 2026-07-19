package semconv

// Attribute keys used only by mdca.* collectors — the Microsoft Defender for
// Cloud Apps Cloud-Discovery governance signal (#145). Shared keys these
// records also emit (file_size via AttrFileSize, state via AttrState,
// ingest_transport via AttrIngestTransport) are reused from the other
// attrs_*.go files, never redeclared. Every key is a semconv.Attr* constant
// (Gate B); no value duplicates another constant (Gate A).
const (
	// AttrTemplate is status.templateMessage.template — the STABLE enum key that
	// distinguishes parse outcomes (e.g. ..._PARSED_LOG_FILE_ALL_RELEVANT vs
	// ..._UNEXPECTED_FORMAT). Alert on this, never on the localized
	// statusMessage prose.
	AttrTemplate = "template"
	// AttrIsSuccess is status.isSuccess — the boolean parse verdict. Redundant
	// with AttrTemplate (which distinguishes WHICH failure) but both ship.
	AttrIsSuccess = "is_success"
	// AttrDataSource is the Cloud Discovery log format (e.g. GENERIC_CEF), from
	// logTypeName / templateMessage.parameters.dataSource.
	AttrDataSource = "data_source"
	// AttrLogType is the numeric MDCA log-type id (e.g. 179 for GENERIC_CEF).
	AttrLogType = "log_type"
	// AttrInputStreamId is the Cloud Discovery input stream a parse task belongs
	// to. Streams are single-digit per tenant, so this bounds the parse-health
	// gauges' cardinality by tenant shape, not tenant size (#112).
	AttrInputStreamId = "input_stream_id"
	// AttrTransactionsCount is templateMessage.parameters.transactionsCount — the
	// discovered transactions in a successful parse. A collapse to zero is the
	// "parsed fine, discovered nothing" case.
	AttrTransactionsCount = "transactions_count"
	// AttrCloudServicesCount is templateMessage.parameters.cloudServicesCount —
	// distinct cloud apps discovered in a successful parse.
	AttrCloudServicesCount = "cloud_services_count"
)
