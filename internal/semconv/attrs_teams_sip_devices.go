package semconv

// Teams SIP device observation attributes. Device and connection health come
// from different Graph resources; the software field records presence only.
const (
	AttrSIPHealthStatus                   = "health_status"
	AttrSIPConnectionStatus               = "connection_status"
	AttrSIPConnectionLastModifiedDateTime = "connection_last_modified_date_time"
	AttrSIPSoftwareUpdateReadout          = "software_update_readout"
)
