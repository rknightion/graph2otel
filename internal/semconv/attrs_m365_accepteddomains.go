package semconv

// Exchange Online accepted-domain attributes (#353, m365.exchange_accepted_domains).
// Reused where a key already exists: AttrDomain, AttrName, AttrId, AttrIsValid
// (attrs_m365.go), AttrDistinguishedName (attrs_defender.go), AttrAdminDisplayName
// (attrs_m365.go), AttrWhenChanged / AttrWhenCreated (attrs_m365.go),
// AttrAuthenticationType (attrs_entra.go). Only
// domain_type and is_default_domain are ever metric label VALUES, and both are
// bounded by the API (a handful of enum members / a strict boolean) rather than
// per-entity — the domain NAME itself is never a label (#112), it lives on the
// m365.exchange_accepted_domain log twin only.
//
// domain_type is intentionally NOT backed by an internal/wirecheck enum watcher:
// live measurement (2026-07-27, #353) observed exactly one value, "Authoritative",
// on the m7kni tenant. Microsoft's own docs additionally describe "InternalRelay"
// and "Mixed", but those are docs-only here — one observed value is not a value
// set, and a watchdog built off it would fire on perfectly correct data the first
// time a tenant's second domain type showed up. See the package doc.
const (
	AttrAddressBookEnabled        = "address_book_enabled"
	AttrAzureProvisioningRegion   = "azure_provisioning_region"
	AttrCatchAllRecipientId       = "catch_all_recipient_id"
	AttrDomainType                = "domain_type"
	AttrEmailOnly                 = "email_only"
	AttrExchangeVersion           = "exchange_version"
	AttrExternallyManaged         = "externally_managed"
	AttrFederatedOrganizationLink = "federated_organization_link"
	AttrIsCoexistenceDomain       = "is_coexistence_domain"
	AttrIsDefaultDomain           = "is_default_domain"
	AttrIsInitialDomain           = "is_initial_domain"
	AttrMailFlowRegion            = "mail_flow_region"
	AttrMatchSubdomains           = "match_subdomains"
	AttrOutboundOnly              = "outbound_only"
	AttrPendingCompletion         = "pending_completion"
	AttrPendingRemoval            = "pending_removal"
	AttrSendingFromDomainDisabled = "sending_from_domain_disabled"
	AttrSendingToDomainDisabled   = "sending_to_domain_disabled"
	AttrSmtpDaneStatus            = "smtp_dane_status"
)
