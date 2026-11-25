package semconv

// Teams admin API (teams_admin transport) Direct Routing gateway and SIP device
// configuration twin attributes (#722). Every key is the event prefix plus the
// snake_case of its wire field (adminmap.SnakeKey), except the *_authority keys,
// which come from ConfigMetadata.Authority. AttrEnabled is reused from
// attrs_intune.go for the teams.pstn_gateway.count gauge label.
//
// pstn_gateway_outbund_teams_number_translation_rules keeps Microsoft's
// misspelling of the wire field OutbundTeamsNumberTranslationRules on purpose.
const (
	// teams.pstn_gateway twin.
	AttrPstnGatewayIdentity                           = "pstn_gateway_identity"
	AttrPstnGatewayFqdn                               = "pstn_gateway_fqdn"
	AttrPstnGatewaySipSignalingPort                   = "pstn_gateway_sip_signaling_port"
	AttrPstnGatewayFailoverTimeSeconds                = "pstn_gateway_failover_time_seconds"
	AttrPstnGatewayForwardCallHistory                 = "pstn_gateway_forward_call_history"
	AttrPstnGatewayForwardPai                         = "pstn_gateway_forward_pai"
	AttrPstnGatewaySendSipOptions                     = "pstn_gateway_send_sip_options"
	AttrPstnGatewayMaxConcurrentSessions              = "pstn_gateway_max_concurrent_sessions"
	AttrPstnGatewayEnabled                            = "pstn_gateway_enabled"
	AttrPstnGatewayMediaBypass                        = "pstn_gateway_media_bypass"
	AttrPstnGatewayGatewaySiteId                      = "pstn_gateway_gateway_site_id"
	AttrPstnGatewayGatewaySiteLbrEnabled              = "pstn_gateway_gateway_site_lbr_enabled"
	AttrPstnGatewayGatewayLbrEnabledUserOverride      = "pstn_gateway_gateway_lbr_enabled_user_override"
	AttrPstnGatewayFailoverResponseCodes              = "pstn_gateway_failover_response_codes"
	AttrPstnGatewayPidfLoSupported                    = "pstn_gateway_pidf_lo_supported"
	AttrPstnGatewayMediaRelayRoutingLocationOverride  = "pstn_gateway_media_relay_routing_location_override"
	AttrPstnGatewayProxySbc                           = "pstn_gateway_proxy_sbc"
	AttrPstnGatewayBypassMode                         = "pstn_gateway_bypass_mode"
	AttrPstnGatewayDescription                        = "pstn_gateway_description"
	AttrPstnGatewayIpAddressVersion                   = "pstn_gateway_ip_address_version"
	AttrPstnGatewayInviteWithReplaces                 = "pstn_gateway_invite_with_replaces"
	AttrPstnGatewayAuthority                          = "pstn_gateway_authority"
	AttrPstnGatewayInboundTeamsNumberTranslationRules = "pstn_gateway_inbound_teams_number_translation_rules"
	AttrPstnGatewayInboundPstnNumberTranslationRules  = "pstn_gateway_inbound_pstn_number_translation_rules"
	AttrPstnGatewayOutbundTeamsNumberTranslationRules = "pstn_gateway_outbund_teams_number_translation_rules"
	AttrPstnGatewayOutboundPstnNumberTranslationRules = "pstn_gateway_outbound_pstn_number_translation_rules"

	// Companion _count keys for the four translation-rule lists.
	AttrPstnGatewayInboundTeamsNumberTranslationRulesCount = "pstn_gateway_inbound_teams_number_translation_rules_count"
	AttrPstnGatewayInboundPstnNumberTranslationRulesCount  = "pstn_gateway_inbound_pstn_number_translation_rules_count"
	AttrPstnGatewayOutbundTeamsNumberTranslationRulesCount = "pstn_gateway_outbund_teams_number_translation_rules_count"
	AttrPstnGatewayOutboundPstnNumberTranslationRulesCount = "pstn_gateway_outbound_pstn_number_translation_rules_count"

	// teams.sip_devices_configuration twin.
	AttrSipDevicesIdentity   = "sip_devices_identity"
	AttrSipDevicesBulkSignIn = "sip_devices_bulk_sign_in"
	AttrSipDevicesAuthority  = "sip_devices_authority"

	// teams.ip_phone_policy twin.
	AttrIpPhonePolicyIdentity                       = "ip_phone_policy_identity"
	AttrIpPhonePolicyDescription                    = "ip_phone_policy_description"
	AttrIpPhonePolicySignInMode                     = "ip_phone_policy_sign_in_mode"
	AttrIpPhonePolicySearchOnCommonAreaPhoneMode    = "ip_phone_policy_search_on_common_area_phone_mode"
	AttrIpPhonePolicyAllowHomeScreen                = "ip_phone_policy_allow_home_screen"
	AttrIpPhonePolicyAllowBetterTogether            = "ip_phone_policy_allow_better_together"
	AttrIpPhonePolicyAllowHotDesking                = "ip_phone_policy_allow_hot_desking"
	AttrIpPhonePolicyHotDeskingIdleTimeoutInMinutes = "ip_phone_policy_hot_desking_idle_timeout_in_minutes"
	AttrIpPhonePolicyAuthority                      = "ip_phone_policy_authority"
)
