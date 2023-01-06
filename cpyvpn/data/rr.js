[{"CCCserverResponse":{
    "ResponseHeader":{
        "id":"",
        "type": "ClientHello",
        "session_id":"",
        "return_code":"600"
    },
    "ResponseData":{
        "protocol_version":{
            "protocol_version":"100",
            "features":"0x1"
        },
        "upgrade_configuration":{
            "available_client_version":835000022,
            "client_upgrade_url":"\"/CSHELL/\"",
            "upgrade_mode": "ask_user"
        },
        "connectivity_info":{
            "default_authentication_method":"client_decide",
            "client_enabled":"true",
            "supported_data_tunnel_protocols":[
                "SSL",
                "IPSec"
            ],
            "server_ip":"",
            "natt_port":"4500",
            "tcpt_port":"443",
            "connectivity_type":"client_decide",
            "ipsec_transport":"auto_detect",
            "connect_with_certificate_url":"\"/clients/cert/\"",
            "cookie_name":"CPCVPN_SESSION_ID",
            "internal_ca_fingerprint":{"1":"123456e7a7"}
        },
        "end_point_security": {
            "ics":{
                "run_ics":"false",
                "ics_base_url":"\"/clients/ICS/components\"",
                "ics_version":403006000,
                "ics_upgrade_url":"\"/clients/ICS/components/icsweb.cab\"",
                "ics_images_url":"\"/clients/ICS/components/ICS_images.cab\"",
                "ics_images_ver":403006000,
                "ics_cab_url":"\"/clients/ICS/components/cl_ics.cab\"",
                "ics_cab_version":"990000010\n"
            }
        },
		"login_options_data":{
			"login_options_list":{
				"0":{
					"id":"vpn",
					"secondary_realm_hash":"00112233445566778899aabbccddeeff",
					"display_name":"Standard",
					"show_realm":1,
					"factors":{
						"0":{
							"factor_type":"password",
							"securid_card_type":"",
							"certificate_storage_type":"",
							"custom_display_labels":{
								"header":"\"Please provide credentials to authenticate\"",
								"username":"\"User name\"",
								"password":"Password"
							}
						}
					}
				},
				"1":{
					"id":"vpn2",
					"secondary_realm_hash":"00112233445566778899aabbccddeeff",
					"display_name":"Legacy",
					"show_realm":1,
					"factors":{
						"0":{
							"factor_type":"password",
							"securid_card_type":"",
							"certificate_storage_type":"",
							"custom_display_labels":{
								"header":"\"1Please provide your credentials\"",
								"username":"\"Login\"",
								"password":"Password"
							}
						}
					}
				},
				"2":{
					"id":"vpn_2fa",
					"secondary_realm_hash":"00112233445566778899aabbccddeeff",
					"display_name":"SMS",
					"show_realm":1,
					"factors":{
						"0":{
							"factor_type":"password",
							"securid_card_type":"",
							"certificate_storage_type":"",
							"custom_display_labels":{
								"header":"\"Please provide user name and password to authenticate\"",
								"username":"\"User name\"",
								"password":"Password"
							}
						},
						"1":{
							"factor_type":"sms",
							"securid_card_type":"",
							"certificate_storage_type":"",
							"custom_display_labels":{
								"header":"\"An SMS\\Email with a verification code was sent to your phone\\Email account and should arrive shortly. Please type the verification code\"",
								"password":"\"Verification Code\""
							}
						}
					}
				}
			},
			"login_options_md5":"00112233445566778899aabbccddeeff"
		}
    }
}},

{"CCCserverResponse":{
    "ResponseHeader":{
        "id":"",
        "type": "UserPass",
        "session_id":"",
        "return_code":600
    },
    "ResponseData":{
        "authn_status":"done",
        "is_authenticated":"true",
        "active_key":"",
        "server_fingerprint":"",
        "server_cn":"",
        "session_id":"",
        "active_key_timeout":"3600"
    }
}},

{"CCCserverResponse":{
    "ResponseHeader":{
        "id":"",
        "type": "CertAuth",
        "session_id":"",
        "return_code":600
    },
    "ResponseData":{
        "authn_status":"done",
        "is_authenticated":"true",
        "active_key":"",
        "server_fingerprint":"",
        "server_cn":"",
        "session_id":"",
        "active_key_timeout":"3600"
    }
}},

{"CCCserverResponse":{
    "ResponseHeader":{
        "id":"",
        "type":"ClientSettings",
        "session_id":"",
        "return_code":600
    },
    "ResponseData":{
        "updated_policies": {
            "range":{
            "settings":[
                    {
                        "from":"192.168.16.0",
                        "to":"192.168.16.255"
                    }
                ],
                "expiry":1440,
                "id":"ea41b11c0567fa6a339e5f75b91fc37f",
                "name": "range"
            },
            "nemo_client_1": {
                "settings":{
                    "neo_route_all_traffic_through_gateway":"client_decide",
                    "location_awareness_enabled":"client_decide",
                    "location_awareness_wlan_networks_are_outside":"client_decide",
                    "location_awareness_wlan_network_names_not_outside":"client_decide",
                    "location_awareness_dns_suffixes_not_outside":"client_decide",
                    "location_awareness_dc_check":"client_decide",
                    "location_awareness_cache_locations":"client_decide",
                    "location_awareness_cache_internal_locations":"client_decide"
                },
                "expiry":-1,
                "id":"a36ba50746343446787cc5f0af8aeb2d",
                "name":"nemo_client_1"
            },
        "unchanged_policies":"",
        "unsupported_policies":"",
        "gateway_policy_version":"5f245b6f",
        "gw_internal_ip":""
        }
    }
}},

{"CCCserverResponse":{
    "ResponseHeader":{
        "id":"",
        "type":"KeyManagement",
        "session_id":"",
        "return_code":"600"
    },
    "ResponseData":{
        "client_encsa": {
            "enckey": "496591aa98aeea432dd27a9848bf0194",
            "authkey": "ab7a18e4282ddb234fb40be056a54280da08d5fb",
            "spi": "0x154d75f5"
        },
        "client_decsa":{
            "enckey":"fbee4eb8cfd66095e970e88b451d1e79",
            "authkey": "a99b44e66be2e306f3b68562c673227ef4556194",
            "spi":"0x77b1c677"
        },
        "om_addr":"",
        "om_subnet_mask":"",
        "om_nbns0":"0x00000000",
        "om_nbns1":"0x00000000",
        "om_nbns2":"0x00000000",
        "om_dns0":"0x00000000",
        "om_dns1":"0x00000000",
        "om_dns2":"0x00000000",
        "om_domain_name":"",
        "lifetime":"86399",
        "encalg":"AES-128",
        "authalg":"SHA1",
        "nattport":"4500",
        "udpencapsulation":"true"
    }
}},


{"CCCclientRequest":{
    "RequestHeader": {
        "id":"",
        "type": "Signout",
        "session_id":"",
        "protocol_version":""
    },
    "RequestData":""
}},

{"CCCserverResponse":{
    "ResponseHeader":{
        "id":"",
        "type": "Signout",
        "session_id":"",
        "return_code":"600"
    },
    "ResponseData":""
}},

{"disconnect":{
    "code": 28,
    "message": "User has disconnected."
    }
},

{"hello_reply":{
    "version":1,
    "protocol_version":1,
    "OM":{
        "ipaddr": "",
        "dns_servers": [
        ],
        "wins_servers":[],
        "dns_suffix":[]
    },
    "range":[
        {
            "from":"192.168.16.0",
            "to":"192.168.16.255"
        }
    ],
    "optional":{
        "subnet":"255.255.255.0"
    },
    "timeouts":{
        "authentication":604785,
        "keepalive":20
    }
}}]
