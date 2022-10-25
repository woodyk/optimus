curl -XPUT "$1:9200/_template/optimus_data_template?pretty" -H 'Content-Type: application/json' -d'
{
	"index_patterns": ["packets_*"],
	"settings": {
		"number_of_shards": 1,
		"default_pipeline": "optimus_geoip"
	},
	"mappings": {
		"properties": {
			"arp": {
				"properties": {
					"hlen": {
						"type": "long"
					},
					"htype": {
						"type": "long"
					},
					"opcode": {
						"type": "long"
					},
					"proto": {
						"type": "long"
					},
					"sha": {
						"type": "text"
					},
					"spa": {
						"type": "text"
					},
					"tha": {
						"type": "text"
					},
					"tpa": {
						"type": "text"
					}
				}
			},
			"datasource": {
				"type": "text"
			},
			"date": {
				"type": "date"
			},
			"geoip": {
				"properties": {
					"dst": {
						"properties": {
							"city": {
								"type": "text"
							},
							"continent_name": {
								"type": "text"
							},
							"country_code": {
								"type": "text"
							},
							"country_name": {
								"type": "text"
							},
							"location": {
								"type": "geo_point"
							},
							"postal_code": {
								"type": "text"
							},
							"subdivision_code": {
								"type": "text"
							},
							"subdivision_name": {
								"type": "text"
							},
							"time_zone": {
								"type": "text"
							}
						}
					},
					"src": {
						"properties": {
							"city": {
								"type": "text"
							},
							"continent_name": {
								"type": "text"
							},
							"country_code": {
								"type": "text"
							},
							"country_name": {
								"type": "text"
							},
							"location": {
								"type": "geo_point"
							},
							"postal_code": {
								"type": "text"
							},
							"subdivision_code": {
								"type": "text"
							},
							"subdivision_name": {
								"type": "text"
							},
							"time_zone": {
								"type": "text"
							}
						}
					}
				}
			},
			"hostname": {
				"type": "text"
			},
			"icmp": {
				"properties": {
					"code": {
						"type": "long"
					},
					"data": {
						"type": "text"
					},
					"type": {
						"type": "long"
					}
				}
			},
			"interface": {
				"type": "text"
			},
			"ip": {
				"properties": {
					"cksum": {
						"type": "long"
					},
					"class": {
						"type": "long"
					},
					"dst": {
						"type": "ip"
					},
					"flags": {
						"type": "long"
					},
					"flow": {
						"type": "long"
					},
					"foffset": {
						"type": "long"
					},
					"hlen": {
						"type": "long"
					},
					"hop_limit": {
						"type": "long"
					},
					"len": {
						"type": "long"
					},
					"options": {
						"type": "text"
					},
					"proto": {
						"type": "text"
					},
					"src": {
						"type": "ip"
					},
					"tos": {
						"type": "long"
					},
					"ttl": {
						"type": "long"
					},
					"ver": {
						"type": "long"
					}
				}
			},
			"ipv6_icmp": {
				"properties": {
					"cksum": {
						"type": "long"
					},
					"code": {
						"type": "long"
					},
					"data": {
						"type": "text"
					},
					"type": {
						"type": "long"
					}
				}
			},
			"mac": {
				"properties": {
					"dst": {
						"type": "text"
					},
					"dst_vendor": {
						"type": "text"
					},
					"src": {
						"type": "text"
					},
					"src_vendor": {
						"type": "text"
					}
				}
			},
			"protos": {
				"properties": {
					"l2": {
						"type": "text"
					},
					"l3": {
						"type": "text"
					},
					"l4": {
						"type": "text"
					},
					"l5": {
						"type": "text"
					},
					"l6": {
						"type": "text"
					},
					"l7": {
						"type": "text"
					}
				}
			},
			"tcp": {
				"properties": {
					"acknum": {
						"type": "long"
					},
					"cksum": {
						"type": "long"
					},
					"data": {
						"type": "text"
					},
					"dstport": {
						"type": "long"
					},
					"flag": {
						"properties": {
							"ACK": {
								"type": "boolean"
							},
							"CWR": {
								"type": "boolean"
							},
							"ECE": {
								"type": "boolean"
							},
							"FIN": {
								"type": "boolean"
							},
							"NS": {
								"type": "boolean"
							},
							"PSH": {
								"type": "boolean"
							},
							"RST": {
								"type": "boolean"
							},
							"SYN": {
								"type": "boolean"
							},
							"URG": {
								"type": "boolean"
							}
						}
					},
					"flags": {
						"type": "text"
					},
					"hlen": {
						"type": "long"
					},
					"reserved": {
						"type": "long"
					},
					"seq": {
						"type": "long"
					},
					"srcport": {
						"type": "long"
					},
					"urg": {
						"type": "long"
					},
					"window_size": {
						"type": "long"
					}
				}
			},
			"udp": {
				"properties": {
					"data": {
						"type": "text"
					},
					"dstport": {
						"type": "long"
					},
					"len": {
						"type": "long"
					},
					"srcport": {
						"type": "long"
					}
				}
			}
		}
	}
}'
