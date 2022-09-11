curl -XPUT 'es1.vm.sr:9200/_template/pcap_template?pretty' -H 'Content-Type: application/json' -d'
{
  "template" : "pcap_template",
  "index_patterns" : ["profile_*"],
  "mappings" : {
      "_default_" : {
         "properties" : {
            "igmp" : {
	       "type": "nested",
               "properties" : {
                  "group_addr" : {
                     "type" : "ip"
                  },
                  "subtype" : {
                     "type" : "long"
                  },
                  "data" : {
                     "type" : "keyword",
                     "index" : "not_analyzed"
                  },
                  "type" : {
                     "type" : "long"
                  },
                  "version" : {
                     "type" : "long"
                  },
                  "len" : {
                     "type" : "long"
                  }
               }
            },
            "metro_code" : {
               "type" : "keyword"
            },
            "tcp" : {
               "type": "nested",
               "properties" : {
                  "hlen" : {
                     "type" : "long"
                  },
                  "acknum" : {
                     "type" : "long"
                  },
                  "urg" : {
                     "type" : "long"
                  },
                  "flag" : {
                     "type": "nested",
                     "properties" : {
                        "CWR" : {
                           "type" : "boolean"
                        },
                        "NS" : {
                           "type" : "boolean"
                        },
                        "PSH" : {
                           "type" : "boolean"
                        },
                        "SYN" : {
                           "type" : "boolean"
                        },
                        "URG" : {
                           "type" : "boolean"
                        },
                        "ECE" : {
                           "type" : "boolean"
                        },
                        "RST" : {
                           "type" : "boolean"
                        },
                        "ACK" : {
                           "type" : "boolean"
                        },
                        "FIN" : {
                           "type" : "boolean"
                        }
                     }
                  },
                  "options" : {
                     "type" : "long"
                  },
                  "seq" : {
                     "type" : "long"
                  },
                  "dstport" : {
                     "type" : "long"
                  },
                  "srcport" : {
                     "type" : "long"
                  },
                  "flags" : {
                     "type" : "keyword"
                  },
                  "reserved" : {
                     "type" : "long"
                  },
                  "window_size" : {
                     "type" : "long"
                  },
                  "data" : {
                     "type" : "keyword",
                     "index" : "not_analyzed"
                  },
                  "cksum" : {
                     "type" : "long"
                  }
               }
            },
            "packets" : {
               "type" : "long"
            },
            "tags" : {
               "type" : "keyword"
            },
            "country_code3" : {
               "type" : "keyword"
            },
            "src_mac" : {
               "type" : "keyword"
            },
            "country_code" : {
               "type" : "keyword"
            },
            "udp" : {
               "type": "nested",
               "properties" : {
                  "len" : {
                     "type" : "long"
                  },
                  "dstport" : {
                     "type" : "long"
                  },
                  "srcport" : {
                     "type" : "long"
                  },
                  "data" : {
                     "index" : "not_analyzed",
                     "type" : "keyword"
                  }
               }
            },
            "region_name" : {
               "type" : "keyword"
            },
            "dest_mac" : {
               "type" : "keyword"
            },
            "area_code" : {
               "type" : "keyword"
            },
            "longitude" : {
               "type" : "keyword"
            },
            "region" : {
               "type" : "keyword"
            },
            "postal_code" : {
               "type" : "keyword"
            },
            "ip6" : {
               "type": "nested",
               "properties" : {
                  "src" : {
                     "type" : "ip"
                  },
                  "dst" : {
                     "type" : "ip"
                  },
                  "nxt" : {
                     "type" : "long"
                  },
                  "flow" : {
                     "type" : "long"
                  },
                  "class" : {
                     "type" : "long"
                  },
                  "plen" : {
                     "type" : "long"
                  },
                  "hlim" : {
                     "type" : "long"
                  }
               }
            },
            "ip" : {
               "type": "nested",
               "properties" : {
                  "src" : {
                     "type" : "ip"
                  },
                  "options" : {
                     "type" : "long"
                  },
                  "dst" : {
                     "type" : "ip"
                  },
                  "ttl" : {
                     "type" : "long"
                  },
                  "ver" : {
                     "type" : "long"
                  },
                  "hlen" : {
                     "type" : "long"
                  },
                  "tos" : {
                     "type" : "long"
                  },
                  "foffset" : {
                     "type" : "long"
                  },
                  "proto" : {
                     "type" : "keyword"
                  },
                  "cksum" : {
                     "type" : "long"
                  },
                  "len" : {
                     "type" : "long"
                  },
                  "flags" : {
                     "type" : "long"
                  }
               }
            },
            "date" : {
               "type" : "date"
            },
            "continent_code" : {
               "type" : "keyword"
            },
            "int" : {
               "type" : "keyword"
            },
            "latitude" : {
               "type" : "keyword"
            },
            "hostname" : {
               "type" : "keyword",
               "index" : "not_analyzed"
            },
            "location" : {
               "type" : "geo_point"
            },
            "l7" : {
               "type": "nested",
               "properties" : {
                  "proto" : {
                     "type" : "keyword"
                  }
               }
            },
            "http" : {
               "type": "nested",
               "properties" : {
		  "response" : {
		     "type": "nested",
		     "properties" : {
			"code" : {
			   "type" : "long"
			}
		      }
		  },
                  "request" : {
                     "type": "nested",
                     "properties" : {
                        "uri" : {
                           "type" : "keyword",
                           "index" : "not_analyzed"
                        }
                     }
                  },
                  "header" : {
                     "type": "nested",
                     "properties" : {
                        "host" : {
                           "type" : "keyword",
                           "index" : "not_analyzed"
                        },
                        "cookie" : {
                           "type" : "keyword",
                           "index" : "not_analyzed"
                        },
                        "referer" : {
                           "type" : "keyword",
                           "index" : "not_analyzed"
                        },
                        "user-agent" : {
                           "type" : "keyword",
                           "index" : "not_analyzed"
                        }
                     }
                  }
               }
            },
            "raw" : {
               "type": "nested",
               "properties" : {
                  "ip" : {
                     "type": "nested",
                     "properties" : {
                        "src" : {
                           "index" : "not_analyzed",
                           "type" : "keyword"
                        },
                        "dst" : {
                           "type" : "keyword",
                           "index" : "not_analyzed"
                        }
                     }
                  }
               }
            },
            "country_name" : {
               "type" : "keyword"
            },
            "icmp" : {
               "type": "nested",
               "properties" : {
                  "type" : {
                     "type" : "long"
                  },
                  "data" : {
                     "type" : "keyword",
                     "index" : "not_analyzed"
                  },
                  "code" : {
                     "type" : "long"
                  }
               }
            },
            "time_zone" : {
               "type" : "keyword"
            },
            "city" : {
               "type" : "keyword"
            }
         }
      }
   }
}
'
