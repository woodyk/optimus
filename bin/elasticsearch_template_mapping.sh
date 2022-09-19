curl -XPUT "$1:9200/_template/pcap_data_template?pretty" -H 'Content-Type: application/json' -d'
{
    "index_patterns" : ["profile_*"],
    "settings" : { "number_of_shards" : 1 },
    "mappings" : {
        "properties" : {
          "dns" : {
            "properties" : {
              "src" : {
                "type" : "text"
              },
              "dst" : {
                "type" : "text"
              }
            }
          },
          "igmp" : {
            "properties" : {
              "group_addr" : {
                "type" : "ip"
              },
              "subtype" : {
                "type" : "long"
              },
              "data" : {
                "type" : "text"
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
          "datasource" : {
            "type" : "keyword"
          }, 
          "filename" : {
            "type" : "keyword"
          },
	  "mac" : {
            "properties" : {
              "src" : {
                "type" : "keyword"
              },
              "dst" : {
                "type" : "keyword"
              }
            }
          },
          "tcp" : {
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
                "type" : "text"
              },
              "reserved" : {
                "type" : "long"
              },
              "window_size" : {
                "type" : "long"
              },
              "data" : {
                "type" : "text"
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
          "country_code" : {
            "type" : "keyword"
          },
          "udp" : {
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
                "type" : "text"
              }
            }
          },
          "region_name" : {
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
            "properties" : {
              "src" : {
                "type" : "ip"
              },
              "options" : {
                "type" : "keyword"
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
          "l7" : {
            "properties" : {
              "proto" : {
                "type" : "keyword"
              }
            }
          },
          "http" : {
            "properties" : {
              "response" : {
                "properties" : {
                  "code" : {
                    "type" : "long"
                  }
                }
              },
              "request" : {
                "properties" : {
                  "uri" : {
                    "type" : "keyword"
                  }
                }
              },
              "header" : {
                "properties" : {
                  "host" : {
                    "type" : "keyword"
                  },
                  "cookie" : {
                    "type" : "keyword"
                  },
                  "referer" : {
                    "type" : "keyword"
                  },
                  "user-agent" : {
                    "type" : "keyword"
                  }
                }
              }
            }
          },
          "raw" : {
            "properties" : {
              "ip" : {
                "properties" : {
                  "src" : {
                    "type" : "keyword"
                  },
                  "dst" : {
                    "type" : "keyword"
                  }
                }
              }
            }
          },
          "icmp" : {
            "properties" : {
              "type" : {
                "type" : "long"
              },
              "data" : {
                "type" : "text"
              },
              "code" : {
                "type" : "long"
              }
            }
          },
          "l2" : {
            "properties" : {
              "proto" : {
                "type" : "keyword"
              }
            }
          },
          "arp" : {
            "properties" : {
              "htype" : {
                "type" : "keyword"
              },
              "proto" : {
                "type" : "keyword"
              },
              "hlen" : {
                "type" : "keyword"
              },
              "opcode" : {
                "type" : "keyword"
              },
              "sha" : {
                "type" : "keyword"
              },
              "spa" : {
                "type" : "keyword"
              },
              "tha" : {
                "type" : "keyword"
              },
              "tpa" : {
                "type" : "keyword"
              }
            }
          },  
          "time_zone" : {
            "type" : "keyword"
          },
          "city" : {
            "type" : "keyword"
          },
          "country_name" : {
            "type" : "keyword"
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
            "type" : "keyword"
          },
          "location" : {
            "type" : "geo_point"
          },
          "vendor" : {
            "type" : "keyword"
          }
        }
    },
    "aliases" : { }
  }
}'
