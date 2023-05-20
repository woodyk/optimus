echo "Creating GeoIP pipeline."
curl -XPUT "$1/_ingest/pipeline/optimus_geoip?pretty" -H 'Content-Type: application/json' -d'
{
  "processors": [
    {
      "geoip": {
        "field": "ip.dst",
        "target_field": "geoip.dst",
        "ignore_failure": true
      }
    },
    {
      "geoip": {
        "field": "ip.src",
        "target_field": "geoip.src",
        "ignore_failure": true
      }
    }
  ]
}
'

echo "Creating index lifecycle policy."
curl -XPUT "$1/_ilm/policy/optimus_policy?pretty" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "set_priority": {
            "priority": 100
          }
        },
        "min_age": "0ms"
      },
      "warm": {
        "min_age": "2h",
        "actions": {
          "set_priority": {
            "priority": 50
          },
          "readonly": {}
        }
      },
      "delete": {
        "min_age": "26h",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
'

echo "Creating index template mapping."
curl -XPUT "$1/_index_template/optimus_template?pretty" -H 'Content-Type: application/json' -d'
{
  "template": {
    "settings": {
      "index": {
        "lifecycle": {
          "name": "optimus_policy"
        },
        "routing": {
          "allocation": {
            "include": {
              "_tier_preference": "data_content"
            }
          }
        },
        "number_of_shards": 1,
        "default_pipeline": "optimus_geoip"
      },
      "search": {
        "idle": {
          "after": "3600s"
        }
      }
    },
    "mappings": {
      "dynamic_templates": [],
      "properties": {
        "arp": {
          "type": "object",
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
              "type": "keyword"
            },
            "spa": {
              "type": "keyword"
            },
            "tha": {
              "type": "keyword"
            },
            "tpa": {
              "type": "keyword"
            }
          }
        },
	"http": {
          "properties": {
            "request": {
              "properties": {
                "header": {
                  "type": "object"
                },
                "method": {
                  "type": "keyword"
                },
                "uri": {
                  "type": "text",
                  "fields": {
                    "keyword": { 
                      "type": "keyword"
                    }     
                  }
                },
                "version": {
                  "type": "keyword"
                }
              }
            },
            "response": {
              "properties": {
                "header": {
                  "type": "object"
                },
                "code": {
                  "type": "integer"
                },
                "status": {
                  "type": "keyword"
                },
                "version": {
                  "type": "keyword"
                }
              }
            }
          }
        },
        "datasource": {
          "type": "keyword"
        },
        "date": {
          "type": "date"
        },
        "hostname": {
          "type": "keyword"
        },
        "icmp": {
          "type": "object",
          "properties": {
            "code": {
              "type": "long"
            },
            "data": {
              "type": "text",
              "fields": {
                "keyword": { 
                  "type": "keyword"
                }     
              }
            },
            "type": {
              "type": "long"
            }
          }
        },
        "igmp": {
          "properties": {
            "cksum": {
              "type": "integer"
            },
            "group_addr": {
              "type": "ip"
            },
            "len": {
              "type": "integer"
            },
            "subtype": {
              "type": "integer"
            },
            "type": {
              "type": "integer"
            },
            "version": {
              "type": "integer"
            }
          }
        },
        "interface": {
          "type": "keyword"
        },
        "ip": {
          "type": "object",
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
              "type": "keyword"
            },
            "proto": {
              "type": "keyword"
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
            },
            "type": {
              "type": "keyword"
            }
          }
        },
        "ipv6_icmp": {
          "type": "object",
          "properties": {
            "cksum": {
              "type": "long"
            },
            "code": {
              "type": "long"
            },
            "data": {
              "type": "text",
              "fields": {
                "keyword": { 
                  "type": "keyword"
                }     
              }
            },
            "type": {
              "type": "long"
            }
          }
        },
        "mac": {
          "type": "object",
          "properties": {
            "dst": {
              "type": "keyword"
            },
            "dst_vendor": {
              "type": "keyword"
            },
            "src": {
              "type": "keyword"
            },
            "src_vendor": {
              "type": "keyword"
            }
          }
        },
        "protos": {
          "type": "object",
          "properties": {
            "l2": {
              "type": "keyword"
            },
            "l3": {
              "type": "keyword"
            },
            "l4": {
              "type": "keyword"
            },
            "l5": {
              "type": "keyword"
            },
            "l6": {
              "type": "keyword"
            },
            "l7": {
              "type": "keyword"
            }
          }
        },
        "tcp": {
          "type": "object",
          "properties": {
            "acknum": {
              "type": "long"
            },
            "cksum": {
              "type": "long"
            },
            "data": {
              "type": "text",
              "fields": {
                "keyword": { 
                  "type": "keyword"
                }     
              }
            },
            "dstport": {
              "type": "long"
            },
            "flag": {
              "type": "object",
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
            "seqnum": {
              "type": "long"
            },
            "srcport": {
              "type": "long"
            },
            "urg": {
              "type": "long"
            },
            "winsize": {
              "type": "long"
            }
          }
        },
        "udp": {
          "type": "object",
          "properties": {
            "data": {
              "type": "text",
              "fields": {
                "keyword": { 
                  "type": "keyword"
                }     
              }
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
        },
	"geoip": {
          "properties": {
            "dst": {
              "properties": {
                "location": {
                  "type": "geo_point",
                  "ignore_malformed": false,
                  "ignore_z_value": true
                }
              }
            },
            "src": {
              "properties": {
                "location": {
                  "type": "geo_point",
                  "ignore_malformed": false,
                  "ignore_z_value": true
                }
              }
            }
          }
        },
        "dns": {
          "type": "object",
          "properties": {
            "src": {
              "type": "text",
              "fields": {
                "keyword": { 
                  "type": "keyword"
                }     
              }
            },
            "dst": {
              "type": "text",
              "fields": {
                "keyword": { 
                  "type": "keyword"
                }     
              }
            }
          }
        }
      }
    }
  },
  "index_patterns": [
    "packets_*"
  ]
}
'
