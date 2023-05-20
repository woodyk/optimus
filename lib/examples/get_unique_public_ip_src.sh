curl -s -XGET $1:9200/packets_*/_search?pretty -H 'Content-Type: application/json' -d '
{
  "aggs": {
    "keys": {
      "terms": {
        "field": "ip.src",
        "size": 10000
      }
    }
  },
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {
          "query_string": {
            "query": "(ip.src:10.1.10.10 OR ip.dst:10.1.10.10) NOT (ip.src:10.1.10.1 OR ipdst:10.1.10.1)",
            "analyze_wildcard": true,
            "time_zone": "America/New_York"
          }
        }
      ],
      "filter": [
        {
          "range": {
            "date": {
              "format": "strict_date_optional_time",
              "gte": "now-1h/h",
              "lte": "now"
            }
          }
        }
      ],
      "should": [],
      "must_not": []
    }
  }
}
'
