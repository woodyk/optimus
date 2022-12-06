echo "Preparing Kibana Index and Visualizations"
curl -X POST -F "file=@$2" -H "kbn-xsrf: true" http://$1/api/saved_objects/_import
echo
