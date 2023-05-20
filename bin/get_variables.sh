#/bin/bash

cat optimus.pl | sed -e "s/\s//g" | egrep '^\$ref' | awk -F "=" '{print$1}' | grep -v count | grep -v sum | sed -e "s/^\$ref->{\$primaryKey}->//g" | sed -e "s/{//g" | sed -e "s/}//g" | sed -e "s/->/\./g" | sed -e "s/\$ref\.\$key\.//g" | sort -d | uniq
