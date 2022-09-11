#!/bin/bash
#
# Monitor the upload directory for new pcaps.  

RACHET="/var/www/html/upload/assets/prime/rachet.pl";
UPLOADS="/var/www/html/upload/uploads";
UUIDGEN="/usr/bin/uuidgen";
cd $UPLOADS

# Prep process lockfile to avoid clobbering
LOCKFILE="/var/run/lock/pcap_directory_monitor.lck";
if [ -f $LOCKFILE ] ; then
	pid=`cat $LOCKFILE`;
	printf "error: $0 process already running. Lockfile $LOCKFILE\n";
	exit 1
else
	echo "$$" >> $LOCKFILE;
fi

# Where all the files will live when the import has been completed.
ARCHIVE="/var/www/html/upload/archive";
if [ ! -d "$ARCHIVE" ]; then
	printf "$ARCHIVE not found. exiting ...\n";
	mkdir -p "$ARCHIVE"
fi

list="`find $UPLOADS -cmin +1 -type f`"
find $UPLOADS -name \*.zip -exec unzip {} \;
find $UPLOADS -name \*.gz -exec gunzip {} \;
find $UPLOADS -name \*.tar -exec tar -xvf {} \;

# Cycle through pcap files and index them.
counter=0;
for x in $UPLOADS/*.pcap; do
	if [ $(find "${x}" -ctime +1 -type f -print) ]; then
		counter=`echo "$counter + 1" | bc -l`
		NEWFILE="$ARCHIVE/`$UUIDGEN`.pcap"
		mv "${x}" "${NEWFILE}"
		$RACHET ${NEWFILE}
		#printf "$RACHET ${NEWFILE}\n"
	fi
done

/usr/bin/logger "$0 processed $counter pcap files.\n"

# Clen up remaining files.
for a in $list; do
	rm -rf "${a}"
done

# Remove lock file
rm -f $LOCKFILE

exit 0
