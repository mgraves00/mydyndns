#!/bin/ksh

DATABASE=""
TIME="30"

PROG=`basename $0`

function usage {
	echo "$PROG <-h> <-d database_file> [-t days]"
	echo "  -h this screen"
	echo "  -d database file"
	echo "  -t number of days of no activity"
}

function cleanup_domain {
	local _d=$1; shift;
	local _t=$1; shift;

	local _sql="DELETE FROM domain WHERE timestamp < datetime('now','-$_t days');"
	printf "$_sql" | sqlite3 $_d
}

args=`getopt d:hu: $*`
if [ $? -ne 0 ]; then
	usage
	exit 2
fi

set -- $args
while [ $# -ne 0 ]; do
	case "$1" in
	-d)
		DATABASE=$2; shift; shift
		;;
	-h)
		usage
		exit 0
		;;
	-t)
		TIME=$2; shift; shift
		;;
	--)
		shift; break;;
	*)
		echo "unknown option: $1"
		usage
		exit 1
		;;
	esac
done

if [ -z "$DATABASE" ]; then
	echo "Database not specified"
	usage
	exit 1
fi

cleanup_domain "$DATABASE" "$TIME"

