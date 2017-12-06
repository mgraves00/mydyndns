#!/bin/ksh

# Copyright (c) 2017 Michael Graves <mgraves@brainfat.net>
#  
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#  
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

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

args=`getopt d:ht:u: $*`
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

