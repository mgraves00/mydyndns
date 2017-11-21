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
USER=""
PASS=""

PROG=`basename $0`

function usage {
	echo "$PROG <-h> <-d database_file> <-u user>"
	echo "  -h this screen"
	echo "  -d database file"
	echo "  -u user name"
}

function ask_pass {
	stty -echo
	IFS= read -r resp?"$1 "
	stty echo
	echo >&2
}

function get_pass {
	local _pass
	while :; do
		ask_pass "Enter Password (will not echo)"
		_pass=$resp
		ask_pass "Enter Password (again)"
		if [ "$resp" == "$_pass" ]; then
			break;
		fi
		echo "Passwords do not match" >&2
	done
	echo $_pass
}

function update_user {
	local _u=$1; shift;
	local _p=$1; shift;
	local _d=$1; shift;

	local _sql="INSERT OR REPLACE INTO user(name,hash) VALUES('$_u','$_p');"
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
	-u)
		USER=$2; shift; shift
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

if [ -z "$DATABASE" -o -z "$USER" ]; then
	echo "Database or user not specified"
	usage
	exit 1
fi

cPASS=`get_pass`
PASS=`sha1 -q -s "$cPASS"`
update_user "$USER" "$PASS" "$DATABASE"


