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
EMAIL=""
ORIGIN=""
# refresh retry expire minimum
MIN=3600
EXP=64800
REF=3600
RET=600

PROG=`basename $0`

function usage {
	echo "$PROG <-h> <-d database_file> <-o origin domain> [-e email] [-r refresh] [-t retry] [-x expire] [-m minimum]"
	echo "  -d database file"
	echo "  -e admin email for domain"
	echo "  -h this screen"
	echo "  -m minimum ttl (default $MIN)"
	echo "  -o origin domain"
	echo "  -r refresh (default $REF)"
	echo "  -t retry (default $RET)"
	echo "  -x expire (default $EXP)"
}

function get_domain {
	local _d=$1; shift;

	local _sql="SELECT name,address,ttl FROM domain;"
	printf ".separator ,\n$_sql" | /usr/local/bin/sqlite3 $_d
}

function print_head {
	printf "; Automatically generated by %s\n" $PROG
	printf ";"; date
	printf ";\n"
}

function print_soa {
	local _o=$1; shift;
	local _e=$1; shift;
	local _refresh=$1; shift;
	local _retry=$1; shift;
	local _expire=$1; shift;
	local _min=$1; shift;
	local _sn=`date +"%y%m%d%H%M"`

	printf "\$ORIGIN %s.\n" $_o
	printf "@ SOA %s. %s. ( %s %s %s %s %s )\n" $_o $_e $_sn $_refresh $_retry $_expire $_min
}

args=`getopt d:e:hm:o:r:t:x: $*`
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
	-e)
		EMAIL=$2; shift; shift`date +"%Y%m%d%H%M%S"`
		;;
	-h)
		usage
		exit 0
		;;
	-m)	
		MIN=$2; shift; shift
		;;
	-o)
		ORIGIN=`echo $2 | sed -r 's/\.+$//g'`;
		shift; shift
		;;
	-r)
		REF=$2; shift; shift
		;;
	-t)
		RET=$2; shift; shift
		;;
	-x)
		EXP=$2; shift; shift
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

if [ -z "$DATABASE" -o -z "$ORIGIN" ]; then
	echo "Database or origin not specified"
	usage
	exit 1
fi

if [ -z "$EMAIL" ]; then
	EMAIL="admin.$ORIGIN"
fi

print_head
print_soa "$ORIGIN" "$EMAIL" "$REF" "$RET" "$EXP" "$MIN"
get_domain "$DATABASE" | awk 'BEGIN { FS="," }{ printf "%s. %s IN A %s", $1, $3, $2 }'

