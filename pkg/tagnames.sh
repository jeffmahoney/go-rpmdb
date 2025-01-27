#!/bin/bash
#
name="$(basename "$0")"
out="$1"

if test -z "$out"; then
	echo "usage: $name <output filename>" >&2
	exit 1
fi

cat <<END > $out
package rpmdb
// generated by $name; DO NOT EDIT

var tagNameToIdMap = map[string]int32 {
END

sed -ne '/RPMTAG_/s/.*\(RPMTAG_[A-Z0-9_]*\).*/   "\1" : \1,/p' rpmtags.go >> $out
sed -ne '/RPMTAG_/s/.*\(RPMTAG_\([A-Z0-9_]*\)\).*/   "\2" : \1,/p' rpmtags.go >> $out
cat <<END >> $out
}

var tagIdToNameMap = map[int32]string {
END

sed -ne '/RPMTAG_/s/.*\(RPMTAG_[A-Z0-9_]*\).*/   \1 : "\1",/p' rpmtags.go >> $out

cat <<END >> $out
}

var typeNames = map[int32]string {
END

grep -Ev '_(MIN|MAX)_' rpmtags.go | sed -ne '/RPM_[A-Z0-9]*_TYPE/s/.*\(RPM_[A-Z0-9]*_TYPE\).*/    \1 : "\1",/p' >> $out

echo "}" >> $out
