package rpmdb
//go:generate bash tagnames.sh rpmtagnames.go

import (
	"fmt"
	"log"
	"time"
)

const (
	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L34
	RPMTAG_HEADERIMAGE      = 61
	RPMTAG_HEADERSIGNATURES = 62
	RPMTAG_HEADERIMMUTABLE  = 63
	HEADER_I18NTABLE        = 100
	RPMTAG_HEADERI18NTABLE  = HEADER_I18NTABLE

	// rpmTag_e
	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L34
	RPMTAG_PGP            = 259  /* b */

	RPMTAG_NAME           = 1000 /* s */
	RPMTAG_VERSION        = 1001 /* s */
	RPMTAG_RELEASE        = 1002 /* s */
	RPMTAG_EPOCH          = 1003 /* i */
	RPMTAG_SUMMARY        = 1004 /* s */
	RPMTAG_DESCRIPTION    = 1005 /* s{} */
	RPMTAG_BUILDTIME      = 1006 /* i */
	RPMTAG_INSTALLTIME    = 1008 /* i */
	RPMTAG_SIZE           = 1009 /* i */
	RPMTAG_DISTRIBUTION   = 1010 /* s */
	RPMTAG_VENDOR         = 1011 /* s */
	RPMTAG_LICENSE        = 1014 /* s */
	RPMTAG_GROUP          = 1016 /* s{} */
	RPMTAG_URL            = 1020 /* s */
	RPMTAG_ARCH           = 1022 /* s */
	RPMTAG_FILESIZES      = 1028 /* i[] */
	RPMTAG_FILEMODES      = 1030 /* h[] , specifically []uint16 (ref https://github.com/rpm-software-management/rpm/blob/2153fa4ae51a84547129b8ebb3bb396e1737020e/lib/rpmtypes.h#L53 )*/
	RPMTAG_FILEDIGESTS    = 1035 /* s[] */
	RPMTAG_FILEFLAGS      = 1037 /* i[] */
	RPMTAG_FILEUSERNAME   = 1039 /* s[] */
	RPMTAG_FILEGROUPNAME  = 1040 /* s[] */
	RPMTAG_SOURCERPM      = 1044 /* s */
	RPMTAG_DIRINDEXES     = 1116 /* i[] */
	RPMTAG_BASENAMES      = 1117 /* s[] */
	RPMTAG_DIRNAMES       = 1118 /* s[] */
	RPMTAG_FILEDIGESTALGO = 5011 /* i  */

	// rpmTag_enhances
	// https://github.com/rpm-software-management/rpm/blob/rpm-4.16.0-release/lib/rpmtag.h#L375
	RPMTAG_MODULARITYLABEL = 5096

	// rpmTagType_e
	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/rpmtag.h#L431
	RPM_MIN_TYPE          = 0
	RPM_NULL_TYPE         = 0
	RPM_CHAR_TYPE         = 1
	RPM_INT8_TYPE         = 2
	RPM_INT16_TYPE        = 3
	RPM_INT32_TYPE        = 4
	RPM_INT64_TYPE        = 5
	RPM_STRING_TYPE       = 6
	RPM_BIN_TYPE          = 7
	RPM_STRING_ARRAY_TYPE = 8
	RPM_I18NSTRING_TYPE   = 9
	RPM_MAX_TYPE          = 9
)

type Tag struct {
	Type	uint32
	Id	int32
	Value	interface{}
}

func TagName(tag int32) string {
	tagname, ok := tagIdToNameMap[tag]
	if !ok {
		tagname = fmt.Sprintf("tag#%v", tag)
	}
	return tagname
}

func TagID(tagname string) (int32, error) {
	tagid, ok := tagNameToIdMap[tagname]
	if !ok {
		return -1, fmt.Errorf("Tag %v has no matching ID", tagname)
	}
	return tagid, nil
}

func TypeName(typeid int32) string {
	typename, ok := typeNames[typeid]
	if !ok {
		typename = fmt.Sprintf("type#%v", typeid)
	}

	return typename
}

func (pkg *PackageInfoMap) GetStringTag(tagid int32) (string, error) {
	tag, ok := pkg.Tags[tagid]
	if !ok {
		return "", fmt.Errorf("Package has no tag \"%s\"", TagName(tagid))
	}

	value, ok := tag.Value.(string)
	if !ok {
		return "", fmt.Errorf("Expected string value for tag \"%s\"", TagName(tagid))
	}

	return value, nil
}

func (pkg *PackageInfoMap) GetStringArrayTag(tagid int32) ([]string, error) {
	tag, ok := pkg.Tags[tagid]
	if !ok {
		return nil, fmt.Errorf("Package has no tag \"%s\"", TagName(tagid))
	}

	value, ok := tag.Value.([]string)
	if !ok {
		return nil, fmt.Errorf("Expected string value for tag \"%s\"", TagName(tagid))
	}

	return value, nil
}

func (pkg *PackageInfoMap) GetIntTag(tagid int32) (int, error) {
	tag, ok := pkg.Tags[tagid]
	if !ok {
		return 0, fmt.Errorf("Package has no tag \"%s\"", TagName(tagid))
	}

	switch v := tag.Value.(type) {
	case uint16:
		return int(v), nil
	case int32:
		return int(v), nil
	case uint32:
		return int(v), nil
	case int64:
		return int(v), nil
	case uint64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("Expected integer value for tag \"%s\"", TagName(tagid))
	}
}

func (pkg *PackageInfoMap) GetIntArrayTag(tagid int32) ([]int, error) {
	tag, ok := pkg.Tags[tagid]
	if !ok {
		return nil, fmt.Errorf("Package has no tag \"%s\"", TagName(tagid))
	}


	switch v := tag.Value.(type) {
	case []uint16:
		ret := make([]int, len(v))
		for i, val := range v {
			ret[i] = int(val)
		}

		return ret, nil
	case []int32:
		ret := make([]int, len(v))
		for i, val := range v {
			ret[i] = int(val)
		}

		return ret, nil
	case []uint32:
		ret := make([]int, len(v))
		for i, val := range v {
			ret[i] = int(val)
		}

		return ret, nil
	case []int64:
		ret := make([]int, len(v))
		for i, val := range v {
			ret[i] = int(val)
		}

		return ret, nil
	case []uint64:
		ret := make([]int, len(v))
		for i, val := range v {
			ret[i] = int(val)
		}

		return ret, nil
	default:
		return nil, fmt.Errorf("Expected integer array value for tag \"%s\"", TagName(tagid))
	}
}

func (pkg *PackageInfoMap) GetTimeTag(tagid int32) (time.Time, error) {
	tag, ok := pkg.Tags[tagid]
	if !ok {
		return time.Time{}, fmt.Errorf("Package has no tag \"%s\"", TagName(tagid))
	}

	value, ok := tag.Value.(time.Time)
	if !ok {
		return time.Time{}, fmt.Errorf("Expected time value for tag \"%s\"", TagName(tagid))
	}

	return value, nil
}


func (pkg *PackageInfoMap) Name() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_NAME))
}

func (pkg *PackageInfoMap) ModularityLabel() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_MODULARITYLABEL))
}

func (pkg *PackageInfoMap) Version() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_VERSION))
}

func (pkg *PackageInfoMap) Release() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_RELEASE))
}

func (pkg *PackageInfoMap) Arch() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_ARCH))
}

func (pkg *PackageInfoMap) SourceRPM() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_SOURCERPM))
}

func (pkg *PackageInfoMap) License() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_LICENSE))
}

func (pkg *PackageInfoMap) Vendor() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_VENDOR))
}

func (pkg *PackageInfoMap) Distribution() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_DISTRIBUTION))
}

func (pkg *PackageInfoMap) URL() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_URL))
}

func (pkg *PackageInfoMap) Summary() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_SUMMARY))
}

func (pkg *PackageInfoMap) Description() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_DESCRIPTION))
}

func (pkg *PackageInfoMap) Group() string {
	return AssumeValid(pkg.GetStringTag(RPMTAG_GROUP))
}

func (pkg *PackageInfoMap) DirNames() []string {
	return AssumeValid(pkg.GetStringArrayTag(RPMTAG_DIRNAMES))
}

func (pkg *PackageInfoMap) BaseNames() []string {
	return AssumeValid(pkg.GetStringArrayTag(RPMTAG_BASENAMES))
}

func (pkg *PackageInfoMap) FileDigests() []string {
	return AssumeValid(pkg.GetStringArrayTag(RPMTAG_FILEDIGESTS))
}

func (pkg *PackageInfoMap) FileUserName() []string {
	return AssumeValid(pkg.GetStringArrayTag(RPMTAG_FILEUSERNAME))
}

func (pkg *PackageInfoMap) FileGroupName() []string {
	return AssumeValid(pkg.GetStringArrayTag(RPMTAG_FILEGROUPNAME))
}

func (pkg *PackageInfoMap) FileModes() []int {
	return AssumeValid(pkg.GetIntArrayTag(RPMTAG_FILEMODES))
}

func (pkg *PackageInfoMap) Size() int {
	return AssumeValid(pkg.GetIntTag(RPMTAG_SIZE))
}

func (pkg *PackageInfoMap) DirIndexes() []int {
	return AssumeValid(pkg.GetIntArrayTag(RPMTAG_DIRINDEXES))
}

func (pkg *PackageInfoMap) FileSizes() []int {
	return AssumeValid(pkg.GetIntArrayTag(RPMTAG_FILESIZES))
}

func (pkg *PackageInfoMap) FileFlags() []int {
	return AssumeValid(pkg.GetIntArrayTag(RPMTAG_FILEFLAGS))
}

func (pkg *PackageInfoMap) InstallTime() time.Time {
	return AssumeValid(pkg.GetTimeTag(RPMTAG_INSTALLTIME))
}

func (pkg *PackageInfoMap) BuildTime() time.Time {
	return AssumeValid(pkg.GetTimeTag(RPMTAG_BUILDTIME))
}

func (pkg *PackageInfoMap) Epoch() int {
	return AssumeValid(pkg.GetIntTag(RPMTAG_EPOCH))
}

func (pkg *PackageInfoMap) PGP() (*PGPInfo, error) {
	tagid := int32(RPMTAG_PGP)

	tag, ok := pkg.Tags[tagid]
	if !ok {
		return nil, fmt.Errorf("Package has no tag \"%s\"", TagName(tagid))
	}

	value, ok := tag.Value.(*PGPInfo)
	if !ok {
		return nil, fmt.Errorf("Expected *PGPInfo value for tag \"%s\"", TagName(tagid))
	}

	return value, nil
}

func AssumeValid[T any](first T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return first
}
