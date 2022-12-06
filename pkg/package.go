package rpmdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/xerrors"
	"golang.org/x/tools/container/intsets"
)

type PGPInfo struct {
       PubKeyAlgorithm string
       HashAlgorithm   string
       Date            string
       KeyID           [8]byte
}

func (info *PGPInfo) String() string {
       return fmt.Sprintf("%s/%s, %s, Key ID %x", info.PubKeyAlgorithm,
                          info.HashAlgorithm, info.Date, info.KeyID)
}

type PackageInfo struct {
	Epoch           *int
	Name            string
	Version         string
	Release         string
	Arch            string
	SourceRpm       string
	Group		string
	Size            int
	InstallTime	time.Time
	BuildTime	time.Time
	License         string
	Vendor          string
	Distribution	string
	Modularitylabel string
	Description	string
	Url		string
	Summary         string
	PGP             string
	PGPInfo		*PGPInfo
	DigestAlgorithm DigestAlgorithm
	BaseNames       []string
	DirIndexes      []int32
	DirNames        []string
	FileSizes       []int32
	FileDigests     []string
	FileModes       []uint16
	FileFlags       []int32
	UserNames       []string
	GroupNames      []string
}

type PackageInfoMap struct {
	Tags	map[int32]Tag
}

type FileInfo struct {
	Path      string
	Mode      uint16
	Digest    string
	Size      int32
	Username  string
	Groupname string
	Flags     FileFlags
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/tagexts.c#L752
func getNEVRAAsPackageInfo(indexEntries []indexEntry) (*PackageInfo, error) {
	pkgInfo := &PackageInfo{}
	for _, ie := range indexEntries {
		var err error
		switch ie.Info.Tag {
		// RPM_STRING_TYPE
		case RPMTAG_MODULARITYLABEL:
			pkgInfo.Modularitylabel, err = ie.ParseString()
		case RPMTAG_NAME:
			pkgInfo.Name, err = ie.ParseString()
		case RPMTAG_VERSION:
			pkgInfo.Version, err = ie.ParseString()
		case RPMTAG_RELEASE:
			pkgInfo.Release, err = ie.ParseString()
		case RPMTAG_ARCH:
			pkgInfo.Arch, err = ie.ParseString()
		case RPMTAG_SOURCERPM:
			pkgInfo.SourceRpm, err = ie.ParseString()
		case RPMTAG_LICENSE:
			pkgInfo.License, err = ie.ParseString()
		case RPMTAG_VENDOR:
			pkgInfo.Vendor, err = ie.ParseString()
		case RPMTAG_DISTRIBUTION:
			pkgInfo.Distribution, err = ie.ParseString()
		case RPMTAG_URL:
			pkgInfo.Url, err = ie.ParseString()

		// RPM_I18NSTRING_TYPE
		case RPMTAG_SUMMARY:
			pkgInfo.Summary, err = ie.ParseI18nString()
		case RPMTAG_DESCRIPTION:
			pkgInfo.Description, err = ie.ParseI18nString()
		case RPMTAG_GROUP:
			pkgInfo.Group, err = ie.ParseI18nString()

		// RPM_STRING_ARRAY_TYPE
		case RPMTAG_DIRNAMES:
			pkgInfo.DirNames, err = ie.ParseStringArray()
		case RPMTAG_BASENAMES:
			pkgInfo.BaseNames, err = ie.ParseStringArray()
		case RPMTAG_FILEDIGESTS:
			pkgInfo.FileDigests, err = ie.ParseStringArray()
		case RPMTAG_FILEUSERNAME:
			pkgInfo.UserNames, err = ie.ParseStringArray()
		case RPMTAG_FILEGROUPNAME:
			pkgInfo.GroupNames, err = ie.ParseStringArray()

		// note: there is no distinction between int16, uint16, and []uint16
		// RPM_INT16_TYPE (array variant)
		case RPMTAG_FILEMODES:
			pkgInfo.FileModes, err = ie.ParseUint16Array()

		// note: there is no distinction between int32, uint32, and []uint32
		// RPM_INT32_TYPE (scalar variant)
		case RPMTAG_SIZE:
			pkgInfo.Size, err = ie.ParseInt32()

		// RPM_INT32_TYPE (array variant)
		case RPMTAG_DIRINDEXES:
			pkgInfo.DirIndexes, err = ie.ParseInt32Array()
		case RPMTAG_FILESIZES:
			pkgInfo.FileSizes, err = ie.ParseInt32Array()
		case RPMTAG_FILEFLAGS:
			pkgInfo.FileFlags, err = ie.ParseInt32Array()

		// Timestamps (either 32- or 64-bit)
		case RPMTAG_INSTALLTIME:
			pkgInfo.InstallTime, err = parseTime(ie)
		case RPMTAG_BUILDTIME:
			pkgInfo.BuildTime, err = parseTime(ie)

		// Special handling
		case RPMTAG_EPOCH:
			if ie.Data != nil {
				value, err := ie.ParseInt32()
				if err != nil {
					break
				}
				pkgInfo.Epoch = &value
			}
		case RPMTAG_FILEDIGESTALGO:
			// note: all digests within a package entry only supports a single
			// digest algorithm (there may be future support for algorithm noted for
			// each file entry, but currently unimplemented:
			// https://github.com/rpm-software-management/rpm/blob/0b75075a8d006c8f792d33a57eae7da6b66a4591/lib/rpmtag.h#L256)
			digestAlgorithm, err := ie.ParseInt32()
			if err != nil {
				break
			}

			pkgInfo.DigestAlgorithm = DigestAlgorithm(digestAlgorithm)
		case RPMTAG_PGP:
			pkgInfo.PGPInfo, err = parsePGPSignature(ie)
			if err != nil {
				break
			}

			pkgInfo.PGP = pkgInfo.PGPInfo.String()
		}

		if err != nil {
			return nil, xerrors.Errorf("error while parsing %v: %w",
						   ie.Info.TagName(), err)
		}
	}

	return pkgInfo, nil
}

func getNEVRAAsPackageInfoMap(indexEntries []indexEntry, tags []string) (*PackageInfoMap, error) {
	pkgInfo := &PackageInfoMap{ Tags: map[int32]Tag{} }

	tagSet := &intsets.Sparse{}

	if len(tags) > 0 {
		for _, tag := range tags {
			tag = strings.ToUpper(tag)
			id, ok := tagNameToIdMap[tag]
			if !ok {
				return nil, xerrors.Errorf("Unknown tag %s", tag)
			}

			_ = tagSet.Insert(int(id))
		}
	}
	for _, ie := range indexEntries {
		var err error

		if !tagSet.IsEmpty() && !tagSet.Has(int(ie.Info.Tag)) {
			continue
		}

		tag := Tag{ Type: ie.Info.Type, Id: ie.Info.Tag, }

		switch ie.Info.Tag {
		// RPM_STRING_TYPE
		case RPMTAG_MODULARITYLABEL,
		     RPMTAG_NAME,
		     RPMTAG_VERSION,
		     RPMTAG_RELEASE,
		     RPMTAG_ARCH,
		     RPMTAG_SOURCERPM,
		     RPMTAG_LICENSE,
		     RPMTAG_VENDOR,
		     RPMTAG_DISTRIBUTION,
		     RPMTAG_URL:
			tag.Value, err = ie.ParseString()

		// RPM_I18NSTRING_TYPE
		case RPMTAG_SUMMARY,
		     RPMTAG_DESCRIPTION,
		     RPMTAG_GROUP:
			tag.Value, err = ie.ParseI18nString()

		// RPM_STRING_ARRAY_TYPE
		case RPMTAG_DIRNAMES,
		     RPMTAG_BASENAMES,
		     RPMTAG_FILEDIGESTS,
		     RPMTAG_FILEUSERNAME,
		     RPMTAG_FILEGROUPNAME:
			tag.Value, err = ie.ParseStringArray()

		// note: there is no distinction between int16, uint16, and []uint16
		// RPM_INT16_TYPE (array variant)
		case RPMTAG_FILEMODES:
			tag.Value, err = ie.ParseUint16Array()

		// note: there is no distinction between int32, uint32, and []uint32
		// RPM_INT32_TYPE (scalar variant)
		case RPMTAG_SIZE:
			tag.Value, err = ie.ParseInt32()

		// RPM_INT32_TYPE (array variant)
		case RPMTAG_DIRINDEXES,
		     RPMTAG_FILESIZES,
		     RPMTAG_FILEFLAGS:
			tag.Value, err = ie.ParseInt32Array()

		// Timestamps (either 32- or 64-bit)
		case RPMTAG_INSTALLTIME,
		     RPMTAG_BUILDTIME:
			tag.Value, err = parseTime(ie)

		// Special handling
		case RPMTAG_EPOCH:
			if ie.Data != nil {
				value, err := ie.ParseInt32()
				if err != nil {
					break
				}
				tag.Value = value
			}
		case RPMTAG_FILEDIGESTALGO:
			// note: all digests within a package entry only supports a single
			// digest algorithm (there may be future support for algorithm noted for
			// each file entry, but currently unimplemented:
			// https://github.com/rpm-software-management/rpm/blob/0b75075a8d006c8f792d33a57eae7da6b66a4591/lib/rpmtag.h#L256)
			digestAlgorithm, err := ie.ParseInt32()
			if err != nil {
				break
			}

			tag.Value = DigestAlgorithm(digestAlgorithm)
		case RPMTAG_PGP:
			tag.Value, err = parsePGPSignature(ie)
		}

		if err != nil {
			return nil, xerrors.Errorf("error while parsing %v: %w",
						   ie.Info.TagName(), err)
		}

		pkgInfo.Tags[tag.Id] = tag
	}

	return pkgInfo, nil
}

func parsePGPSignature(ie indexEntry) (*PGPInfo, error) {
	type pgpSig struct {
		_          [3]byte
		Date       int32
		KeyID      [8]byte
		PubKeyAlgo uint8
		HashAlgo   uint8
	}

	type textSig struct {
		_          [2]byte
		PubKeyAlgo uint8
		HashAlgo   uint8
		_          [4]byte
		Date       int32
		_          [4]byte
		KeyID      [8]byte
	}

	type pgp4Sig struct {
		_          [2]byte
		PubKeyAlgo uint8
		HashAlgo   uint8
		_          [17]byte
		KeyID      [8]byte
		_          [2]byte
		Date       int32
	}

	pubKeyLookup := map[uint8]string{
		0x01: "RSA",
	}
	hashLookup := map[uint8]string{
		0x02: "SHA1",
		0x08: "SHA256",
	}

	if ie.Info.Type != RPM_BIN_TYPE {
		return nil, xerrors.New("invalid PGP signature")
	}

	var tag, signatureType, version uint8
	r := bytes.NewReader(ie.Data)
	err := binary.Read(r, binary.BigEndian, &tag)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.BigEndian, &signatureType)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.BigEndian, &version)
	if err != nil {
		return nil, err
	}

	var pubKeyAlgo, hashAlgo, pkgDate string
	var keyId [8]byte

	switch signatureType {
	case 0x01:
		switch version {
		case 0x1c:
			sig := textSig{}
			err = binary.Read(r, binary.BigEndian, &sig)
			if err != nil {
				return nil, xerrors.Errorf("invalid PGP signature on decode: %w", err)
			}
			pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
			hashAlgo = hashLookup[sig.HashAlgo]
			pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
			keyId = sig.KeyID
		default:
			sig := pgpSig{}
			err = binary.Read(r, binary.BigEndian, &sig)
			if err != nil {
				return nil, xerrors.Errorf("invalid PGP signature on decode: %w", err)
			}
			pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
			hashAlgo = hashLookup[sig.HashAlgo]
			pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
			keyId = sig.KeyID
		}
	case 0x02:
		switch version {
		case 0x33:
			sig := pgp4Sig{}
			err = binary.Read(r, binary.BigEndian, &sig)
			if err != nil {
				return nil, xerrors.Errorf("invalid PGP signature on decode: %w", err)
			}
			pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
			hashAlgo = hashLookup[sig.HashAlgo]
			pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
			keyId = sig.KeyID
		default:
			sig := pgpSig{}
			err = binary.Read(r, binary.BigEndian, &sig)
			if err != nil {
				return nil, xerrors.Errorf("invalid PGP signature on decode: %w", err)
			}
			pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
			hashAlgo = hashLookup[sig.HashAlgo]
			pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
			keyId = sig.KeyID
		}
	}

	PGP := &PGPInfo{PubKeyAlgorithm: pubKeyAlgo, HashAlgorithm: hashAlgo,
			Date: pkgDate, KeyID: keyId}

	return PGP, nil
}

func parseTime(ie indexEntry) (time.Time, error) {
	if ie.Info.Type == RPM_INT32_TYPE {
		ts, err := ie.ParseInt32()
		if err != nil {
			return time.Time{}, xerrors.Errorf("failed to parse time field: %w", err)
		}
		return time.Unix(int64(ts), 0).UTC(), nil
	} else if ie.Info.Type == RPM_INT64_TYPE {
		ts, err := ie.ParseInt64()
		if err != nil {
			return time.Time{}, xerrors.Errorf("failed to parse time field: %w", err)
		}
		return time.Unix(int64(ts), 0).UTC(), nil
	}

	return time.Time{}, xerrors.Errorf("invalid tag type for timestamp field: %v",
					   ie.Info.TypeName())
}

func (p *PackageInfo) InstalledFileNames() ([]string, error) {
	if len(p.DirNames) == 0 || len(p.DirIndexes) == 0 || len(p.BaseNames) == 0 {
		return nil, nil
	}

	// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/tagexts.c#L68-L70
	if len(p.DirIndexes) != len(p.BaseNames) || len(p.DirNames) > len(p.BaseNames) {
		return nil, xerrors.Errorf("invalid rpm %s", p.Name)
	}

	var filePaths []string
	for i, baseName := range p.BaseNames {
		dir := p.DirNames[p.DirIndexes[i]]
		filePaths = append(filePaths, filepath.Join(dir, baseName))
	}
	return filePaths, nil
}

func (p *PackageInfo) InstalledFiles() ([]FileInfo, error) {
	fileNames, err := p.InstalledFileNames()
	if err != nil {
		return nil, err
	}

	var files []FileInfo
	for i, fileName := range fileNames {
		var digest, username, groupname string
		var mode uint16
		var size, flags int32

		if p.FileDigests != nil && len(p.FileDigests) > i {
			digest = p.FileDigests[i]
		}

		if p.FileModes != nil && len(p.FileModes) > i {
			mode = p.FileModes[i]
		}

		if p.FileSizes != nil && len(p.FileSizes) > i {
			size = p.FileSizes[i]
		}

		if p.UserNames != nil && len(p.UserNames) > i {
			username = p.UserNames[i]
		}

		if p.GroupNames != nil && len(p.GroupNames) > i {
			groupname = p.GroupNames[i]
		}

		if p.FileFlags != nil && len(p.FileFlags) > i {
			flags = p.FileFlags[i]
		}

		record := FileInfo{
			Path:      fileName,
			Mode:      mode,
			Digest:    digest,
			Size:      size,
			Username:  username,
			Groupname: groupname,
			Flags:     FileFlags(flags),
		}
		files = append(files, record)
	}

	return files, nil
}

func (p *PackageInfo) EpochNum() int {
	if p.Epoch == nil {
		return 0
	}
	return *p.Epoch
}
