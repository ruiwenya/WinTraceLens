//go:build windows

package process

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	wtdUIChoiceNone          = 2
	wtdRevokeNone            = 0
	wtdChoiceFile            = 1
	wtdChoiceCatalog         = 2
	wtdStateActionIgnore     = 0
	wtdCacheOnlyURLRetrieval = 0x00000010
	trustENoSignature        = 0x800B0100
	trustESubjectFormUnknown = 0x800B0003
	trustEProviderUnknown    = 0x800B0001
	cryptEFileError          = 0x80092003
	trustEBadDigest          = 0x80096010
)

var (
	modWintrust                            = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust                     = modWintrust.NewProc("WinVerifyTrust")
	procCryptCATAdminAcquireContext        = modWintrust.NewProc("CryptCATAdminAcquireContext")
	procCryptCATAdminAcquireContext2       = modWintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminCalcHashFromFile      = modWintrust.NewProc("CryptCATAdminCalcHashFromFileHandle")
	procCryptCATAdminCalcHashFromFile2     = modWintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash   = modWintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATCatalogInfoFromContext     = modWintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCryptCATAdminReleaseCatalogContext = modWintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATAdminReleaseContext        = modWintrust.NewProc("CryptCATAdminReleaseContext")
	procGetWindowsDirectoryW               = modKernel32.NewProc("GetWindowsDirectoryW")
)

var errCatalogNotFound = errors.New("no matching catalog signature")

type SignatureResult struct {
	Status  string
	Message string
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type wintrustFileInfo struct {
	CbStruct     uint32
	FilePath     *uint16
	File         uintptr
	KnownSubject *guid
}

type wintrustCatalogInfo struct {
	CbStruct               uint32
	CatalogVersion         uint32
	CatalogFilePath        *uint16
	MemberTag              *uint16
	MemberFilePath         *uint16
	MemberFile             uintptr
	CalculatedFileHash     *byte
	CalculatedFileHashSize uint32
	CatalogContext         uintptr
	CatAdmin               uintptr
}

type wintrustData struct {
	CbStruct          uint32
	PolicyCallback    uintptr
	SIPClientData     uintptr
	UIChoice          uint32
	RevocationChecks  uint32
	UnionChoice       uint32
	ChoiceData        uintptr
	StateAction       uint32
	StateData         uintptr
	URLReference      *uint16
	ProvFlags         uint32
	UIContext         uint32
	SignatureSettings uintptr
}

type catalogInfo struct {
	CbStruct    uint32
	CatalogFile [syscall.MAX_PATH]uint16
}

type catalogAdmin struct {
	Handle    uintptr
	Algorithm string
	UseV2     bool
}

var genericVerifyV2 = guid{
	Data1: 0x00aac56b,
	Data2: 0xcd44,
	Data3: 0x11d0,
	Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
}

func CheckSignature(path string) SignatureResult {
	if path == "" {
		return SignatureResult{}
	}

	systemPath := isWindowsSystemPath(path)
	embeddedCode, embeddedMsg := verifyEmbeddedSignature(path)
	if embeddedCode == 0 {
		if systemPath {
			return SignatureResult{Status: "系统文件", Message: "可信嵌入式 Authenticode 签名，位于 Windows 系统目录"}
		}
		return SignatureResult{Status: "已签名", Message: "可信嵌入式 Authenticode 签名"}
	}

	catalogCode, catalogPath, catalogErr := verifyCatalogSignature(path)
	if catalogCode == 0 {
		if systemPath {
			return SignatureResult{Status: "系统文件", Message: "可信 Catalog 签名: " + catalogPath}
		}
		return SignatureResult{Status: "已签名", Message: "可信 Catalog 签名: " + catalogPath}
	}

	catalogMsg := ""
	if catalogErr != nil {
		catalogMsg = "; Catalog: " + catalogErr.Error()
	} else if catalogCode != 0 {
		catalogMsg = fmt.Sprintf("; Catalog 返回 0x%08X", catalogCode)
	}

	if systemPath {
		return SignatureResult{
			Status:  "系统文件",
			Message: "位于 Windows 系统目录；嵌入签名未验证: " + embeddedMsg + catalogMsg,
		}
	}

	if isNoSignatureCode(embeddedCode) && (catalogCode == 0 || isNoSignatureCode(catalogCode) || errors.Is(catalogErr, errCatalogNotFound)) {
		return SignatureResult{Status: "无签名请注意!!!", Message: "未发现可信嵌入签名或 Catalog 签名"}
	}

	return SignatureResult{Status: "签名异常", Message: "嵌入签名: " + embeddedMsg + catalogMsg}
}

func verifyEmbeddedSignature(path string) (uint32, string) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return trustESubjectFormUnknown, err.Error()
	}

	fileInfo := wintrustFileInfo{
		CbStruct: uint32(unsafe.Sizeof(wintrustFileInfo{})),
		FilePath: pathPtr,
	}
	data := wintrustData{
		CbStruct:         uint32(unsafe.Sizeof(wintrustData{})),
		UIChoice:         wtdUIChoiceNone,
		RevocationChecks: wtdRevokeNone,
		UnionChoice:      wtdChoiceFile,
		ChoiceData:       uintptr(unsafe.Pointer(&fileInfo)),
		StateAction:      wtdStateActionIgnore,
		ProvFlags:        wtdCacheOnlyURLRetrieval,
	}

	ret, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&genericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)
	code := uint32(ret)
	if code == 0 {
		return 0, "OK"
	}
	return code, signatureCodeMessage(code)
}

func verifyCatalogSignature(path string) (uint32, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return trustESubjectFormUnknown, "", err
	}
	defer file.Close()

	attempts := []catalogAdmin{}
	for _, algorithm := range []string{"SHA256", "SHA1"} {
		admin, err := acquireCatalogAdminV2(algorithm)
		if err == nil {
			attempts = append(attempts, admin)
		}
	}
	if admin, err := acquireCatalogAdmin(); err == nil {
		attempts = append(attempts, admin)
	}
	if len(attempts) == 0 {
		return trustESubjectFormUnknown, "", errors.New("cannot acquire catalog admin context")
	}
	defer func() {
		for _, admin := range attempts {
			releaseCatalogAdmin(admin)
		}
	}()

	var lastCode uint32
	var lastErr error = errCatalogNotFound
	for _, admin := range attempts {
		hash, err := calcCatalogHash(admin, file)
		if err != nil {
			lastErr = err
			continue
		}

		code, catalogPath, err := verifyCatalogHash(admin, path, file, hash)
		if code == 0 {
			return 0, catalogPath, nil
		}
		if err != nil {
			lastErr = err
		}
		if code != 0 {
			lastCode = code
		}
	}

	if lastCode == 0 {
		lastCode = trustENoSignature
	}
	return lastCode, "", lastErr
}

func acquireCatalogAdminV2(algorithm string) (catalogAdmin, error) {
	if err := procCryptCATAdminAcquireContext2.Find(); err != nil {
		return catalogAdmin{}, err
	}

	algorithmPtr, err := syscall.UTF16PtrFromString(algorithm)
	if err != nil {
		return catalogAdmin{}, err
	}

	var handle uintptr
	ret, _, callErr := procCryptCATAdminAcquireContext2.Call(
		uintptr(unsafe.Pointer(&handle)),
		0,
		uintptr(unsafe.Pointer(algorithmPtr)),
		0,
		0,
	)
	if ret == 0 {
		return catalogAdmin{}, callErr
	}

	return catalogAdmin{Handle: handle, Algorithm: algorithm, UseV2: true}, nil
}

func acquireCatalogAdmin() (catalogAdmin, error) {
	var handle uintptr
	ret, _, callErr := procCryptCATAdminAcquireContext.Call(
		uintptr(unsafe.Pointer(&handle)),
		0,
		0,
	)
	if ret == 0 {
		return catalogAdmin{}, callErr
	}
	return catalogAdmin{Handle: handle, Algorithm: "legacy", UseV2: false}, nil
}

func releaseCatalogAdmin(admin catalogAdmin) {
	if admin.Handle != 0 {
		procCryptCATAdminReleaseContext.Call(admin.Handle, 0)
	}
}

func calcCatalogHash(admin catalogAdmin, file *os.File) ([]byte, error) {
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}

	var size uint32
	var ret uintptr
	var callErr error
	if admin.UseV2 {
		ret, _, callErr = procCryptCATAdminCalcHashFromFile2.Call(
			admin.Handle,
			file.Fd(),
			uintptr(unsafe.Pointer(&size)),
			0,
			0,
		)
	} else {
		ret, _, callErr = procCryptCATAdminCalcHashFromFile.Call(
			file.Fd(),
			uintptr(unsafe.Pointer(&size)),
			0,
			0,
		)
	}
	if ret == 0 && size == 0 {
		return nil, callErr
	}

	hash := make([]byte, size)
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}
	if admin.UseV2 {
		ret, _, callErr = procCryptCATAdminCalcHashFromFile2.Call(
			admin.Handle,
			file.Fd(),
			uintptr(unsafe.Pointer(&size)),
			uintptr(unsafe.Pointer(&hash[0])),
			0,
		)
	} else {
		ret, _, callErr = procCryptCATAdminCalcHashFromFile.Call(
			file.Fd(),
			uintptr(unsafe.Pointer(&size)),
			uintptr(unsafe.Pointer(&hash[0])),
			0,
		)
	}
	if ret == 0 {
		return nil, callErr
	}

	return hash[:size], nil
}

func verifyCatalogHash(admin catalogAdmin, path string, file *os.File, hash []byte) (uint32, string, error) {
	if len(hash) == 0 {
		return trustENoSignature, "", errors.New("empty catalog hash")
	}

	filePathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return trustESubjectFormUnknown, "", err
	}

	memberTag := strings.ToUpper(hex.EncodeToString(hash))
	memberTagPtr, err := syscall.UTF16PtrFromString(memberTag)
	if err != nil {
		return trustESubjectFormUnknown, "", err
	}

	hashPtr := uintptr(unsafe.Pointer(&hash[0]))
	var previous uintptr
	var lastCode uint32
	var found bool
	for {
		catContext, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(
			admin.Handle,
			hashPtr,
			uintptr(len(hash)),
			0,
			uintptr(unsafe.Pointer(&previous)),
		)
		if catContext == 0 {
			break
		}
		found = true
		previous = catContext

		var cat catalogInfo
		cat.CbStruct = uint32(unsafe.Sizeof(cat))
		ret, _, _ := procCryptCATCatalogInfoFromContext.Call(
			catContext,
			uintptr(unsafe.Pointer(&cat)),
			0,
		)
		if ret == 0 {
			continue
		}

		catalogPath := syscall.UTF16ToString(cat.CatalogFile[:])
		catalogPathPtr, err := syscall.UTF16PtrFromString(catalogPath)
		if err != nil {
			continue
		}

		catInfo := wintrustCatalogInfo{
			CbStruct:               uint32(unsafe.Sizeof(wintrustCatalogInfo{})),
			CatalogFilePath:        catalogPathPtr,
			MemberTag:              memberTagPtr,
			MemberFilePath:         filePathPtr,
			MemberFile:             file.Fd(),
			CalculatedFileHash:     &hash[0],
			CalculatedFileHashSize: uint32(len(hash)),
			CatAdmin:               admin.Handle,
		}
		data := wintrustData{
			CbStruct:         uint32(unsafe.Sizeof(wintrustData{})),
			UIChoice:         wtdUIChoiceNone,
			RevocationChecks: wtdRevokeNone,
			UnionChoice:      wtdChoiceCatalog,
			ChoiceData:       uintptr(unsafe.Pointer(&catInfo)),
			StateAction:      wtdStateActionIgnore,
			ProvFlags:        wtdCacheOnlyURLRetrieval,
		}

		ret, _, _ = procWinVerifyTrust.Call(
			0,
			uintptr(unsafe.Pointer(&genericVerifyV2)),
			uintptr(unsafe.Pointer(&data)),
		)
		code := uint32(ret)
		if code == 0 {
			releaseCatalogContext(admin, previous)
			return 0, catalogPath, nil
		}
		lastCode = code
	}

	if previous != 0 {
		releaseCatalogContext(admin, previous)
	}
	if !found {
		return trustENoSignature, "", errCatalogNotFound
	}
	if lastCode == 0 {
		lastCode = trustENoSignature
	}
	return lastCode, "", nil
}

func releaseCatalogContext(admin catalogAdmin, context uintptr) {
	if admin.Handle != 0 && context != 0 {
		procCryptCATAdminReleaseCatalogContext.Call(admin.Handle, context, 0)
	}
}

func isNoSignatureCode(code uint32) bool {
	switch code {
	case trustENoSignature, trustESubjectFormUnknown, trustEProviderUnknown, cryptEFileError:
		return true
	default:
		return false
	}
}

func signatureCodeMessage(code uint32) string {
	switch code {
	case trustENoSignature:
		return "未发现签名"
	case trustESubjectFormUnknown:
		return "无法识别签名主体"
	case trustEProviderUnknown:
		return "未知签名提供者"
	case cryptEFileError:
		return "文件读取或签名解析失败"
	case trustEBadDigest:
		return "签名摘要不匹配"
	default:
		return fmt.Sprintf("WinVerifyTrust 返回 0x%08X", code)
	}
}

func isWindowsSystemPath(path string) bool {
	windowsDir := windowsDirectory()
	if windowsDir == "" {
		return false
	}

	p := strings.ToLower(strings.TrimRight(path, `\/`))
	root := strings.ToLower(strings.TrimRight(windowsDir, `\/`))
	return p == root || strings.HasPrefix(p, root+`\`)
}

func windowsDirectory() string {
	buf := make([]uint16, syscall.MAX_PATH)
	ret, _, _ := procGetWindowsDirectoryW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return ""
	}
	if int(ret) > len(buf) {
		buf = make([]uint16, int(ret)+1)
		ret, _, _ = procGetWindowsDirectoryW.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if ret == 0 {
			return ""
		}
	}
	return syscall.UTF16ToString(buf[:ret])
}
