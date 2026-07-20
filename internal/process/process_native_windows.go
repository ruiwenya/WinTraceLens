//go:build windows

package process

import (
	"fmt"
	"syscall"
	"unsafe"
)

const systemProcessInformation = 5

type nativeUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type systemProcessInformationHeader struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        int64
	HardFaultCount               uint32
	NumberOfThreadsHighWatermark uint32
	CycleTime                    uint64
	CreateTime                   int64
	UserTime                     int64
	KernelTime                   int64
	ImageName                    nativeUnicodeString
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

func snapshotProcessesNative() (map[uint32]string, error) {
	size := uint32(1024 * 1024)
	for attempt := 0; attempt < 6; attempt++ {
		buffer := make([]byte, size)
		var needed uint32
		status, _, _ := procNtQuerySystemInformation.Call(
			uintptr(systemProcessInformation),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&needed)),
		)
		if status == 0 {
			return parseNativeProcessSnapshot(buffer)
		}
		if uint32(status) != statusInfoLengthMismatch {
			return nil, fmt.Errorf("NTSTATUS 0x%X", uint32(status))
		}
		if needed > size {
			size = needed + 64*1024
		} else {
			size *= 2
		}
	}
	return nil, fmt.Errorf("系统进程缓冲区持续不足")
}

func parseNativeProcessSnapshot(buffer []byte) (map[uint32]string, error) {
	headerSize := int(unsafe.Sizeof(systemProcessInformationHeader{}))
	if len(buffer) < headerSize {
		return nil, fmt.Errorf("系统进程返回数据过短")
	}
	result := make(map[uint32]string)
	base := uintptr(unsafe.Pointer(&buffer[0]))
	end := base + uintptr(len(buffer))
	offset := 0
	for count := 0; count < 100000; count++ {
		if offset < 0 || offset+headerSize > len(buffer) {
			return nil, fmt.Errorf("系统进程记录偏移越界")
		}
		entry := (*systemProcessInformationHeader)(unsafe.Pointer(&buffer[offset]))
		pid := uint32(entry.UniqueProcessID)
		name := ""
		if entry.ImageName.Length > 0 && entry.ImageName.Buffer >= base &&
			entry.ImageName.Buffer+uintptr(entry.ImageName.Length) <= end {
			chars := unsafe.Slice((*uint16)(unsafe.Pointer(entry.ImageName.Buffer)), int(entry.ImageName.Length/2))
			name = syscall.UTF16ToString(chars)
		}
		if pid == 0 && name == "" {
			name = "[System Idle Process]"
		} else if pid == 4 && name == "" {
			name = "System"
		}
		result[pid] = name
		if entry.NextEntryOffset == 0 {
			return result, nil
		}
		next := offset + int(entry.NextEntryOffset)
		if next <= offset || next > len(buffer) {
			return nil, fmt.Errorf("系统进程记录链损坏")
		}
		offset = next
	}
	return nil, fmt.Errorf("系统进程记录数量异常")
}
