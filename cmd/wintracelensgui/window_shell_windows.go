//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	gwlStyle           = -16
	gwlpWndProc        = -4
	wsCaption          = 0x00c00000
	wmClose            = 0x0010
	wmSize             = 0x0005
	wmGetMinMaxInfo    = 0x0024
	wmNCHitTest        = 0x0084
	wmNCDestroy        = 0x0082
	wmNCLButtonDown    = 0x00a1
	wmSysCommand       = 0x0112
	htCaption          = 2
	htMaxButton        = 9
	swMinimize         = 6
	swMaximize         = 3
	swRestore          = 9
	swpNoSize          = 0x0001
	swpNoMove          = 0x0002
	swpNoZOrder        = 0x0004
	swpNoActivate      = 0x0010
	swpFrameChanged    = 0x0020
	tpmRightButton     = 0x0002
	tpmReturnCommand   = 0x0100
	dwmaBorderColor    = 34
	dwmaCaptionColor   = 35
	dwmaTextColor      = 36
	dwmaImmersiveDark  = 20
	dwmaImmersiveDark2 = 19
	monitorNearest     = 2
	spiGetHighContrast = 0x0042
	hcfHighContrastOn  = 0x00000001
)

var (
	user32                = syscall.NewLazyDLL("user32.dll")
	dwmapi                = syscall.NewLazyDLL("dwmapi.dll")
	getWindowLongPtrW     = user32.NewProc("GetWindowLongPtrW")
	setWindowLongPtrW     = user32.NewProc("SetWindowLongPtrW")
	setWindowPos          = user32.NewProc("SetWindowPos")
	showWindow            = user32.NewProc("ShowWindow")
	isZoomed              = user32.NewProc("IsZoomed")
	releaseCapture        = user32.NewProc("ReleaseCapture")
	sendMessageW          = user32.NewProc("SendMessageW")
	postMessageW          = user32.NewProc("PostMessageW")
	getSystemMenu         = user32.NewProc("GetSystemMenu")
	trackPopupMenu        = user32.NewProc("TrackPopupMenu")
	getCursorPos          = user32.NewProc("GetCursorPos")
	setForegroundWindow   = user32.NewProc("SetForegroundWindow")
	callWindowProcW       = user32.NewProc("CallWindowProcW")
	monitorFromWindow     = user32.NewProc("MonitorFromWindow")
	getMonitorInfoW       = user32.NewProc("GetMonitorInfoW")
	getClientRect         = user32.NewProc("GetClientRect")
	screenToClient        = user32.NewProc("ScreenToClient")
	systemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	dwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
	windowProcedures      sync.Map
	windowMaxButtonRects  sync.Map
	windowProcCallback    = windows.NewCallback(windowShellProcedure)
)

type nativeShellBootstrap struct {
	Trusted         bool   `json:"trusted"`
	CustomFrame     bool   `json:"customFrame"`
	CurrentFrame    string `json:"currentFrame"`
	FramePreference string `json:"framePreference"`
	FrameOverride   bool   `json:"frameOverride"`
	FrameReason     string `json:"frameReason,omitempty"`
	Token           string `json:"token"`
}

type nativePoint struct {
	X int32
	Y int32
}

type nativeMinMaxInfo struct {
	Reserved     nativePoint
	MaxSize      nativePoint
	MaxPosition  nativePoint
	MinTrackSize nativePoint
	MaxTrackSize nativePoint
}

type nativeMonitorInfo struct {
	Size    uint32
	Monitor [4]int32
	Work    [4]int32
	Flags   uint32
}

type nativeHighContrast struct {
	Size   uint32
	Flags  uint32
	Scheme uintptr
}

type nativeRect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

func newWindowShellToken() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func windowShellInitScript(origin string, bootstrap nativeShellBootstrap) (string, error) {
	originJSON, err := json.Marshal(origin)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(bootstrap)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`(function () {
  if (window.location.origin !== %s) return;
  Object.defineProperty(window, '__WTL_NATIVE_SHELL', {
    configurable: false,
    enumerable: false,
    writable: false,
    value: %s
  });
})();`, originJSON, payload), nil
}

func installCustomWindowFrame(hwnd uintptr) bool {
	if hwnd == 0 {
		return false
	}
	if !installWindowProcedure(hwnd) {
		return false
	}
	index := int32(gwlStyle)
	style, _, _ := getWindowLongPtrW.Call(hwnd, uintptr(index))
	if style == 0 {
		restoreWindowProcedure(hwnd)
		return false
	}
	updated := style &^ uintptr(wsCaption)
	if updated == style {
		return true
	}
	previous, _, _ := setWindowLongPtrW.Call(hwnd, uintptr(index), updated)
	if previous == 0 {
		restoreWindowProcedure(hwnd)
		return false
	}
	result, _, _ := setWindowPos.Call(
		hwnd,
		0,
		0,
		0,
		0,
		0,
		uintptr(swpNoSize|swpNoMove|swpNoZOrder|swpNoActivate|swpFrameChanged),
	)
	if result == 0 {
		_, _, _ = setWindowLongPtrW.Call(hwnd, uintptr(index), style)
		restoreWindowProcedure(hwnd)
		return false
	}
	_, _, _ = sendMessageW.Call(hwnd, wmSize, 0, 0)
	return true
}

func installWindowProcedure(hwnd uintptr) bool {
	index := int32(gwlpWndProc)
	previous, _, _ := setWindowLongPtrW.Call(hwnd, uintptr(index), windowProcCallback)
	if previous == 0 {
		return false
	}
	windowProcedures.Store(hwnd, previous)
	return true
}

func restoreWindowProcedure(hwnd uintptr) {
	previous, ok := windowProcedures.LoadAndDelete(hwnd)
	if !ok {
		return
	}
	index := int32(gwlpWndProc)
	setWindowLongPtrW.Call(hwnd, uintptr(index), previous.(uintptr))
	windowMaxButtonRects.Delete(hwnd)
}

func windowShellProcedure(hwnd, message, wParam, lParam uintptr) uintptr {
	previousValue, ok := windowProcedures.Load(hwnd)
	if !ok {
		return 0
	}
	previous := previousValue.(uintptr)
	if message == wmNCHitTest && maxButtonHit(hwnd, lParam) {
		return htMaxButton
	}
	result, _, _ := callWindowProcW.Call(previous, hwnd, message, wParam, lParam)
	if message == wmGetMinMaxInfo && lParam != 0 {
		applyMonitorWorkArea(hwnd, (*nativeMinMaxInfo)(unsafe.Pointer(lParam)))
	}
	if message == wmNCDestroy {
		windowProcedures.Delete(hwnd)
		windowMaxButtonRects.Delete(hwnd)
	}
	return result
}

func maxButtonHit(hwnd, lParam uintptr) bool {
	point := nativePoint{
		X: int32(int16(uint16(lParam & 0xffff))),
		Y: int32(int16(uint16((lParam >> 16) & 0xffff))),
	}
	converted, _, _ := screenToClient.Call(hwnd, uintptr(unsafe.Pointer(&point)))
	if converted == 0 {
		return false
	}
	if value, ok := windowMaxButtonRects.Load(hwnd); ok {
		rect := value.(nativeRect)
		if point.X >= rect.Left && point.X < rect.Right && point.Y >= rect.Top && point.Y < rect.Bottom {
			return true
		}
	}

	// The HTML shell uses three fixed 46 CSS-pixel caption buttons. This native
	// fallback keeps Snap hit testing available during initial navigation and if
	// the WebView bridge cannot refresh the measured rectangle.
	client := nativeRect{}
	ok, _, _ := getClientRect.Call(hwnd, uintptr(unsafe.Pointer(&client)))
	if ok == 0 {
		return false
	}
	const buttonWidth = int32(46)
	const headerHeight = int32(42)
	return point.X >= client.Right-2*buttonWidth && point.X < client.Right-buttonWidth && point.Y >= 0 && point.Y < headerHeight
}

func updateMaxButtonRect(hwnd uintptr, value string) error {
	parts := strings.Split(value, ",")
	if len(parts) != 5 {
		return errors.New("invalid maximize button rectangle")
	}
	values := make([]float64, len(parts))
	for index, part := range parts {
		parsed, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return errors.New("invalid maximize button rectangle")
		}
		values[index] = parsed
	}
	x, y, width, height, scale := values[0], values[1], values[2], values[3], values[4]
	if x < 0 || y < 0 || width < 8 || height < 8 || scale < 0.5 || scale > 8 || x+width > 10000 || y+height > 10000 {
		return errors.New("maximize button rectangle out of range")
	}
	rect := nativeRect{
		Left:   int32(math.Round(x * scale)),
		Top:    int32(math.Round(y * scale)),
		Right:  int32(math.Round((x + width) * scale)),
		Bottom: int32(math.Round((y + height) * scale)),
	}
	if rect.Right <= rect.Left || rect.Bottom <= rect.Top {
		return errors.New("empty maximize button rectangle")
	}
	windowMaxButtonRects.Store(hwnd, rect)
	return nil
}

func applyMonitorWorkArea(hwnd uintptr, limits *nativeMinMaxInfo) {
	monitor, _, _ := monitorFromWindow.Call(hwnd, monitorNearest)
	if monitor == 0 {
		return
	}
	info := nativeMonitorInfo{Size: uint32(unsafe.Sizeof(nativeMonitorInfo{}))}
	ok, _, _ := getMonitorInfoW.Call(monitor, uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return
	}
	limits.MaxPosition.X = info.Work[0] - info.Monitor[0]
	limits.MaxPosition.Y = info.Work[1] - info.Monitor[1]
	limits.MaxSize.X = info.Work[2] - info.Work[0]
	limits.MaxSize.Y = info.Work[3] - info.Work[1]
	limits.MaxTrackSize = limits.MaxSize
}

func systemWindowTheme() string {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return "light"
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue("AppsUseLightTheme")
	if err == nil && value == 0 {
		return "dark"
	}
	return "light"
}

func systemHighContrastEnabled() bool {
	settings := nativeHighContrast{Size: uint32(unsafe.Sizeof(nativeHighContrast{}))}
	ok, _, _ := systemParametersInfoW.Call(
		spiGetHighContrast,
		uintptr(settings.Size),
		uintptr(unsafe.Pointer(&settings)),
		0,
	)
	return ok != 0 && settings.Flags&hcfHighContrastOn != 0
}

func colorRef(red, green, blue byte) uint32 {
	return uint32(red) | uint32(green)<<8 | uint32(blue)<<16
}

func setDWMAttribute(hwnd uintptr, attribute uintptr, value unsafe.Pointer, size uintptr) bool {
	result, _, _ := dwmSetWindowAttribute.Call(hwnd, attribute, uintptr(value), size)
	return result == 0
}

func applyWindowTheme(hwnd uintptr, theme string) {
	dark := theme == "dark"
	darkMode := int32(0)
	if dark {
		darkMode = 1
	}
	if !setDWMAttribute(hwnd, dwmaImmersiveDark, unsafe.Pointer(&darkMode), unsafe.Sizeof(darkMode)) {
		setDWMAttribute(hwnd, dwmaImmersiveDark2, unsafe.Pointer(&darkMode), unsafe.Sizeof(darkMode))
	}

	caption := colorRef(0xf7, 0xf8, 0xfa)
	textColor := colorRef(0x17, 0x1b, 0x22)
	border := colorRef(0xd7, 0xdc, 0xe3)
	if dark {
		caption = colorRef(0x23, 0x26, 0x2b)
		textColor = colorRef(0xf2, 0xf4, 0xf7)
		border = colorRef(0x3a, 0x40, 0x49)
	}
	setDWMAttribute(hwnd, dwmaCaptionColor, unsafe.Pointer(&caption), unsafe.Sizeof(caption))
	setDWMAttribute(hwnd, dwmaTextColor, unsafe.Pointer(&textColor), unsafe.Sizeof(textColor))
	setDWMAttribute(hwnd, dwmaBorderColor, unsafe.Pointer(&border), unsafe.Sizeof(border))
}

func runWindowAction(hwnd uintptr, token, expectedToken, preferencesPath, action string) (string, error) {
	if token == "" || token != expectedToken {
		return "", errors.New("window action denied")
	}
	if theme, ok := strings.CutPrefix(action, "theme:"); ok {
		if theme != "light" && theme != "dark" {
			return "", errors.New("invalid window theme")
		}
		applyWindowTheme(hwnd, theme)
		return windowState(hwnd), nil
	}
	if frame, ok := strings.CutPrefix(action, "frame-preference:"); ok {
		if err := saveWindowFramePreference(preferencesPath, frame); err != nil {
			return "", fmt.Errorf("save window frame preference: %w", err)
		}
		return frame, nil
	}
	if action == "frame-preference-get" {
		frame, err := loadWindowFramePreference(preferencesPath)
		if err != nil {
			return "", fmt.Errorf("load window frame preference: %w", err)
		}
		return frame, nil
	}
	if rectangle, ok := strings.CutPrefix(action, "max-button-rect:"); ok {
		if err := updateMaxButtonRect(hwnd, rectangle); err != nil {
			return "", err
		}
		return windowState(hwnd), nil
	}
	if action == "clear-max-button-rect" {
		windowMaxButtonRects.Delete(hwnd)
		return windowState(hwnd), nil
	}

	switch action {
	case "state":
		return windowState(hwnd), nil
	case "minimize":
		showWindow.Call(hwnd, swMinimize)
	case "toggle-maximize":
		if windowState(hwnd) == "maximized" {
			showWindow.Call(hwnd, swRestore)
		} else {
			showWindow.Call(hwnd, swMaximize)
		}
	case "close":
		postMessageW.Call(hwnd, wmClose, 0, 0)
	case "drag":
		releaseCapture.Call()
		sendMessageW.Call(hwnd, wmNCLButtonDown, htCaption, 0)
	case "system-menu":
		showSystemMenu(hwnd)
	default:
		return "", errors.New("unsupported window action")
	}
	return windowState(hwnd), nil
}

func windowState(hwnd uintptr) string {
	value, _, _ := isZoomed.Call(hwnd)
	if value != 0 {
		return "maximized"
	}
	return "normal"
}

func showSystemMenu(hwnd uintptr) {
	menu, _, _ := getSystemMenu.Call(hwnd, 0)
	if menu == 0 {
		return
	}
	point := nativePoint{}
	ok, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&point)))
	if ok == 0 {
		return
	}
	setForegroundWindow.Call(hwnd)
	command, _, _ := trackPopupMenu.Call(
		menu,
		tpmRightButton|tpmReturnCommand,
		uintptr(point.X),
		uintptr(point.Y),
		0,
		hwnd,
		0,
	)
	if command != 0 {
		postMessageW.Call(hwnd, wmSysCommand, command, 0)
	}
}
