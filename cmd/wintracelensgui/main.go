//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"

	"github.com/ruiwenya/WinTraceLens/internal/server"
)

var version = "2.0.0-preview-gui"

func main() {
	runtime.LockOSThread()

	addr := flag.String("addr", "127.0.0.1:0", "internal HTTP listen address")
	hashLimitMB := flag.Int64("hash-limit-mb", 512, "skip MD5 hashing for executable files larger than this size")
	debug := flag.Bool("debug-webview", false, "enable WebView2 dev tools and context menu")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		fatalGUI("WinTraceLens 启动失败", "无法启动本地界面服务: "+err.Error())
	}

	appServer := server.New(server.Options{
		HashLimitBytes: *hashLimitMB * 1024 * 1024,
		Version:        version,
	})
	srv := &http.Server{Handler: appServer.Routes()}

	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	url := appServer.BootstrapURL("http://" + listener.Addr().String())
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     *debug,
		AutoFocus: true,
		DataPath:  webviewDataPath(),
		WindowOptions: webview2.WindowOptions{
			Title:  "WinTraceLens基础版",
			Width:  1280,
			Height: 820,
			Center: true,
		},
	})
	if w == nil {
		_ = srv.Shutdown(context.Background())
		fatalGUI("WinTraceLens 启动失败", "无法加载 WebView2。请确认系统已安装 Microsoft Edge WebView2 Runtime。")
	}
	defer w.Destroy()

	w.Navigate(url)
	w.Run()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func webviewDataPath() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	path := filepath.Join(base, "WinTraceLens", "WebView2")
	_ = os.MkdirAll(path, 0o700)
	return path
}

func fatalGUI(title, message string) {
	messageBox(title, message)
	os.Exit(1)
}

func messageBox(title, message string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)
	const mbIconError = 0x00000010
	const mbOK = 0x00000000
	_, _, _ = messageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(mbOK|mbIconError),
	)
}
