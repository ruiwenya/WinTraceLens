//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"

	"github.com/ruiwenya/WinTraceLens/internal/loopback"
	"github.com/ruiwenya/WinTraceLens/internal/server"
)

var version = "2.0.0-preview-gui"

func main() {
	runtime.LockOSThread()

	addr := flag.String("addr", loopback.AutomaticAddress, "internal HTTP listen address")
	hashLimitMB := flag.Int64("hash-limit-mb", 512, "skip MD5 hashing for executable files larger than this size")
	debug := flag.Bool("debug-webview", false, "enable WebView2 dev tools and context menu")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	listener, err := loopback.Listen(*addr)
	if err != nil {
		fatalGUI("WinTraceLens 启动失败", fmt.Sprintf(
			"无法启动本地界面服务（监听地址 %s）。\n\n"+
				"当前 GUI 默认使用系统分配的随机空闲端口。如果错误信息仍指向 8787，"+
				"请确认运行的是最新 WinTraceLens.exe，且快捷方式没有附加 -addr 参数。\n\n"+
				"系统错误: %v", *addr, err))
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
