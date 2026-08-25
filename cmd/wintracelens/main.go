package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/loopback"
	"github.com/ruiwenya/WinTraceLens/internal/server"
)

var version = "2.0.0-preview"

func main() {
	addr := flag.String("addr", loopback.AutomaticAddress, "HTTP listen address (port 0 selects an available port)")
	hashLimitMB := flag.Int64("hash-limit-mb", 512, "skip MD5 hashing for executable files larger than this size")
	noBrowser := flag.Bool("no-browser", false, "do not open the web UI automatically")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	srv := server.New(server.Options{
		HashLimitBytes: *hashLimitMB * 1024 * 1024,
		Version:        version,
	})

	listener, err := loopback.Listen(*addr)
	if err != nil {
		log.Fatalf("cannot start the local interface service on %s: %v", *addr, err)
	}
	defer listener.Close()
	url := srv.BootstrapURL(fmt.Sprintf("http://%s", listener.Addr().String()))

	fmt.Printf("WinTraceLens %s is running: %s\n", version, url)
	fmt.Println("For event log and security-log coverage, run this program as Administrator.")
	fmt.Println("Press Ctrl+C to stop.")

	if !*noBrowser {
		go func() {
			time.Sleep(600 * time.Millisecond)
			openBrowser(url)
		}()
	}

	if err := http.Serve(listener, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
