package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/ruiwenya/WinTraceLens/internal/server"
)

var version = "1.0.0-basic"

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "HTTP listen address")
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

	url := fmt.Sprintf("http://%s", *addr)
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

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
