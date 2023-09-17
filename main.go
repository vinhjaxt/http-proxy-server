package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var httpClientTimeout = 15 * time.Second
var dialTimeout = 7 * time.Second

var localDialFunc = (&net.Dialer{
	Timeout:   dialTimeout,
	DualStack: true,
}).Dial

var httpClientLocal = &fasthttp.Client{
	ReadTimeout:         30 * time.Second,
	MaxConnsPerHost:     233,
	MaxIdleConnDuration: 15 * time.Minute,
	ReadBufferSize:      1024 * 8,
	Dial: func(addr string) (net.Conn, error) {
		// no suitable address found => ipv6 can not dial to ipv4,..
		hostname, port, err := net.SplitHostPort(addr)
		if err != nil {
			if err1, ok := err.(*net.AddrError); ok && strings.Contains(err1.Err, "missing port") {
				hostname, port, err = net.SplitHostPort(strings.TrimRight(addr, ":") + ":80")
			}
			if err != nil {
				return nil, err
			}
		}
		if port == "" || port == ":" {
			port = "80"
		}
		return localDialFunc("tcp", "["+hostname+"]:"+port)
	},
}

func httpsHandler(ctx *fasthttp.RequestCtx, remoteAddr string) error {
	var r net.Conn
	var err error
	r, err = localDialFunc("tcp", remoteAddr)
	if err != nil {
		return err
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Keep-Alive", "timeout=120, max=5")
	ctx.Hijack(func(clientConn net.Conn) {
		defer clientConn.Close()
		defer r.Close()
		go io.Copy(r, clientConn)
		io.Copy(clientConn, r)
	})
	return nil
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	if proxyAuth != nil {
		if !bytes.Equal(ctx.Request.Header.Peek("Proxy-Authorization"), proxyAuth) {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			log.Println("Reject: wrong creds")
			return
		}
	}
	// Some library must set header: Connection: keep-alive
	// ctx.Response.Header.Del("Connection")
	// ctx.Response.ConnectionClose() // ==> false

	// log.Println(string(ctx.Path()), string(ctx.Host()), ctx.String(), "\r\n\r\n", ctx.Request.String())

	host := string(ctx.Host())
	if len(host) < 1 {
		host = string(ctx.Path())[1:]
	}
	if len(host) < 1 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		log.Println("Reject: Empty host")
		return
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if err1, ok := err.(*net.AddrError); ok && strings.Contains(err1.Err, "missing port") {
			hostname, port, err = net.SplitHostPort(host + ":443")
		}
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			log.Println("Reject: Invalid host", host, err)
			return
		}
	}

	// https connecttion
	if bytes.Equal(ctx.Method(), []byte("CONNECT")) {
		err = httpsHandler(ctx, `[`+hostname+`]:`+port)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			log.Println("httpsHandler:", host, err)
		}
		return
	}

	err = httpClientLocal.DoTimeout(&ctx.Request, &ctx.Response, httpClientTimeout)

	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		log.Println("httpHandler:", host, err)
	}
}

var listen = flag.String(`l`, `:8081`, `Listen address. Eg: :8443; unix:/tmp/proxy.sock`)
var certFile = flag.String(`cert`, ``, `Certificate file (for tls). Eg: cert.pem`)
var keyFile = flag.String(`key`, ``, `Private key file (for tls). Eg: cert.key`)
var creds = flag.String(`u`, ``, `HTTP proxy credentials (user:pass)`)
var proxyAuth []byte

func main() {
	flag.Parse()

	if *creds != "" {
		proxyAuth = []byte(`Basic `)
		proxyAuth = append(proxyAuth, []byte(base64.StdEncoding.EncodeToString([]byte(*creds)))...)
		log.Println("Proxy-Authorization:", string(proxyAuth))
	}

	// Server
	var err error
	var ln net.Listener
	if strings.HasPrefix(*listen, `unix:`) {
		unixFile := (*listen)[5:]
		os.Remove(unixFile)
		ln, err = net.Listen(`unix`, unixFile)
		os.Chmod(unixFile, os.ModePerm)
		log.Println(`Listening:`, unixFile)
	} else {
		ln, err = net.Listen(`tcp`, *listen)
		log.Println(`Listening:`, ln.Addr().String())
	}
	if err != nil {
		log.Panicln(err)
	}

	srv := &fasthttp.Server{
		// ErrorHandler: nil,
		Handler:               requestHandler,
		NoDefaultServerHeader: true, // Don't send Server: fasthttp
		// Name: "nginx",  // Send Server header
		ReadBufferSize:                2 * 4096, // Make sure these are big enough.
		WriteBufferSize:               4096,
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  time.Second,
		IdleTimeout:                   time.Minute, // This can be long for keep-alive connections.
		DisableHeaderNamesNormalizing: false,       // If you're not going to look at headers or know the casing you can set this.
		// NoDefaultContentType: true, // Don't send Content-Type: text/plain if no Content-Type is set manually.
		MaxRequestBodySize: 200 * 1024 * 1024, // 200MB
		DisableKeepalive:   false,
		KeepHijackedConns:  false,
		// NoDefaultDate: len(*staticDir) == 0,
		ReduceMemoryUsage: true,
		TCPKeepalive:      true,
		// TCPKeepalivePeriod: 10 * time.Second,
		// MaxRequestsPerConn: 1000,
		// MaxConnsPerIP: 20,
	}

	// curl -v -x https://user:pass@127.0.0.1:8081 https://1.1.1.1/cdn-cgi/trace --proxy-insecure
	if *certFile != "" && *keyFile != "" {
		log.Panicln(srv.ServeTLS(ln, *certFile, *keyFile))
	}

	log.Panicln(srv.Serve(ln))
}
