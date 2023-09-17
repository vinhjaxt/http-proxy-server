package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var listen = flag.String(`l`, `:443`, `Listen address. Eg: :8443; unix:/tmp/proxy.sock`)
var certFile = flag.String(`cert`, ``, `Certificate file (for tls). Eg: cert.pem`)
var keyFile = flag.String(`key`, ``, `Private key file (for tls). Eg: cert.key`)
var creds = flag.String(`u`, ``, `Credentials (token)`)
var credsLen int
var credsByte []byte

var dialTimeout = 7 * time.Second

var localDialFunc = (&net.Dialer{
	Timeout:   dialTimeout,
	DualStack: true,
}).Dial

var TCPKeepalive bool = true
var TCPKeepalivePeriod time.Duration

func acceptConn(ln net.Listener) (net.Conn, error) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Println("Timeout error when accepting new connections:", netErr)
				time.Sleep(time.Second)
				continue
			}
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Println("Permanent error when accepting new connections:", err)
				return nil, err
			}
			return nil, io.EOF
		}

		if tc, ok := c.(*net.TCPConn); ok && TCPKeepalive {
			if err := tc.SetKeepAlive(TCPKeepalive); err != nil {
				_ = tc.Close()
				return nil, err
			}
			if TCPKeepalivePeriod > 0 {
				if err := tc.SetKeepAlivePeriod(TCPKeepalivePeriod); err != nil {
					_ = tc.Close()
					return nil, err
				}
			}
		}

		return c, nil
	}
}

var bufLen int
var bytePool = &sync.Pool{
	New: func() any {
		b := make([]byte, bufLen)
		return &b
	},
}

var zeroTime = time.Time{}

func serve(c net.Conn) {
	defer c.Close()
	var buf = (*bytePool.Get().(*[]byte))[:]
	c.SetReadDeadline(time.Now().Add(dialTimeout))
	n, err := c.Read(buf)
	if err != nil {
		bytePool.Put(&buf)
		log.Println("read:", c.RemoteAddr().String(), err)
		return
	}
	if n < credsLen {
		log.Println(string(buf))
		bytePool.Put(&buf)
		log.Println("read n < credsLen", c.RemoteAddr().String())
		return
	}

	c.SetReadDeadline(zeroTime)

	addr := buf[:n]
	idx := bytes.IndexRune(addr, '\n')
	if idx == -1 {
		bytePool.Put(&buf)
		log.Println("read not found \\n", c.RemoteAddr().String())
		return
	}
	if idx <= credsLen {
		log.Println(string(buf))
		bytePool.Put(&buf)
		log.Println("read idx < bufLen", c.RemoteAddr().String())
		return
	}

	authStr := addr[:credsLen]
	if !bytes.Equal(authStr, credsByte) {
		bytePool.Put(&buf)
		log.Println("auth failed", c.RemoteAddr().String())
		return
	}
	rest := addr[idx+1:]
	addr = addr[credsLen:idx]

	// log.Println(string(authStr), string(addr), string(rest))

	r, err := localDialFunc("tcp", string(addr))
	if err != nil {
		bytePool.Put(&buf)
		log.Println("remote connect failed", c.RemoteAddr().String())
		return
	}
	defer r.Close()

	if len(rest) != 0 {
		r.SetWriteDeadline(time.Now().Add(dialTimeout))
		_, err = r.Write(rest)
		if err != nil {
			bytePool.Put(&buf)
			log.Println("remote write failed:", c.RemoteAddr().String(), err)
			return
		}
		r.SetWriteDeadline(zeroTime)
	}

	bytePool.Put(&buf)

	go io.Copy(r, c)
	io.Copy(c, r)
}

func main() {
	flag.Parse()
	if *certFile == "" || *keyFile == "" {
		log.Panicln("Not found args: -certFile, -keyFile")
		return
	}
	credsLen = len(*creds)
	credsByte = []byte(*creds)
	bufLen = credsLen /*auth str*/ + 253 /*domain*/ + 2 /* 2 brackes [] */ + 1 /* : */ + 5 /*port*/ + 1 /*\n*/

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Panicln(err)
		return
	}

	tlsConfig := &tls.Config{}
	tlsConfig.Certificates = append(tlsConfig.Certificates, cert)

	// BuildNameToCertificate has been deprecated since 1.14.
	// But since we also support older versions we'll keep this here.
	tlsConfig.BuildNameToCertificate() //nolint:staticcheck

	// Server
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
	if ln == nil {
		log.Panicln(`Error listening:`, *listen)
	}

	tlsLn := tls.NewListener(ln, tlsConfig.Clone())

	for {
		c, err := acceptConn(tlsLn)
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Panicln(err)
		}
		go serve(c)
	}
}
