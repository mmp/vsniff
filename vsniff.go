// vatsniff
//
// sniffs a vatsim network connection and saves the network traffic to a
// file, including timestamps.  The vice client is then capable of replaying
// those messages, as if it were connected to vatsim.
//
// networking bits derived from Jaime Pillora <dev@jpillora.com>'s
// tcp-proxy (MIT licensed)

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Message struct {
	Time     time.Time
	Sent     bool
	Contents string
}

var (
	lg *log.Logger

	localPort  = flag.Int("local", 6809, "local port to listen to")
	clientPort = flag.Int("sidechannel", 6810, "port for serving stream of messages")
	remote     = flag.String("remote", "137.184.8.6:6809", "remote server address")

	// All of the network traffic for a session is accumulated in messages;
	// updates to messages are protected by messageMutex.
	messageMutex sync.Mutex
	messageCond  *sync.Cond
	messages     []Message
)

func main() {
	lg = log.New(os.Stderr, "vsniff ", log.Ltime|log.Lmicroseconds|log.Lshortfile)

	flag.Parse()

	messageCond = sync.NewCond(&messageMutex)

	listenAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", *localPort))
	if err != nil {
		lg.Fatalf("Failed to resolve local address: %s", err)
	}
	remoteAddr, err := net.ResolveTCPAddr("tcp", *remote)
	if err != nil {
		lg.Fatalf("Failed to resolve remote address: %s", err)
	}
	clientAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", *clientPort))
	if err != nil {
		lg.Fatalf("Failed to resolve client address: %s", err)
	}

	go replayTraffic(clientAddr)
	sniffTraffic(listenAddr, remoteAddr)
}

func replayTraffic(clientAddr *net.TCPAddr) {
	listener, err := net.ListenTCP("tcp", clientAddr)
	if err != nil {
		lg.Fatalf("Failed to open local port to listen: %s", err)
	}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			lg.Printf("Failed to accept connection: %s", err)
			continue
		}

		go serveMessages(conn)
	}
}

// Serve all of the messages we've seen so far all at once and then send
// along subsequent ones as they arrive.
func serveMessages(conn *net.TCPConn) {
	n := 0
	messageMutex.Lock()
	defer messageMutex.Unlock()

	lg.Printf("Serving %d messages on conn %+v", len(messages), *conn)

	// loop precondition: mutex is locked
	for {
		for ; n < len(messages); n += 1 {
			msg := messages[n]
			if _, err := conn.Write([]byte(msg.Contents)); err != nil {
				lg.Printf("%v: error sending message %d: %+v. Closing connection.", err, n, msg)
				conn.Close()
				return
			}
		}

		// The sniffer will signal the condition variable when there are
		// new messages.
		messageCond.Wait()
	}
}

// Listen for connections locally on listenAddr and sniff the network
// traffic between listenAddr and remoteAddr.
func sniffTraffic(listenAddr, remoteAddr *net.TCPAddr) {
	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		lg.Fatalf("Failed to open local port to listen: %s", err)
	}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			lg.Printf("Failed to accept connection '%s'", err)
			continue
		}

		lg.Printf("New connection on %v", listenAddr)

		// TODO: still needed?
		lg.Printf("Discarding %d messages", len(messages))
		messageMutex.Lock()
		messages = nil
		messageMutex.Unlock()

		p := New(conn, listenAddr, remoteAddr)

		go p.Start()
	}
}

// Proxy - Manages a Proxy connection, piping data between local and remote.
type Proxy struct {
	laddr, raddr *net.TCPAddr
	lconn, rconn *net.TCPConn
	erred        bool
	errsig       chan bool
	w            io.WriteCloser
	encoder      *json.Encoder
}

// New - Create a new Proxy instance. Takes over local connection passed in,
// and closes it when finished.
func New(lconn *net.TCPConn, laddr, raddr *net.TCPAddr) *Proxy {
	p := &Proxy{
		lconn:  lconn,
		laddr:  laddr,
		raddr:  raddr,
		erred:  false,
		errsig: make(chan bool),
	}

	fn := time.Now().Format("2006-01-02@150405") + ".vsess"
	var err error
	p.w, err = os.Create(fn)
	if err != nil {
		lg.Fatalf("%s: %s", fn, err)
	}

	p.encoder = json.NewEncoder(p.w)

	return p
}

// Start - open connection to remote and start proxying data.
func (p *Proxy) Start() {
	defer p.lconn.Close()

	//connect to remote
	var err error
	p.rconn, err = net.DialTCP("tcp", nil, p.raddr)

	if err != nil {
		lg.Fatalf("Remote connection failed: %s", err)
		return
	}
	defer p.rconn.Close()

	p.lconn.SetNoDelay(true)
	p.rconn.SetNoDelay(true)

	lg.Printf("Opened %s >>> %s", p.laddr.String(), p.raddr.String())

	go p.pipe(p.lconn, p.rconn)
	go p.pipe(p.rconn, p.lconn)

	// Wait for close...
	<-p.errsig

	lg.Printf("Closed %s >>> %s", p.laddr.String(), p.raddr.String())

	p.w.Close()
	lg.Printf("Closed session file")

	messageMutex.Lock()
	messages = nil
	messageMutex.Unlock()
}

func (p *Proxy) err(s string, err error) {
	if p.erred {
		return
	}
	if err != io.EOF {
		lg.Printf(s, err)
	}
	p.errsig <- true
	p.erred = true
}

func (p *Proxy) pipe(src, dst io.ReadWriter) {
	// Use bufio so we don't read partial messages.
	b := bufio.NewReader(src)
	for {
		str, err := b.ReadString('\n')
		if err != nil {
			p.err("Read failed: %v\n", err)
			return
		}

		// Send it before we save it to disk.
		_, err = dst.Write([]byte(str))
		if err != nil {
			p.err("Write failed: %v\n", err)
			return
		}

		if strings.HasPrefix(str, "#AA") {
			args := strings.Split(str, ":")
			// nuke the password field, in case it's present
			if args[4] != "" {
				args[4] = "(elided password)"
			}
			str = strings.Join(args, ":")
		}

		sending := src == p.lconn
		msg := Message{time.Now(), sending, str}
		messages = append(messages, msg)
		messageMutex.Lock()

		// Write it to the file immediately
		if err := p.encoder.Encode(msg); err != nil {
			lg.Printf("%s: error encoding message: %+v", err, msg)
		}

		messageCond.Broadcast()
		messageMutex.Unlock()
	}
}
