package httpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

// socks5DialContext returns a DialContext that tunnels through a SOCKS5 proxy.
// It always forwards the target host name to the proxy (socks5h semantics),
// which is what penetration tests normally want so DNS happens server side.
func socks5DialContext(proxyURL *url.URL, base *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "1080")
	}
	var auth *socksAuth
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		auth = &socksAuth{user: proxyURL.User.Username(), pass: pass}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := base.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("socks5: dial proxy: %w", err)
		}
		deadline := time.Now().Add(10 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)
		if err := socks5Handshake(conn, addr, auth); err != nil {
			conn.Close()
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}
}

type socksAuth struct{ user, pass string }

func socks5Handshake(conn net.Conn, target string, auth *socksAuth) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("socks5: bad target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("socks5: bad port %q", portStr)
	}
	methods := []byte{0x00}
	if auth != nil {
		methods = []byte{0x00, 0x02}
	}
	greet := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greet); err != nil {
		return fmt.Errorf("socks5: greeting: %w", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("socks5: greeting reply: %w", err)
	}
	if buf[0] != 0x05 {
		return errors.New("socks5: bad version in greeting reply")
	}
	switch buf[1] {
	case 0x00:
	case 0x02:
		if auth == nil {
			return errors.New("socks5: proxy requires authentication")
		}
		req := []byte{0x01, byte(len(auth.user))}
		req = append(req, auth.user...)
		req = append(req, byte(len(auth.pass)))
		req = append(req, auth.pass...)
		if _, err := conn.Write(req); err != nil {
			return fmt.Errorf("socks5: auth: %w", err)
		}
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("socks5: auth reply: %w", err)
		}
		if buf[1] != 0x00 {
			return errors.New("socks5: authentication rejected")
		}
	default:
		return fmt.Errorf("socks5: unsupported auth method 0x%02x", buf[1])
	}
	mustIP := net.ParseIP(host) != nil
	var req []byte
	if mustIP {
		ip := net.ParseIP(host)
		if v4 := ip.To4(); v4 != nil {
			req = append([]byte{0x05, 0x01, 0x00, 0x01}, v4...)
		} else {
			req = append([]byte{0x05, 0x01, 0x00, 0x04}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks5: hostname too long")
		}
		req = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5: connect: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5: connect reply: %w", err)
	}
	if head[0] != 0x05 {
		return errors.New("socks5: bad version in connect reply")
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connect failed with code 0x%02x", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return fmt.Errorf("socks5: connect reply address: %w", err)
		}
		skip = int(l[0])
	default:
		return fmt.Errorf("socks5: unknown address type 0x%02x", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return fmt.Errorf("socks5: connect reply tail: %w", err)
	}
	return nil
}
