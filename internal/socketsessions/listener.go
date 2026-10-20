package socketsessions

import (
	"errors"
	"net"
	"sync"
)

// Track the underlying sockets, including connections hijacked for CONNECT.
type trackedListener struct {
	net.Listener
	mu     sync.Mutex
	closed bool
	conns  map[*trackedConn]struct{}
}

type trackedConn struct {
	net.Conn
	owner *trackedListener
	once  sync.Once
}

func newTrackedListener(l net.Listener) *trackedListener {
	return &trackedListener{Listener: l, conns: make(map[*trackedConn]struct{})}
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		c.Close()
		return nil, net.ErrClosed
	}
	tracked := &trackedConn{Conn: c, owner: l}
	l.conns[tracked] = struct{}{}
	return tracked, nil
}

func (l *trackedListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	conns := make([]*trackedConn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	err := l.Listener.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	for _, c := range conns {
		if closeErr := c.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}
	return err
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})
	return err
}
