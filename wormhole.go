// Copyright 2022 The CortexTheseus Authors
// This file is part of the CortexTheseus library.
//
// The CortexTheseus library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The CortexTheseus library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the CortexTheseus library. If not, see <http://www.gnu.org/licenses/>

package wormhole

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CortexFoundation/CortexTheseus/common"
	"github.com/CortexFoundation/CortexTheseus/common/mclock"
	"github.com/CortexFoundation/CortexTheseus/log"
	mapset "github.com/deckarep/golang-set/v2"
	resty "github.com/go-resty/resty/v2"
	//"sync"
)

type Wormhole struct {
	cl *resty.Client
}

func New() *Wormhole {
	return &Wormhole{
		cl: resty.New().SetTimeout(time.Second * 10),
	}
}

func (wh *Wormhole) Tunnel(hash string) error {
	log.Debug("Wormhole tunnel", "hash", hash)
	for _, worm := range Wormholes {
		if _, err := wh.cl.R().Post(worm + hash); err != nil {
			log.Error("Wormhole err", "err", err, "worm", worm, "hash", hash)
		}
	}

	return nil
}

func (wh *Wormhole) BestTrackers() (ret []string) {
	defer wh.cl.SetTimeout(time.Second * 10)

	var hc, uc int

	for _, ur := range BestTrackerUrl {
		log.Debug("Fetch trackers", "url", ur)
		fmt.Println(ur)
		resp, err := wh.cl.R().Get(ur)

		if err != nil || resp == nil || len(resp.String()) == 0 {
			log.Warn("Global tracker lost", "err", err)
			continue
		}

		// 0.5s for health check
		wh.cl.SetTimeout(time.Millisecond * 2000)

		//var wg sync.WaitGroup
		var (
			str      = strings.Split(resp.String(), "\n\n")
			retCh    = make(chan string, len(str))
			failedCh = make(chan string, len(str))
			start    = mclock.Now()
		)
		for _, s := range str {
			//if len(ret) < CAP {
			//	wg.Add(1)
			go func(ss string) {
				//		defer wg.Done()
				if t, err := wh.healthCheck(ss); err == nil {
					//ret = append(ret, s)
					if t == 0 {
						hc++
					} else if t == 1 {
						uc++
					}
					retCh <- ss
				} else {
					//retCh <- ""
					failedCh <- ss
				}
			}(s)
			/*switch {
			case strings.HasPrefix(s, "http"), strings.HasPrefix(s, "https"):
				if _, err := wh.cl.R().Post(s); err != nil {
					log.Warn("tracker failed", "err", err)
				} else {
					ret = append(ret, s)
				}
			case strings.HasPrefix(s, "udp"):
				if u, err := url.Parse(s); err == nil {
					if host, port, err := net.SplitHostPort(u.Host); err == nil {
						if err := ping(host, port); err == nil {
							ret = append(ret, s)
						} else {
							log.Warn("UDP ping err", "s", s, "err", err)
						}
					}
				}
			default:
				log.Warn("Other protocols trackers", "s", s)
			}*/
			//} else {
			//	break
			//}
		}

		if ret == nil {
			ret = make([]string, 0)
		}
		for i := 0; i < len(str); i++ {
			select {
			case x := <-retCh:
				//if len(x) > 0 {
				log.Debug("Healthy tracker", "url", x, "latency", common.PrettyDuration(time.Duration(mclock.Now())-time.Duration(start)))
				ret = append(ret, x)
				//}
			case x := <-failedCh:
				// TODO
				log.Debug("Unhealthy tracker", "url", x, "latency", common.PrettyDuration(time.Duration(mclock.Now())-time.Duration(start)))

			}
		}

		//wg.Wait()
		fmt.Println(hc)
		fmt.Println(uc)

		if len(ret) > CAP {
			return
		}
		wh.cl.SetTimeout(time.Second * 10)
	}

	return
}

func (wh *Wormhole) healthCheck(s string) (int, error) {
	log.Debug("Global best trackers", "url", s)
	switch {
	case strings.HasPrefix(s, "http"), strings.HasPrefix(s, "https"):
		//if _, err := wh.cl.R().Post(s); err != nil {
		if err := checkHTTPTracker(s); err != nil {
			log.Warn("tracker failed", "err", err)
			// TODO
			return 0, err
		} else {
			//ret = append(ret, s)
			return 0, nil
		}
	case strings.HasPrefix(s, "udp"):
		if u, err := url.Parse(s); err == nil {
			if host, port, err := net.SplitHostPort(u.Host); err == nil {
				if err := ping(host, port); err == nil {
					//ret = append(ret, s)
					return 1, nil
				} else {
					log.Warn("UDP ping err", "s", s, "err", err)
					// TODO
					return 1, err
				}
			}
		} else {
			return 1, err
		}
	default:
		log.Warn("Other protocols trackers", "s", s)
		return -1, errors.New("invalid url protocol")
	}

	return -1, errors.New("unhealthy tracker url")
}

func (wh *Wormhole) ColaList() mapset.Set[string] {
	m := mapset.NewSet[string]()
	for _, url := range ColaUrl {
		resp, err := wh.cl.R().Get(url)

		if err != nil {
			log.Warn("Cola lost", "err", err)
			continue
		}

		str := strings.Split(resp.String(), "\n\n")
		for _, s := range str {
			log.Info("Cola", "ih", s)
			m.Add(s)
		}
	}

	return m
}

func random20Bytes() []byte {
	b := make([]byte, 20)
	rand.Read(b)
	return b
}

func buildAnnounceURL(base string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	infoHash := random20Bytes()
	peerID := []byte("-GT0001-" + hex.EncodeToString(random20Bytes())[:12])
	values := url.Values{
		"info_hash":  {string(infoHash)},
		"peer_id":    {string(peerID)},
		"port":       {"6881"},
		"uploaded":   {"0"},
		"downloaded": {"0"},
		"left":       {"0"},
		"compact":    {"1"},
		"event":      {"started"},
	}

	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func checkHTTPTracker(base string) error {
	fullURL, err := buildAnnounceURL(base)
	if err != nil {
		return fmt.Errorf("invalid tracker URL: %w", err)
	}

	client := http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(fullURL)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read tracker response: %w", err)
	}

	if bytes.Contains(body, []byte("failure reason")) {
		return fmt.Errorf("tracker responded with failure")
	}

	fmt.Printf("Tracker responded (%d bytes)\n", len(body))
	return nil
}

func ping(host, port string) error {
	address := net.JoinHostPort(host, port)

	return checkUDPTracker(address)

	/*raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte{})
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %w", err)
	}

	return nil*/
}

/*
	func ping(host string, port string) error {
		address := net.JoinHostPort(host, port)
		raddr, err1 := net.ResolveUDPAddr("udp", address)
		if err1 != nil {
			return err1
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if conn != nil {
			defer conn.Close()
		}
		return err
	}
*/
const (
	udpTimeout     = 5 * time.Second
	actionConnect  = 0
	actionAnnounce = 1
	protocolID     = 0x41727101980
)

func checkUDPTracker(trackerURL string) error {
	host, port, err := net.SplitHostPort(trackerURL[6:])
	if err != nil {
		return fmt.Errorf("invalid tracker URL: %w", err)
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("resolve failed: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(udpTimeout))

	transactionID := make([]byte, 4)
	rand.Read(transactionID)

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint64(protocolID))    // protocol ID
	binary.Write(&buf, binary.BigEndian, uint32(actionConnect)) // action = connect
	buf.Write(transactionID)                                    // transaction ID

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("send connect request failed: %w", err)
	}

	resp := make([]byte, 16)
	_, err = conn.Read(resp)
	if err != nil {
		return fmt.Errorf("connect response failed: %w", err)
	}

	if len(resp) < 16 || resp[0] != 0 || !bytes.Equal(resp[4:8], transactionID) {
		return fmt.Errorf("invalid connect response")
	}

	connectionID := resp[8:16]

	fmt.Println("Tracker responded to connect request.")
	fmt.Printf("Connection ID: %x\n", connectionID)
	return nil
}
