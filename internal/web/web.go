// Package web serves the dashboard and its JSON API on the LAN.
package web

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/demyaha/brutter/internal/app"
	"github.com/demyaha/brutter/internal/netx"
)

//go:embed panel.html
var panel []byte

// actions maps each POST path to the X-Brutter-Action value it requires.
var actions = map[string]string{
	"/settings":        "settings",
	"/client":          "client",
	"/reset":           "reset",
	"/rescan":          "rescan",
	"/servers/refresh": "refresh",
	"/servers/remove":  "remove",
	"/valorant/rescan": "rescan",
}

type Server struct {
	App     *app.App
	Version string
	host    string
}

func (s *Server) header(w http.ResponseWriter, kind string) {
	h := w.Header()
	h.Set("Content-Type", kind)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; "+
		"style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
}

func (s *Server) json(w http.ResponseWriter, code int, v any) {
	s.header(w, "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) client(r *http.Request) (netip.Addr, error) {
	clients := s.App.Clients()
	value := r.URL.Query().Get("client")
	if value == "" && len(clients) > 0 {
		return clients[0], nil
	}
	a, err := netip.ParseAddr(value)
	if err == nil {
		for _, c := range clients {
			if c == a {
				return a, nil
			}
		}
	}
	return netip.Addr{}, errors.New("unknown gaming device")
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if len(s.App.Clients()) == 0 {
		// A fresh install has no gaming device yet; the dashboard asks for one.
		s.json(w, 200, map[string]any{"version": s.Version, "clients": []string{},
			"settings": s.App.Settings.Get(), "capture_error": s.App.CaptureError(),
			"firewall_error": s.App.FirewallError()})
		return
	}
	client, err := s.client(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	csw, vw, ok := s.App.Workers(client)
	if !ok {
		http.Error(w, "device is starting", http.StatusServiceUnavailable)
		return
	}
	now := time.Now().Unix()
	cs, val := csw.Status(), vw.Status()
	clients := []string{}
	for _, c := range s.App.Clients() {
		clients = append(clients, c.String())
	}
	s.json(w, 200, map[string]any{
		"version":        s.Version,
		"client":         client.String(),
		"clients":        clients,
		"settings":       s.App.Settings.Get(),
		"capture_error":  s.App.CaptureError(),
		"firewall_error": s.App.FirewallError(),
		"cs":             cs,
		"cs_healthy":     now-cs.UpdatedAt < 20,
		"valorant":       val,
		"val_healthy":    now-val.UpdatedAt < 20,
	})
}

func endpoint(body []byte) (netx.Endpoint, error) {
	var v struct {
		Server string `json:"server"`
		DPort  uint16 `json:"dport"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return netx.Endpoint{}, err
	}
	a, err := netip.ParseAddr(v.Server)
	if err != nil || !netx.IsPublic(a) || v.DPort == 0 {
		return netx.Endpoint{}, errors.New("invalid server")
	}
	return netx.Endpoint{Server: a, Port: v.DPort}, nil
}

func (s *Server) act(w http.ResponseWriter, r *http.Request) {
	action, ok := actions[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Same-origin requests from the dashboard only: no other site can drive it.
	if r.Host != s.host || r.Header.Get("Origin") != "http://"+s.host || r.Header.Get("X-Brutter-Action") != action {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1025))
	if err != nil || len(body) > 1024 {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	conflict := func(err error) {
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		s.json(w, http.StatusAccepted, map[string]bool{"accepted": true})
	}
	switch r.URL.Path {
	case "/settings":
		_, err := s.App.Settings.Update(body)
		conflict(err)
	case "/client":
		var v struct {
			Clients []string `json:"clients"`
		}
		if err := json.Unmarshal(body, &v); err != nil {
			conflict(err)
			return
		}
		conflict(s.App.SetClients(v.Clients))
	case "/reset":
		s.App.Settings.Reset()
		conflict(nil)
	default:
		client, err := s.client(r)
		if err != nil {
			conflict(err)
			return
		}
		csw, vw, ok := s.App.Workers(client)
		if !ok {
			conflict(errors.New("device is starting"))
			return
		}
		switch r.URL.Path {
		case "/rescan":
			conflict(csw.Request("rescan", netx.Endpoint{}))
		case "/valorant/rescan":
			conflict(vw.RequestRescan())
		default:
			ep, err := endpoint(body)
			if err != nil {
				conflict(err)
				return
			}
			conflict(csw.Request(action, ep))
		}
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// The version is in the page from the first paint, so the brand pill
	// never widens when the first status arrives.
	page := bytes.Replace(panel, []byte(`<small id="version"></small>`),
		[]byte(`<small id="version">v`+html.EscapeString(s.Version)+`</small>`), 1)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s.header(w, "text/html; charset=utf-8")
		w.Write(page)
	})
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		clients := []string{}
		for _, c := range s.App.Clients() {
			clients = append(clients, c.String())
		}
		s.json(w, 200, map[string]any{"clients": clients, "devices": s.App.Devices.List(s.App.Clients())})
	})
	mux.HandleFunc("POST /", s.act)
	return mux
}

// Listen serves on listen:port until the listener closes.
func (s *Server) Listen(listen string, port int) (*http.Server, error) {
	s.host = net.JoinHostPort(listen, strconv.Itoa(port))
	ln, err := net.Listen("tcp4", s.host)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go srv.Serve(ln)
	return srv, nil
}
