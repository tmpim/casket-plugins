package tmpauth

import (
	"log"
	"net/http"
	"os"

	"github.com/tmpim/casket"
	"github.com/tmpim/casket/caskethttp/httpserver"
)

const (
	TmpAuthEndpoint = "https://auth.tmpim.pw"
)

func init() {
	casket.RegisterPlugin("tmpauth", casket.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *casket.Controller) error {
	config, err := parseConfig(c)
	if err != nil {
		return err
	}

	cfg := httpserver.GetConfig(c)

	mid := func(next httpserver.Handler) httpserver.Handler {
		return &Tmpauth{
			Next:   next,
			Config: config,
			Logger: log.New(os.Stderr, "tmpauth", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile),
			HttpClient: &http.Client{
				Transport: &Transport{
					config: config,
					base:   http.DefaultTransport,
				},
			},
			TokenCache: make(map[[32]byte]*CachedToken),
		}
	}
	cfg.AddMiddleware(mid)

	return nil
}
