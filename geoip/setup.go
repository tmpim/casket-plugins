package geoip

import (
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/tmpim/casket"
	"github.com/tmpim/casket/caskethttp/httpserver"
	"github.com/mmcloughlin/geohash"
	"github.com/oschwald/maxminddb-golang"
)

// GeoIP represents a middleware instance
type GeoIP struct {
	Next      httpserver.Handler
	DBHandler *maxminddb.Reader
	Config    Config
}

type GeoIPRecord struct {
	Country struct {
		ISOCode           string            `maxminddb:"iso_code"`
		IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
		Names             map[string]string `maxminddb:"names"`
		GeoNameID         uint64            `maxminddb:"geoname_id"`
	} `maxminddb:"country"`

	City struct {
		Names     map[string]string `maxminddb:"names"`
		GeoNameID uint64            `maxminddb:"geoname_id"`
	} `maxminddb:"city"`

	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
		TimeZone  string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

// Init initializes the plugin
func init() {
	casket.RegisterPlugin("geoip", casket.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *casket.Controller) error {
	config, err := parseConfig(c)
	if err != nil {
		return err
	}

	dbhandler, err := maxminddb.Open(config.DatabasePath)
	if err != nil {
		return c.Err("geoip: Can't open database: " + config.DatabasePath)
	}
	// Create new middleware
	newMiddleWare := func(next httpserver.Handler) httpserver.Handler {
		return &GeoIP{
			Next:      next,
			DBHandler: dbhandler,
			Config:    config,
		}
	}
	// Add middleware
	cfg := httpserver.GetConfig(c)
	cfg.AddMiddleware(newMiddleWare)

	return nil
}

func (gip GeoIP) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	gip.lookupLocation(w, r)
	return gip.Next.ServeHTTP(w, r)
}

func (gip GeoIP) lookupLocation(w http.ResponseWriter, r *http.Request) {
	record := gip.fetchGeoipData(r)

	replacer := newReplacer(r)
	replacer.Set("geoip_country_code", record.Country.ISOCode)
	replacer.Set("geoip_country_name", record.Country.Names["en"])
	replacer.Set("geoip_country_eu", strconv.FormatBool(record.Country.IsInEuropeanUnion))
	replacer.Set("geoip_country_geoname_id", strconv.FormatUint(record.Country.GeoNameID, 10))
	replacer.Set("geoip_city_name", record.City.Names["en"])
	replacer.Set("geoip_city_geoname_id", strconv.FormatUint(record.City.GeoNameID, 10))
	replacer.Set("geoip_latitude", strconv.FormatFloat(record.Location.Latitude, 'f', 6, 64))
	replacer.Set("geoip_longitude", strconv.FormatFloat(record.Location.Longitude, 'f', 6, 64))
	replacer.Set("geoip_geohash", geohash.Encode(record.Location.Latitude, record.Location.Longitude))
	replacer.Set("geoip_time_zone", record.Location.TimeZone)

	if rr, ok := w.(*httpserver.ResponseRecorder); ok {
		rr.Replacer = replacer
	}
}

func (gip GeoIP) fetchGeoipData(r *http.Request) GeoIPRecord {
	clientIP, _ := getClientIP(r, true)

	var record = GeoIPRecord{}
	err := gip.DBHandler.Lookup(clientIP, &record)
	if err != nil {
		log.Println(err)
	}

	if record.Country.ISOCode == "" {
		record.Country.Names = make(map[string]string)
		record.City.Names = make(map[string]string)
		if clientIP.IsLoopback() {
			record.Country.ISOCode = "**"
			record.Country.Names["en"] = "Loopback"
			record.City.Names["en"] = "Loopback"
		} else {
			record.Country.ISOCode = "!!"
			record.Country.Names["en"] = "No Country"
			record.City.Names["en"] = "No City"
		}
	}

	return record
}

func getClientIP(r *http.Request, strict bool) (net.IP, error) {
	var ip string

	// Use the client ip from the 'X-Forwarded-For' header, if available.
	if fwdFor := r.Header.Get("X-Forwarded-For"); fwdFor != "" && !strict {
		ips := strings.Split(fwdFor, ", ")
		ip = ips[0]
	} else {
		// Otherwise, get the client ip from the request remote address.
		var err error
		ip, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			if serr, ok := err.(*net.AddrError); ok && serr.Err == "missing port in address" { // It's not critical try parse
				ip = r.RemoteAddr
			} else {
				log.Printf("Error when SplitHostPort: %v", serr.Err)
				return nil, err
			}
		}
	}

	// Parse the ip address string into a net.IP.
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, errors.New("unable to parse address")
	}

	return parsedIP, nil
}

func newReplacer(r *http.Request) httpserver.Replacer {
	return httpserver.NewReplacer(r, nil, "")
}
