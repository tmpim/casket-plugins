package metrics

import (
	"reflect"
	"testing"

	"github.com/tmpim/casket"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		expected  *Metrics
	}{
		{`prometheus`, false, &Metrics{addr: defaultAddr, path: defaultPath, extraLabels: []extraLabel{}}},
		{`prometheus foo:123`, false, &Metrics{addr: "foo:123", path: defaultPath, extraLabels: []extraLabel{}}},
		{`prometheus foo bar`, true, nil},
		{`prometheus {
			a b
		}`, true, nil},
		{`prometheus
			prometheus`, true, nil},
		{`prometheus {
			address
		}`, true, nil},
		{`prometheus {
			path
		}`, true, nil},
		{`prometheus {
			hostname
		}`, true, nil},
		{`prometheus {
			address 0.0.0.0:1234
			use_casket_addr
		}`, true, nil},
		{`prometheus {
			use_casket_addr
			address 0.0.0.0:1234
		}`, true, nil},
		{`prometheus {
			use_casket_addr
		}`, false, &Metrics{useCasketAddr: true, addr: defaultAddr, path: defaultPath, extraLabels: []extraLabel{}}},
		{`prometheus {
			path /foo
		}`, false, &Metrics{addr: defaultAddr, path: "/foo", extraLabels: []extraLabel{}}},
		{`prometheus {
			use_casket_addr
			hostname example.com
		}`, false, &Metrics{useCasketAddr: true, hostname: "example.com", addr: defaultAddr, path: defaultPath, extraLabels: []extraLabel{}}},
		{`prometheus {
			label version 1.2
			label route_name {<X-Route-Name}
		}`, false, &Metrics{addr: defaultAddr, path: defaultPath, extraLabels: []extraLabel{extraLabel{"version", "1.2"}, extraLabel{"route_name", "{<X-Route-Name}"}}}},
		{`prometheus {
			latency_buckets
		}`, true, nil},
		{`prometheus {
			latency_buckets 0.1 2 5 10
		}`, false, &Metrics{addr: defaultAddr, path: defaultPath, extraLabels: []extraLabel{}, latencyBuckets: []float64{0.1, 2, 5, 10}}},
		{`prometheus {
			size_buckets
		}`, true, nil},
		{`prometheus {
			size_buckets 1 5 10 50 100 1e3 10e6
		}`, false, &Metrics{addr: defaultAddr, path: defaultPath, extraLabels: []extraLabel{}, sizeBuckets: []float64{1, 5, 10, 50, 100, 1e3, 10e6}}},
	}
	for i, test := range tests {
		c := casket.NewTestController("http", test.input)
		m, err := parse(c)
		if test.shouldErr && err == nil {
			t.Errorf("Test %v: Expected error but found nil", i)
		} else if !test.shouldErr && err != nil {
			t.Errorf("Test %v: Expected no error but found error: %v", i, err)
		}
		if !reflect.DeepEqual(test.expected, m) && !reflect.DeepEqual(*test.expected, *m) {
			t.Errorf("Test %v: Created Metrics (\n%#v\n) does not match expected (\n%#v\n)", i, m, test.expected)
		}
	}
}
