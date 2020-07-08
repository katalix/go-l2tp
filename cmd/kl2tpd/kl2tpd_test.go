package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/katalix/go-l2tp/config"
)

func TestConfigParser(t *testing.T) {
	pppdArgsPath := "/tmp/test.pppd.args"
	pppdArgs := "noauth 10.42.0.1:10.42.0.2"

	f, err := os.Create(pppdArgsPath)
	if err != nil {
		t.Fatalf("os.Create(%v): %v", pppdArgsPath, err)
	}

	_, err = f.WriteString(pppdArgs)
	if err != nil {
		t.Fatalf("f.WriteString(%v): %v", pppdArgs, err)
	}

	err = f.Close()
	if err != nil {
		t.Fatalf("f.Close(): %v", err)
	}

	cases := []struct {
		name       string
		in         string
		expectFail bool
		out        *kl2tpdConfig
	}{
		{
			name: "pppdargs0",
			in: fmt.Sprintf(`[tunnel.t1]
				 peer = "127.0.0.1:9000"
				 version = "l2tpv2"
				 encap = "udp"

				 [tunnel.t1.session.s1]
				 pseudowire = "ppp"
				 pppd_args = "%s"`, pppdArgsPath),
			out: &kl2tpdConfig{
				pppArgs: map[string]map[string]*sessionPPPArgs{
					"t1": map[string]*sessionPPPArgs{
						"s1": &sessionPPPArgs{
							pppdArgs: strings.Split(pppdArgs, " "),
						},
					},
				},
			},
		},
		{
			name: "pppac0",
			in: `[tunnel.t1]
				 peer = "127.0.0.1:9000"
				 version = "l2tpv2"
				 encap = "udp"

				 [tunnel.t1.session.s1]
				 pseudowire = "ppp"
				 `,
			out: &kl2tpdConfig{
				pppArgs: map[string]map[string]*sessionPPPArgs{},
			},
		},
	}
	for _, c := range cases {
		cfg := newKl2tpdConfig()
		_, err := config.LoadStringWithCustomParser(c.in, cfg)
		if err != nil {
			t.Fatalf("LoadStringWithCustomParser: %v", err)
		}
		if !reflect.DeepEqual(cfg, c.out) {
			t.Fatalf("expect %v, got %v", c.out, cfg)
		}
	}

	os.Remove(pppdArgsPath)
}
