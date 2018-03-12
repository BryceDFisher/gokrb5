package sasl

import (
	"net"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"gopkg.in/jcmturner/gokrb5.v4/asn1tools"
	"gopkg.in/jcmturner/gokrb5.v4/client"
	"gopkg.in/jcmturner/gokrb5.v4/config"
	"gopkg.in/jcmturner/gokrb5.v4/keytab"
)

func TestConnect(t *testing.T) {
	kt, err := keytab.Load("bryce.keytab")
	if err != nil {
		t.Fatalf("Unable to load keytab: %s", err)
		return
	}

	if len(kt.Entries) == 0 {
		t.Fatalf("No entries in keytab")
		return
	}

	for i, e := range kt.Entries {
		t.Logf("Entry %d", i)
		for _, c := range e.Principal.Components {
			t.Logf("Found entry component: %s", c)
		}
	}
	kte := kt.Entries[0]

	conf, err := config.Load("/etc/krb5.conf")
	if err != nil {
		t.Fatalf("Unable to read krb5 config: %s", err.Error())
		return
	}

	cl := client.NewClientWithKeytab("brycef", kte.Principal.Realm, kt)
	cl.WithConfig(conf)
	cl.GoKrb5Conf.DisablePAFXFast = true
	err = cl.Login()
	if err != nil {
		t.Fatalf("Unable to login; %s", err.Error())
	}

	rw, err := net.Dial("tcp", "novdev-ddc-001.novadev.local:389")
	if err != nil {
		t.Fatalf("Unable to dial: %s", err.Error())
		return
	}

	w := NewWrapper(rw)
	_, err = w.Connect(WrapperMarshal(t), "ldap", cl)
	if err != nil {
		t.Fatalf("Unable to connect: %s", err.Error())
	}
}

type BindRequest struct {
	Version        int
	name           string
	Authentication asn1.RawContent
}

type LDAPAuthChoice struct {
	ChoiceSASL asn1.RawContent `asn1:"tag:3"`
}

type Credentials struct {
	Mechanism   []byte
	Credentials []byte `asn1:"optional"`
}

var (
	BindParam = "tag:3"
)

func WrapperMarshal(t *testing.T) func([]byte) []byte {
	return func(b []byte) []byte {
		data, err := asn1.Marshal(Credentials{[]byte("GSSAPI"), b})
		if err != nil {
			t.Fatalf("Unable to marshal credentials: %s", err.Error())
		}

		data, err = asn1.Marshal(LDAPAuthChoice{
			ChoiceSASL: data,
		})
		if err != nil {
			t.Fatalf("Unable to marshal choice: %s", err.Error())
		}
		data, err = asn1.Marshal(BindRequest{
			Version:        3,
			Authentication: data,
		})
		if err != nil {
			t.Fatalf("Unable to marshal bind request: %s", err.Error())
		}

		data = asn1tools.AddASNAppTag(data, 0)
		return data
	}
}
