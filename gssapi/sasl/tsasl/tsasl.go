package main

import (
	"net"

	"github.com/BryceDFisher/gokrb5/gssapi/sasl"
	"github.com/Novetta/go.logging"
	"github.com/jcmturner/gofork/encoding/asn1"
	"gopkg.in/jcmturner/gokrb5.v4/asn1tools"
	"gopkg.in/jcmturner/gokrb5.v4/client"
	"gopkg.in/jcmturner/gokrb5.v4/config"
	"gopkg.in/jcmturner/gokrb5.v4/iana/nametype"
	"gopkg.in/jcmturner/gokrb5.v4/keytab"
)

func main() {
	kt, err := keytab.Load("perseus.keytab")
	if err != nil {
		logging.Fatalf("Unable to load keytab: %s", err)
		return
	}

	if len(kt.Entries) == 0 {
		logging.Fatalf("No entries in keytab")
		return
	}

	for i, e := range kt.Entries {
		logging.Mandatory("Entry %d - type %d - %s", i, e.Principal.NameType, e.Principal.Realm)
		if e.Principal.NameType == 0 {
			kt.Entries[i].Principal.NameType = nametype.KRB_NT_PRINCIPAL
		}
		for _, c := range e.Principal.Components {
			logging.Mandatory("Found entry component: %s", c)
		}
	}
	kte := kt.Entries[0]

	conf, err := config.Load("/etc/krb5.conf")
	if err != nil {
		logging.Fatalf("Unable to read krb5 config: %s", err.Error())
		return
	}

	cl := client.NewClientWithKeytab("HTTP/perseus.novadev.local", kte.Principal.Realm, kt)
	cl.WithConfig(conf)
	//cl.Config.LibDefaults.UDPPreferenceLimit = 1
	cl.GoKrb5Conf.DisablePAFXFast = true
	err = cl.Login()
	if err != nil {
		logging.Fatalf("Unable to login; %s", err.Error())
	}

	rw, err := net.Dial("tcp", "novdev-ddc-001.novadev.local:389")
	if err != nil {
		logging.Fatalf("Unable to dial: %s", err.Error())
		return
	}

	w := sasl.NewWrapper(rw)
	_, err = w.Connect(WrapperMarshal(), "ldap", cl)
	if err != nil {
		logging.Fatalf("Unable to connect: %s", err.Error())
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

func WrapperMarshal() func([]byte) []byte {
	return func(b []byte) []byte {
		data, err := asn1.Marshal(Credentials{[]byte("GSSAPI"), b})
		if err != nil {
			logging.Fatalf("Unable to marshal credentials: %s", err.Error())
		}

		data, err = asn1.Marshal(LDAPAuthChoice{
			ChoiceSASL: data,
		})
		if err != nil {
			logging.Fatalf("Unable to marshal choice: %s", err.Error())
		}
		data, err = asn1.Marshal(BindRequest{
			Version:        3,
			Authentication: data,
		})
		if err != nil {
			logging.Fatalf("Unable to marshal bind request: %s", err.Error())
		}

		data = asn1tools.AddASNAppTag(data, 0)
		return data
	}
}
