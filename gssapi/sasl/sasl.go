package sasl

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/jcmturner/gofork/encoding/asn1"
	"gopkg.in/jcmturner/gokrb5.v4/client"
	"gopkg.in/jcmturner/gokrb5.v4/crypto"
	"gopkg.in/jcmturner/gokrb5.v4/gssapi"
	"gopkg.in/jcmturner/gokrb5.v4/messages"
	"gopkg.in/jcmturner/gokrb5.v4/types"
)

//Wrapper is a sasl wrapper for negotiating and encrypting / decrypting connections
type Wrapper struct {
	rxseq uint32
	txseq uint32
	rw    io.ReadWriter
	key   types.EncryptionKey
}

//NewWrapper creates a new Wrapper with the given io.ReadWriter
func NewWrapper(rw io.ReadWriter) *Wrapper {
	return &Wrapper{
		rw: rw,
	}
}

type MarshalWrapper func([]byte) []byte

//Connect performs the initial negotiation
func (w *Wrapper) Connect(mw MarshalWrapper, service string, cl client.Client) (rw io.ReadWriter, err error) {
	tkt, key, err := cl.GetServiceTicket(service)
	if err != nil {
		return w.rw, err
	}

	w.key = key

	auth, err := gssapi.NewAuthenticator(*cl.Credentials, []int{gssapi.GSS_C_INTEG_FLAG, gssapi.GSS_C_CONF_FLAG})
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return w.rw, err
	}

	auth.GenerateSeqNumberAndSubKey(key.KeyType, etype.GetKeyByteSize())

	//Checksum

	apreq, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		return w.rw, err
	}

	tb, _ := hex.DecodeString(gssapi.TOK_ID_KRB_AP_REP)
	mt := gssapi.MechToken{
		OID:   gssapi.MechTypeOIDKRB5,
		TokID: tb,
		APReq: apreq,
	}

	mtb, err := mt.Marshal()
	if err != nil {
		return w.rw, err
	}

	nt := gssapi.NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{gssapi.MechTypeOIDKRB5},
		MechToken: mtb,
	}

	//send the request
	data, err := nt.Marshal()
	if err != nil {
		return w.rw, err
	}

	b := mw(data)

	_, err = w.rw.Write(b)
	if err != nil {
		return w.rw, err
	}

	//read the response
	b = make([]byte, 4096)
	_, err = rw.Read(b)
	if err != nil {
		return w.rw, err
	}
	err = mt.Unmarshal(b)
	if err != nil {
		return w.rw, err
	}
	if !mt.IsAPRep() {
		return w.rw, fmt.Errorf("Response is not an AP Reply: %s", err.Error())
	}

	return w, nil
}

func (w *Wrapper) Write(p []byte) (int, error) {
	return w.rw.Write(p)
}

func (w *Wrapper) Read(p []byte) (int, error) {
	return w.rw.Read(p)
}
