package coredns

import (
	"context"
	"errors"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

func (c *ConsoleDns) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qName := state.Name()
	c.rwLock.RLock()
	defer c.rwLock.RUnlock()
	zone, record, err := c.QueryRecord(qName, state.Type())
	if err != nil {
		c.Debug("DNS 未命中: %s", err.Error())
		if errors.Is(err, ErrNoZones) {
			return plugin.NextOrFailure(c.Name(), c.Next, ctx, w, r)
		}
		return errorResponse(state, dns.RcodeSuccess)
	}
	var answers []dns.RR
	var extras []dns.RR

	switch state.Type() {
	case "A":
		a, e := c.GetRecordA(zone, record, qName)
		answers = append(answers, a...)
		extras = append(extras, e...)

	case "AAAA":
		a, e := c.GetRecordAAAA(zone, record, qName)
		answers = append(answers, a...)
		extras = append(extras, e...)
	case "TXT":
		a, e := c.GetRecordTXT(zone, record, qName)
		answers = append(answers, a...)
		extras = append(extras, e...)
	case "CNAME":
		a, e := c.GetRecordCNAME(zone, record, qName)
		answers = append(answers, a...)
		extras = append(extras, e...)
	case "NS":
		a, e := c.GetRecordNS(zone, record, qName)
		answers = append(answers, a...)
		extras = append(extras, e...)
	case "MX":
		a, e := c.GetRecordMX(zone, record, qName)
		answers = append(answers, a...)
		extras = append(extras, e...)
	case "SRV":
		a, e := c.GetRecordSRV(zone, record, qName)
		answers = append(answers, a...)
		extras = append(extras, e...)
	case "SOA":
		a, e := c.GetRecordSOA(zone, "@", qName)
		answers = append(answers, a...)
		extras = append(extras, e...)
	case "CAA":
		a, e := c.GetRecordCAA(zone, record, qName)
		answers = append(answers, a...)
		extras = append(extras, e...)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true
	m.Answer = append(m.Answer, answers...)
	m.Extra = append(m.Extra, extras...)

	state.SizeAndDo(m)
	m = state.Scrub(m)
	_ = w.WriteMsg(m)
	return dns.RcodeSuccess, nil

}

func errorResponse(state request.Request, code int) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(state.Req, code)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, false, true

	state.SizeAndDo(m)
	_ = state.W.WriteMsg(m)
	return dns.RcodeSuccess, nil
}
