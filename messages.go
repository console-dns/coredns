package coredns

import (
	"github.com/console-dns/spec/models"
	"github.com/miekg/dns"
)

func (c *ConsoleDns) GetRecordA(zone, record, name string) (answers []dns.RR, extras []dns.RR) {
	answers = make([]dns.RR, 0)
	extras = make([]dns.RR, 0)
	c.record(zone, record, func(record *models.Record) {
		for _, a := range record.A {
			answers = append(answers, &dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET, Ttl: a.Ttl},
				A: a.Ip,
			})
		}
	})
	return
}

func (c *ConsoleDns) GetRecordAAAA(zone, record, name string) (answers []dns.RR, extras []dns.RR) {
	answers = make([]dns.RR, 0)
	extras = make([]dns.RR, 0)
	c.record(zone, record, func(record *models.Record) {
		for _, a := range record.AAAA {
			answers = append(answers, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET, Ttl: a.Ttl},
				AAAA: a.Ip,
			})
		}
	})
	return
}

func (c *ConsoleDns) GetRecordTXT(zone, record, name string) (answers []dns.RR, extras []dns.RR) {
	answers = make([]dns.RR, 0)
	extras = make([]dns.RR, 0)
	c.record(zone, record, func(record *models.Record) {
		for _, txt := range record.TXT {
			answers = append(answers, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET, Ttl: txt.Ttl},
				Txt: split255(txt.Text),
			})
		}
	})
	return
}
func (c *ConsoleDns) GetRecordCNAME(zone, record, name string) (answers []dns.RR, extras []dns.RR) {
	answers = make([]dns.RR, 0)
	extras = make([]dns.RR, 0)
	c.record(zone, record, func(record *models.Record) {
		for _, cname := range record.CNAME {
			answers = append(answers, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET, Ttl: cname.Ttl},
				Target: dns.Fqdn(cname.Host),
			})
		}
	})
	return
}

func (c *ConsoleDns) GetRecordNS(zone, record, name string) (answers []dns.RR, extras []dns.RR) {
	answers = make([]dns.RR, 0)
	extras = make([]dns.RR, 0)

	c.record(zone, record, func(record *models.Record) {
		for _, ns := range record.NS {
			answers = append(answers, &dns.NS{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET, Ttl: ns.Ttl},
				Ns: dns.Fqdn(ns.Host),
			})
			extras = append(extras, c.hosts(ns.Host)...)
		}
	})
	return
}

func (c *ConsoleDns) GetRecordMX(zone, record, name string) (answers []dns.RR, extras []dns.RR) {
	answers = make([]dns.RR, 0)
	extras = make([]dns.RR, 0)

	c.record(zone, record, func(record *models.Record) {
		for _, mx := range record.MX {
			answers = append(answers, &dns.MX{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET, Ttl: mx.Ttl},
				Preference: mx.Preference,
				Mx:         dns.Fqdn(mx.Host),
			})
			extras = append(extras, c.hosts(mx.Host)...)
		}
	})
	return
}

func (c *ConsoleDns) GetRecordSRV(zone, record, name string) (answers []dns.RR, extras []dns.RR) {
	answers = make([]dns.RR, 0)
	extras = make([]dns.RR, 0)

	c.record(zone, record, func(record *models.Record) {
		for _, srv := range record.SRV {
			answers = append(answers, &dns.SRV{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET, Ttl: srv.Ttl},
				Priority: srv.Priority,
				Weight:   srv.Weight,
				Port:     srv.Port,
				Target:   dns.Fqdn(srv.Target),
			},
			)
			extras = append(extras, c.hosts(srv.Target)...)
		}
	})
	return
}

func (c *ConsoleDns) GetRecordSOA(zone, record, name string) (answers []dns.RR, extras []dns.RR) {
	answers = make([]dns.RR, 0)
	extras = make([]dns.RR, 0)

	c.record(zone, record, func(r *models.Record) {
		soa := r.SOA
		if soa == nil {
			return
		}
		answers = append(answers, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(zone),
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET, Ttl: soa.Ttl},
			Ns:      dns.Fqdn(soa.MName),
			Mbox:    dns.Fqdn(soa.RName),
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			Minttl:  soa.Minimum,
		})
		//zone, record, err := c.QueryRecord(soa.MName, "NS")
		//if err == nil {
		//	as, ext := c.GetRecordNS(zone, record, soa.MName)
		//	extras = append(extras, as...)
		//	extras = append(extras, ext...)
		//}
	})
	return
}

func (c *ConsoleDns) GetRecordCAA(zone, record, name string) (answers []dns.RR, extras []dns.RR) {
	answers = make([]dns.RR, 0)
	extras = make([]dns.RR, 0)

	c.record(zone, record, func(record *models.Record) {
		for _, caa := range record.CAA {
			answers = append(answers, &dns.CAA{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeCAA,
					Class:  dns.ClassINET},
				Flag:  caa.Flag,
				Tag:   caa.Tag,
				Value: caa.Value,
			})
		}
	})
	return
}

func split255(s string) []string {
	if len(s) < 255 {
		return []string{s}
	}
	var sx []string
	p, i := 0, 255
	for {
		if i <= len(s) {
			sx = append(sx, s[p:i])
		} else {
			sx = append(sx, s[p:])
			break

		}
		p, i = p+255, i+255
	}

	return sx
}
