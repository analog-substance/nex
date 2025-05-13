package dns_guard_rail

import "strings"

var DomainMatches []DomainMatch
var CDNMatches []DomainMatch

type DomainMatch struct {
	Suffix  string
	Prefix  string
	Pattern string
}

func (d *DomainMatch) matches(target string) bool {
	matches := true
	if d.Suffix != "" {
		matches = strings.HasSuffix(target, d.Suffix)
	}

	if matches && d.Prefix != "" {
		matches = strings.HasPrefix(target, d.Prefix)
	}

	return matches
}

func ShouldInvestigateMore(domain string) bool {
	if IsCDN(domain) {
		return false
	}

	for _, matcher := range DomainMatches {
		if matcher.matches(domain) {
			return false
		}
	}

	return true
}

func IsCDN(domain string) bool {
	for _, matcher := range CDNMatches {
		if matcher.matches(domain) {
			return true
		}
	}

	return false
}

func init() {
	// TODO: make this better/configurable

	DomainMatches = append(DomainMatches,
		DomainMatch{
			Prefix: "ec2-",
			Suffix: ".amazonaws.com",
		},
		DomainMatch{
			Suffix: ".awsglobalaccelerator.com",
		},
		DomainMatch{
			Suffix: ".bc.googleusercontent.com",
		},
		DomainMatch{
			Suffix: ".1e100.net",
		},
		DomainMatch{
			Suffix: ".haip.transip.net",
		},
		DomainMatch{
			Suffix: ".windows.net",
		},
		DomainMatch{
			Suffix: ".cloudfront.net",
		},
		DomainMatch{
			Suffix: ".one.com",
		},
		DomainMatch{
			Suffix: ".mktossl.com",
		},
		DomainMatch{
			Suffix: ".zendesk.com",
		},
		DomainMatch{
			Suffix: ".cloudflare.com",
		},
		DomainMatch{
			Suffix: ".document360.io",
		},
		DomainMatch{
			Suffix: ".salesforce.com",
		},
		DomainMatch{
			Suffix: ".hubapi.com",
		},
		DomainMatch{
			Suffix: ".microsoft.com",
		})

	CDNMatches = append(CDNMatches, DomainMatch{
		Suffix: ".r.cloudfront.net",
	})

}
