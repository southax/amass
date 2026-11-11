// SPDX-License-Identifier: Apache-2.0

package enum

import "testing"

func TestNdxerLine(t *testing.T) {
	for msg, want := range map[string]string{
		`{"level":"INFO","msg":"ndxer related scope for example.com: added 3 domains","plugin":{"name":"ndxer"}}`:                                           "ndxer related scope for example.com: added 3 domains",
		`{"level":"WARN","msg":"ndxer hostnames for example.net are partial","plugin":{"name":"ndxer"}}`:                                                    "WARN ndxer hostnames for example.net are partial",
		`{"level":"INFO","msg":"ndxer related domain added","domain":"example.net","class":"subject","reason":"Shares a token.","plugin":{"name":"ndxer"}}`: "  example.net  subject  Shares a token.",
		`{"level":"INFO","msg":"ndxer related domain not added (review)","domain":"x.example","class":"review","plugin":{"name":"ndxer"}}`:                  "",
		`{"level":"INFO","msg":"Plugin started","plugin":{"name":"ndxer"}}`:                                                                                 "",
		`{"level":"INFO","msg":"relationship discovered","plugin":{"name":"DNS"}}`:                                                                          "",
		`not json`: "",
	} {
		if got := ndxerLine(msg); got != want {
			t.Errorf("ndxerLine(%s) = %q, want %q", msg, got, want)
		}
	}
}
