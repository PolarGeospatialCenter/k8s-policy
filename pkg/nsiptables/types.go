package nsiptables

import "strings"

type IPVersion int

var ProtocolIPv6 IPVersion = 6
var ProtocolIPv4 IPVersion = 4

type NsIpTables struct {
	NSPath  string
	Version IPVersion
	Filter  *FilterTable
}

func NewNsIpTables(nsPath string, version IPVersion) *NsIpTables {
	return &NsIpTables{
		NSPath:  nsPath,
		Version: version,
		Filter:  NewFilterTable(),
	}
}

type FilterTable struct {
	Input             *Chain
	Output            *Chain
	Forward           *Chain
	userDefinedChains []*Chain
}

func NewFilterTable() *FilterTable {
	return &FilterTable{
		Input:             NewChain("INPUT"),
		Output:            NewChain("OUTPUT"),
		Forward:           NewChain("FORWARD"),
		userDefinedChains: make([]*Chain, 0),
	}
}

func (t *FilterTable) AddChain(chain *Chain) {
	t.userDefinedChains = append(t.userDefinedChains, chain)
}

type Chain struct {
	Name  string
	Rules []Rule
}

func NewChain(name string) *Chain {
	c := &Chain{
		Name:  name,
		Rules: make([]Rule, 0, 0),
	}
	return c
}

func (c *Chain) Append(rule Rule) {
	c.Rules = append(c.Rules, rule)
}

func (c *Chain) GetName() string {
	return strings.ToUpper(c.Name)
}

type Rule string

func (r Rule) Spec() []string {
	return strings.Fields(string(r))
}
