// +build linux

package nsiptables

import (
	"fmt"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/coreos/go-iptables/iptables"
)

func (t *NsIpTables) Apply() error {

	netns, err := ns.GetNS(t.NSPath)
	if err != nil {
		return err
	}

	err = netns.Do(func(_ ns.NetNS) error {
		var ipt *iptables.IPTables
		var err error

		if t.Version == ProtocolIPv6 {
			ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		} else {
			ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv4)
		}
		if err != nil {
			return fmt.Errorf("failed to locate iptables: %v", err)
		}

		table := "filter"

		appendRules := func(chain *Chain) error {
			for _, rule := range chain.Rules {
				if err := ipt.Append(table, chain.GetName(), rule.Spec()...); err != nil {
					return err
				}
			}
			return nil
		}

		for _, chain := range t.Filter.userDefinedChains {
			err = ipt.NewChain(table, chain.GetName())
			if err != nil {
				return fmt.Errorf("failed to create chain %s: %v", chain.GetName(), err)
			}
			err = appendRules(chain)
			if err != nil {
				return fmt.Errorf("failed to append rules to chain %s: %v", chain.GetName(), err)
			}
		}

		err = appendRules(t.Filter.Input)
		if err != nil {
			return fmt.Errorf("failed to append input rules to chain: %v", err)
		}

		err = appendRules(t.Filter.Output)
		if err != nil {
			return fmt.Errorf("failed to append output rules to chain: %v", err)
		}

		err = appendRules(t.Filter.Forward)
		if err != nil {
			return fmt.Errorf("failed to append forward rules to chain: %v", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error applying iptables rules: %v", err)
	}

	return nil
}
