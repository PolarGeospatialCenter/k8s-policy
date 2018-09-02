// +build !linux

package nsiptables

import "fmt"

func (t *NsIpTables) Apply() error {
	return fmt.Errorf("not implemented on this platform")
}
