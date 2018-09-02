package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PolarGeospatialCenter/k8s-policy/pkg/nsiptables"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

type PluginConf struct {
	types.NetConf

	RawPrevResult *map[string]interface{} `json:"prevResult"`
	PrevResult    *current.Result         `json:"-"`
	KubeConfig    string                  `json:"kubeConfig"`
	StaticRules   PodRules                `json:"staticRules"`
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(conf.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		conf.RawPrevResult = nil
		conf.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	return &conf, nil

}

func getPodFromArgs(args string) (namespace, podName string, err error) {
	argList := strings.Split(args, ";")
	argMap := make(map[string]string, len(argList))
	for _, arg := range argList {
		vals := strings.Split(arg, "=")
		if len(vals) == 2 {
			argMap[vals[0]] = vals[1]
		}
	}

	namespace, ok := argMap["K8S_POD_NAMESPACE"]
	if !ok || namespace == "" {
		return namespace, "", fmt.Errorf("no K8S_POD_NAMESPACE provided in CNI_ARGS")
	}

	podName, ok = argMap["K8S_POD_NAME"]
	if !ok || podName == "" {
		return namespace, podName, fmt.Errorf("no K8S_POD_NAME provided in CNI_ARGS")
	}

	return namespace, podName, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}

	k8sClient := &KubeClient{KubeConfig: conf.KubeConfig}
	// Get pod annotations
	namespace, podName, err := getPodFromArgs(args.Args)
	if err != nil {
		return err
	}
	pod, err := k8sClient.GetPod(namespace, podName)
	if err != nil {
		return fmt.Errorf("unable to get pod: %v", err)
	}

	podRules, err := getPodRules(pod)
	if err != nil {
		return fmt.Errorf("unable to parse rules from pod: %v", err)
	}

	err = applyIpTablesRules(args.Netns, podRules.IPv4, conf.StaticRules.IPv4, nsiptables.ProtocolIPv4)
	if err != nil {
		return fmt.Errorf("unable to apply iptables rules: %v", err)
	}

	err = applyIpTablesRules(args.Netns, podRules.IPv6, conf.StaticRules.IPv6, nsiptables.ProtocolIPv6)
	if err != nil {
		return fmt.Errorf("unable to apply ip6tables rules: %v", err)
	}

	return types.PrintResult(conf.PrevResult, conf.CNIVersion)
}

func applyIpTablesRules(nsPath string, dynamicRules, staticRules []string, ipVersion nsiptables.IPVersion) error {
	nsIpTable := nsiptables.NewNsIpTables(nsPath, ipVersion)

	dynamicChain := nsiptables.NewChain("K8S_POLICY_DYNAMIC")
	for _, rule := range dynamicRules {
		dynamicChain.Append(nsiptables.Rule(rule))
	}
	nsIpTable.Filter.AddChain(dynamicChain)

	staticChain := nsiptables.NewChain("K8S_POLICY_STATIC")
	for _, rule := range staticRules {
		staticChain.Append(nsiptables.Rule(rule))
	}
	nsIpTable.Filter.AddChain(staticChain)

	// nsIpTable.Filter.Input.Append(nsiptables.Rule("-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"))
	nsIpTable.Filter.Input.Append(nsiptables.Rule("-j K8S_POLICY_DYNAMIC"))
	nsIpTable.Filter.Input.Append(nsiptables.Rule("-j K8S_POLICY_STATIC"))
	nsIpTable.Filter.Input.Append(nsiptables.Rule("-j DROP"))

	return nsIpTable.Apply()
}

func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	_ = conf

	return nil
}

func main() {
	// TODO: implement plugin version
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports("0.3.0", "0.3.1", version.Current()))
}
