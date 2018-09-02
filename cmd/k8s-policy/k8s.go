package main

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type PodRules struct {
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

func NewPodRules() *PodRules {
	return &PodRules{
		IPv4: make([]string, 0, 0),
		IPv6: make([]string, 0, 0),
	}
}

type PodRetriever interface {
	GetPod(string, string) (*corev1.Pod, error)
}

type KubeClient struct {
	KubeConfig string
}

func (k *KubeClient) client() (*kubernetes.Clientset, error) {
	conf, err := clientcmd.BuildConfigFromFlags("", k.KubeConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to load kubeconfig from %s: %v", k.KubeConfig, err)
	}

	return kubernetes.NewForConfig(conf)
}

func (k *KubeClient) GetPod(namespace, podName string) (*corev1.Pod, error) {
	client, err := k.client()
	if err != nil {
		return nil, fmt.Errorf("error getting client: %v", err)
	}

	pod, err := client.CoreV1().Pods(namespace).Get(podName, metav1.GetOptions{})
	if err != nil && kubeerrors.IsNotFound(err) {
		return nil, nil
	}

	return pod, err
}

func getPodRules(pod *corev1.Pod) (*PodRules, error) {
	rawRules, ok := pod.GetAnnotations()["k8s-policy-rules"]
	if !ok {
		return NewPodRules(), nil
	}

	rules := NewPodRules()
	err := json.Unmarshal([]byte(rawRules), rules)
	return rules, err
}
