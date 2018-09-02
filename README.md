# k8s-policy

Allows the creation of iptables rules using k8s annotations


```yaml
apiVersion: v1
kind: Pod
metadata:
  iptables: '["-m tcp -p tcp -s 2001:db8::1 --dport 80 -j ACCEPT"]'
```
