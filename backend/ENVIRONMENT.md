# Environment, generated 2026-10-22

## Host
{
 "platform": "Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.39",
 "cpu": "11th Gen Intel(R) Core(TM) i5-11260H @ 2.60GHz",
 "logical_cpus": 12,
 "ram_gb_visible": 3.7,
 "python": "3.12.3"
}

## Tools
Client Version: v1.36.4
Kustomize Version: v5.8.1
kind v0.33.0-alpha+fed268827e21ca go1.26.7 linux/amd64
v3.21.4+g813176c

## Cluster
Server Version: v1.37.0-rc.1
NAME                                STATUS   ROLES           AGE   VERSION        INTERNAL-IP   EXTERNAL-IP   OS-IMAGE                       KERNEL-VERSION                             CONTAINER-RUNTIME
cape-policy-cluster-control-plane   Ready    control-plane   61d   v1.37.0-rc.1   172.18.0.2    <none>        Debian GNU/Linux 13 (trixie)   6.6.87.2-microsoft-standard-WSL2 (amd64)   containerd://2.3.4

## Gatekeeper images
openpolicyagent/gatekeeper:v3.24.0-beta.0
openpolicyagent/gatekeeper:v3.24.0-beta.0

## Kyverno
NAME   	NAMESPACE	REVISION	UPDATED                                	STATUS  	CHART        	APP VERSION
kyverno	kyverno  	1       	2026-08-22 07:17:36.141643699 +0000 UTC	deployed	kyverno-3.9.0	v1.19.0    

## Baseline tools
3.3.30
Your current version is: v4.0.12
