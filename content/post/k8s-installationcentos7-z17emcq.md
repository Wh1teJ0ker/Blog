---
title: K8s安装-Centos7
slug: k8s-installationcentos7-z17emcq
url: /post/k8s-installationcentos7-z17emcq.html
date: '2024-08-28 08:36:16+08:00'
lastmod: '2025-04-06 14:16:35+08:00'
toc: true
categories:
  - K8s
isCJKLanguage: true
---

# K8s安装-Centos7

# 环境与配置文件

**K8S_master**

* 1处理器4核
* 4G内存
* 40G硬盘

**K8S_node1**

**K8S_node2**

# Vmware虚拟机设置安装

## Centos7安装

使用镜像如下：CentOS-7-x86\_64-Minimal-2009.iso

首先先完成虚拟机的安装，基本是默认设置即可

唯一注意需要添加root账户的密码！

​![](https://cdn.nlark.com/yuque/0/2024/png/42600779/1717074028087-41e79e38-097f-4885-a26a-80b32eedd407.png)​

## 配置网络

```plain
$ vi /etc/sysconfig/network
# 添加下面的配置
NETWORKING=yes
HOSTNAME=master
```

```plain
$ vi /etc/sysconfig/network-scripts/ifcfg-ens33
# 配置如下

TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
-BOOTPROTO=dchp
+BOOTPROTO=static
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=stable-privacy
-UUID=XXXX-XXXX-XXXX
-ONBOOT=no
+ONBOOT=yes
IPADDR=192.168.188.180  
NETMASK=255.255.255.0
GATEWAY=192.168.188.2   
NAME=ens33
DEVICE=ens33
#DNS1采用本地网关，DNS2使用公共DNS
DNS1=192.168.188.2  
DNS2=114.114.114.114
```

配置hosts

```plain
$ vi /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
#根据上述查看的NAT分配IP进行调整
192.168.188.180 master
192.168.188.181 node1
192.168.188.182 node2
```

完成上述后，进行reboot并且进行ping确认是否能够联网

[CentOS7安装VMware Tools_yun安装vmtools-CSDN博客](https://blog.csdn.net/zhujing16/article/details/88677253)

00:0c:29:84:5a:b4

## 系统配置

**关闭防火墙**

```plain
$ service iptables stop
$ systemctl disable iptables
```

若无，则会报错

```plain
  [root@master ~]# service iptables stop
  Redirecting to /bin/systemctl stop iptables.service
  Failed to stop iptables.service: Unit iptables.service not loaded.
  [root@master ~]# systemctl disable iptables
  Failed to execute operation: No such file or directory
```

**禁用selinux**

```plain
# 查看selinux
$ getenforce
Enforcing

# 关闭
$ vi /etc/selinux/config
# 修改为：disabled
SELINUX=disabled
```

**禁用防火墙**

```plain
systemctl stop firewalld
systemctl disable firewalld
```

## SSH登录配置

```plain
$ vi /etc/ssh/sshd_config
# 修改
UseDNS no
PermitRootLogin yes #允许root登录
PermitEmptyPasswords no #不允许空密码登录
PasswordAuthentication yes # 设置是否使用口令验证
```

440

## 4关闭Swap空间

```plain
[root@master ~]# swapoff -a
[root@master ~]# sed -ie '/swap/ s/^/# /' /etc/fstab 
[root@master ~]# free -m
              total        used        free      shared  buff/cache   available
Mem:           3770        1265        1304          12        1200        2267
Swap:             0           0           0
```

## 配置桥接流量

```plain
[root@k8s-master1 ~]# cat > /etc/sysctl.d/k8s.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
```

## 配置yum源

```plain
# 配置阿里云源
# 备份
mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup
# 配置
curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo
wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
# 生成缓存
yum makecache

# 安装epel库
yum -y install epel-release
yum -y update
```

## 基本软件配置

```plain
yum install -y wget
yum install -y htop vim net-tools wget
```

### 时间同步ntp

```plain
yum install ntp
```

配置ntp：

```plain
# 开启服务
service ntpd start

# 开机启动
systemctl enable ntpd
```

### Docker

```plain
yum install -y yum-utils device-mapper-persistent-data lvm2
yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
sed -i 's+download.docker.com+mirrors.aliyun.com/docker-ce+' /etc/yum.repos.d/docker-ce.repo
# 更新源
yum makecache fast
#查看所有版本
yum list docker-ce --showduplicates | sort -r
#安装指定版本
yum -y install docker-ce-19.03.9
yum install -y docker-ce-19.03.9 docker-ce-cli-19.03.9 containerd.io
#设置开机自启动
systemctl enable docker && systemctl start docker
#配置镜像源
cat > /etc/docker/daemon.json << EOF
{
  "exec-opts": [“native.cgroupdriver=systemd”],
  "registry-mirrors" : [
    "http://hub-mirror.c.163.com",
    "http://registry.docker-cn.com",
    "http://docker.mirrors.ustc.edu.cn"
  ]
}
EOF
vi /etc/docker/daemon.json
#重启docker
systemctl restart docker
docker info | grep 'Server Version'
```

### 安装kubeadm/kubelet和kubectl

安装需要注意两问题，一个是安装的版本要统一，一个是安装的版本不要太新

```plain
cat  > /etc/yum.repos.d/kubernetes.repo <<EOF
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF
```

```plain
yum install kubeadm-1.20.2 -y
yum install -y kubelet-1.20.4 kubectl-1.20.4 kubeadm-1.20.4
systemctl enable kubelet
kubectl version
kubeadm version
kubelet version
```

## 快照克隆

在master机器保持静止的状态下使用克隆功能，进行复制，创建node1和node2

## 修改克隆机及测试

```plain
$ vi /etc/sysconfig/network
NETWORKING=yes
HOSTNAME=master
HOSTNAME=node1
HOSTNAME=node2

$ vi /etc/sysconfig/network-scripts/ifcfg-ens33
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=static
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=stable-privacy
- IPADDR=192.168.188.180
+ IPADDR=192.168.188.181
NETMASK=255.255.255.0
GATEWAY=192.168.188.2
NAME=ens33
DEVICE=ens33
ONBOOT=yes
DNS1=192.168.188.2
DNS2=114.114.114.114
```

使用ping分别对node1和ndoe2进行测试

# 创建Kubernetes集群

## 初始化master

```plain
[root@master ~]# kubeadm init \
  --apiserver-advertise-address=192.168.188.180 \
  --image-repository registry.aliyuncs.com/google_containers \
  --kubernetes-version v1.28.2 \
  --service-cidr=10.96.0.0/12 \
  --pod-network-cidr=10.244.0.0/16 \
  --ignore-preflight-errors=all
  sudo kubeadm init --apiserver-advertise-address=192.168.188.180 --image-repository registry.aliyuncs.com/google_containers --pod-network-cidr=10.244.0.0/16 --service-cidr=10.96.0.0/12 --kubernetes-version=v1.20.4  --ignore-preflight-errors=all
```

配置文件同上

```plain
  $ vi kubeadm.conf
  apiVersion: kubeadm.k8s.io/v1beta2
  kind: ClusterConfiguration
  kubernetesVersion: v1.28.2
  imageRepository: registry.aliyuncs.com/google_containers 
  networking:
    podSubnet: 10.244.0.0/16 
    serviceSubnet: 10.96.0.0/12 

  $ kubeadm init --config kubeadm.conf --ignore-preflight-errors=all
```

**问题**

```plain
vim /etc/systemd/system/kubelet.service.d/10-kubeadm.conf

[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
# This is a file that the user can use for overrides of the kubelet args as a last resort. 
EnvironmentFile=-/etc/default/kubelet
ExecStart=
ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
```

## 拷贝认证文件

```plain
# 拷贝kubectl使用的连接k8s认证文件到默认路径
mkdir -p $HOME/.kube
cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
chown $(id -u):$(id -g) $HOME/.kube/config
```

## 安装Calico

这里又卡了好一会儿，是需要又对应的k8s和calico的版本要求

```plain
curl https://docs.projectcalico.org/v3.20/manifests/calico.yaml -O
```

```plain
kubectl apply -f calico.yaml
```

**检测**

```plain
kubectl get pods -n kube-system
kubectl get nodes
```

**创建鉴权token**

```plain
kubeadm token create --print-join-command
kubeadm join 192.168.188.180:6443 --token w928sh.9zjwu8hlfy12y3x6     --discovery-token-ca-cert-hash sha256:da708b8f6be1ed027ecc3910e3d13174fe8f608c3460d84c929fece921ed0597
```

如果出现服务未启动，先尝试重启再去查找问题，可能是镜像不适配

# 部署WebUI（Dashboard）

## 下载部署

```plain
wget https://raw.githubusercontent.com/kubernetes/dashboard/v2.1.0/aio/deploy/recommended.yaml -O dashboard.yaml
wget https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml -O dashboard.yaml
```

```plain
vi dashboard.yaml

kind: Service
apiVersion: v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
+ type: NodePort
  ports:
    - port: 443
      targetPort: 8443
+     nodePort: 30001
  selector:
    k8s-app: kubernetes-dashboard
```

配置文件应用即可

```plain
kubectl apply -f recommended.yaml
```

确认服务启用后running以及是否TYPE修改成功

```plain
kubectl get pods -n kubernetes-dashboard
kubectl get svc -n kubernetes-dashboard
kubectl get all -n kubernetes-dashboard
```

## 证书修改（方法存疑）（保留）

### 删除默认的secret

```plain
kubectl delete secret -n kubernetes-dashboard kubernetes-dashboard-certs
```

### 签发证书

```plain
mkdir keys & cd keys
openssl genrsa -out tls.key 2048
openssl req -new -out tls.csr -key tls.key -subj '/CN=192.168.188.180'
openssl x509 -req -in tls.csr -signkey tls.key -out tls.crt
ls
>tls.crt tls.csr tls.key
```

### 创建启用secret

```plain
cd keys # 如果本身就在keys文件夹下，则可以省略该步骤
kubectl create secret generic kubernetes-dashboard-certs --from-file=./ -n kubernetes-dashboard
kubectl edit deploy kubernetes-dashboard -n kubernetes-dashboard
```

### 创建用户角色

```plain
kubectl create serviceaccount dashboard-admin -n kube-system
kubectl create clusterrolebinding dashboard-admin --clusterrole=cluster-admin --serviceaccount=kube-system:dashboard-admin
kubectl describe secrets -n kube-system $(kubectl -n kube-system get secret | awk '/dashboard-admin/{print $1}')
```

```plain
#用户信息
Name:         dashboard-admin-token-2pnkj
Namespace:    kube-system
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: dashboard-admin
              kubernetes.io/service-account.uid: c872295c-3483-4558-a96e-6161cf9f84cb

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1066 bytes
namespace:  11 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6Im5GbG83eUp0TThGeDNySHBUZ2pqSVE3UFg2empBYm1rbnFvVkVaYV8tVUEifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJkYXNoYm9hcmQtYWRtaW4tdG9rZW4tMnBua2oiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGFzaGJvYXJkLWFkbWluIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiYzg3MjI5NWMtMzQ4My00NTU4LWE5NmUtNjE2MWNmOWY4NGNiIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omt1YmUtc3lzdGVtOmRhc2hib2FyZC1hZG1pbiJ9.WbaC6TYCnUvfg-N3EbZ6Um-jl78tU_KRLorYUtGG7_ZSR7of_z6cJTDjd4U87OKeNlmNRqEXQkEEx3JZMMiEB6UzCF7QrLN0hOhtKtlarL-xd3HVwuiK_9m8GYtKtvB7wMvrmX4VUNeib11QhMiNDbvYdZc6JdqsEiqdP5bq3_iVsrWFFj5g6B5Z-ZvhdeHRE9Yy9KNBXdItqjLCot5Azv7GXn58WP6E8sZ3zM52J5J5dE8fcArHTptY6kxn0L7qHnzUd2pzqiTWVNBAtGYw-FH42feMFG0dMPsI4o0QqVswxQlp0dZ5YQlmfFn5J1EPEo__-LFbA5sipHk_dKKmow
```

至此，k8s已经安装成功，中途大大小小的坑点真多，emmm

# 安装metrics-server

又碰到了一个小问题，这里主要是解决的无法查看cpu和内存的运行情况

需要安装一个新东西

修改相关yaml内容

1. args增加参数：- –kubelet-insecure-tls   #表示不验证客户端证书
2. image改为阿里镜像：registry.cn-hangzhou.aliyuncs.com/google\_containers/metrics-server:v0.6.4

```plain
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    k8s-app: metrics-server
    rbac.authorization.k8s.io/aggregate-to-admin: "true"
    rbac.authorization.k8s.io/aggregate-to-edit: "true"
    rbac.authorization.k8s.io/aggregate-to-view: "true"
  name: system:aggregated-metrics-reader
rules:
- apiGroups:
  - metrics.k8s.io
  resources:
  - pods
  - nodes
  verbs:
  - get
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    k8s-app: metrics-server
  name: system:metrics-server
rules:
- apiGroups:
  - ""
  resources:
  - nodes/metrics
  verbs:
  - get
- apiGroups:
  - ""
  resources:
  - pods
  - nodes
  verbs:
  - get
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server-auth-reader
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: extension-apiserver-authentication-reader
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server:system:auth-delegator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  labels:
    k8s-app: metrics-server
  name: system:metrics-server
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:metrics-server
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
---
apiVersion: v1
kind: Service
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server
  namespace: kube-system
spec:
  ports:
  - name: https
    port: 443
    protocol: TCP
    targetPort: https
  selector:
    k8s-app: metrics-server
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    k8s-app: metrics-server
  name: metrics-server
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: metrics-server
  strategy:
    rollingUpdate:
      maxUnavailable: 0
  template:
    metadata:
      labels:
        k8s-app: metrics-server
    spec:
      containers:
      - args:
        - --cert-dir=/tmp
        - --secure-port=4443
        - --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname
        - --kubelet-use-node-status-port
        - --metric-resolution=15s
        - --kubelet-insecure-tls   #表示不验证客户端证书
        image: registry.cn-hangzhou.aliyuncs.com/google_containers/metrics-server:v0.6.4  #使用阿里镜像
        imagePullPolicy: IfNotPresent
        livenessProbe:
          failureThreshold: 3
          httpGet:
            path: /livez
            port: https
            scheme: HTTPS
          periodSeconds: 10
        name: metrics-server
        ports:
        - containerPort: 4443
          name: https
          protocol: TCP
        readinessProbe:
          failureThreshold: 3
          httpGet:
            path: /readyz
            port: https
            scheme: HTTPS
          initialDelaySeconds: 20
          periodSeconds: 10
        resources:
          requests:
            cpu: 100m
            memory: 200Mi
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
        volumeMounts:
        - mountPath: /tmp
          name: tmp-dir
      nodeSelector:
        kubernetes.io/os: linux
      priorityClassName: system-cluster-critical
      serviceAccountName: metrics-server
      volumes:
      - emptyDir: {}
        name: tmp-dir
---
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  labels:
    k8s-app: metrics-server
  name: v1beta1.metrics.k8s.io
spec:
  group: metrics.k8s.io
  groupPriorityMinimum: 100
  insecureSkipTLSVerify: true
  service:
    name: metrics-server
    namespace: kube-system
  version: v1beta1
  versionPriority: 100
```

```plain
kubectl apply -f components.yaml
```

进行部署

另外还有一个dashboard可能会有点问题

```plain
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:metrics-server
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - nodes
  - nodes/stats
  - namespaces
  - configmaps
  - nodes/stats # 添加
  - pods/stats # 添加
  verbs:
  - get
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:metrics-server
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:metrics-server
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
```

# 参考文档

[在VMWare中部署你的K8S集群](https://jasonkayzk.github.io/2021/05/16/%E5%9C%A8VMWare%E4%B8%AD%E9%83%A8%E7%BD%B2%E4%BD%A0%E7%9A%84K8S%E9%9B%86%E7%BE%A4/)

[使用Kuboard快速部署Kubernetes集群](https://jasonkayzk.github.io/2023/12/14/%E4%BD%BF%E7%94%A8Kuboard%E5%BF%AB%E9%80%9F%E9%83%A8%E7%BD%B2Kubernetes%E9%9B%86%E7%BE%A4/)

[K8s dashboard 安装过程(Chrome无法打开)](https://www.jianshu.com/p/9b34807cb6d4)
