---
categories:
- K8s
date: '2024-08-28 08:37:03+08:00'
description: K8s初认知
isCJKLanguage: true
lastmod: '2025-04-06 14:13:40+08:00'
slug: introduction-to-k8s-basics-2bouut
title: K8s基础介绍
toc: true
url: /post/introduction-to-k8s-basics-2bouut.html
---
# K8s基础介绍

首先来学习一下k8s的相关原理

根据我个人理解简单说一下吧，就是存在一个动态的服务器集群，有一个master节点作为核心控制，其余存在若干个node节点，可以动态地分配资源给当前正在运行的服务。

**master：集群的控制平面，负责集群的决策**

Master 节点上会安装四个重要组件，分别如下：

* **ApiServer** : 资源操作的唯一入口，接收用户输入的命令，提供认证、授权、API注册和发现等机制
* **Scheduler** : 负责集群资源调度，按照预定的调度策略将 Pod 调度到相应的 node 节点上
* **ControllerManager** : 负责维护集群的状态，比如程序部署安排、故障检测、自动扩展、滚动更新等
* **Etcd** ：负责存储集群中各种资源对象的信息，相当于 K8S 的数据库

**node：集群的数据平面，负责为容器提供运行环境**

node 节点上会安装三个重要组件，分别如下：

* **Kubelet** : 负责维护容器的生命周期，即通过控制docker，来创建、更新、销毁容器
* **KubeProxy** : 负责提供集群内部的服务发现和负载均衡
* **Docker** : 负责节点上容器的各种操作

​![1717071368265-c5cc572e-9a59-4401-a063-f886ae852b0f](https://raw.githubusercontent.com/Wh1teJ0ker/PicGo/main/Pic/net-img-1717071368265-c5cc572e-9a59-4401-a063-f886ae852b0f-20240828083736-ytr4d5l.png)​

一些相关概念

**Master**：集群控制节点，每个集群需要至少一个 master 节点负责集群的管控

**Node**：工作负载节点，由 master 分配容器到这些 node 工作节点上，然后 node 节点上的 docker 负责容器的运行

**Pod**：kubernetes 的最小控制单元，容器都是运行在 pod 中的，一个 pod 中可以有 1 个或者多个容器

**Controller**：控制器，通过它来实现对 pod 的管理，比如启动 pod、停止 pod、伸缩 pod 的数量等等

**Service**：pod 对外服务的统一入口，下面可以维护着同一类的多个 pod

**Label**：标签，用于对 pod 进行分类，同一类 pod 会拥有相同的标签

**NameSpace**：命名空间，用来隔离 pod 的运行环境
