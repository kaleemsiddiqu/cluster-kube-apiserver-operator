package e2e

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	e2e "github.com/openshift/cluster-kube-apiserver-operator/test/library"
)

const (
	defaultAgnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.45"
)

var _ = g.Describe("[sig-api-machinery] kube-apiserver operator", func() {
	g.It("[Operator][NetworkPolicy] should enforce NetworkPolicy allow/deny basics in a test namespace", func() {
		testGenericNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce kube-apiserver-operator NetworkPolicies", func() {
		testKubeAPIServerOperatorNetworkPolicyEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should enforce cross-namespace ingress traffic", func() {
		testCrossNamespaceIngressEnforcement()
	})
	g.It("[Operator][NetworkPolicy] should allow metrics but block other ports", func() {
		testMetricsOpenButOtherPortsBlocked()
	})
	g.It("[Operator][NetworkPolicy] should allow metrics ingress from any namespace", func() {
		testMetricsIngressOpenAccess()
	})
})

func testGenericNetworkPolicyEnforcement() {
	kubeConfig, err := e2e.NewClientConfigForTest()
	o.Expect(err).NotTo(o.HaveOccurred())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating a temporary namespace for policy enforcement checks")
	nsName := fmt.Sprintf("np-enforcement-%s", rand.String(5))
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
		},
	}
	_, err = kubeClient.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	defer func() {
		g.GinkgoWriter.Printf("deleting test namespace %s\n", nsName)
		_ = kubeClient.CoreV1().Namespaces().Delete(context.TODO(), nsName, metav1.DeleteOptions{})
	}()

	serverName := "np-server"
	clientLabels := map[string]string{"app": "np-client"}
	serverLabels := map[string]string{"app": "np-server"}

	serverIPs, cleanupServer := createServerPod(kubeClient, nsName, serverName, serverLabels, 8080)
	defer cleanupServer()
	o.Expect(serverIPs).NotTo(o.BeEmpty())

	g.By("Verifying allow-all when no policies select the pod")
	expectConnectivity(kubeClient, nsName, clientLabels, serverIPs, 8080, true)

	g.By("Applying default deny and verifying traffic is blocked")
	g.GinkgoWriter.Printf("creating default-deny policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), defaultDenyPolicy("default-deny", nsName), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	expectConnectivity(kubeClient, nsName, clientLabels, serverIPs, 8080, false)

	g.By("Adding ingress allow only and verifying traffic is still blocked")
	g.GinkgoWriter.Printf("creating allow-ingress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), allowIngressPolicy("allow-ingress", nsName, serverLabels, clientLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	expectConnectivity(kubeClient, nsName, clientLabels, serverIPs, 8080, false)

	g.By("Adding egress allow and verifying traffic is permitted")
	g.GinkgoWriter.Printf("creating allow-egress policy in %s\n", nsName)
	_, err = kubeClient.NetworkingV1().NetworkPolicies(nsName).Create(context.TODO(), allowEgressPolicy("allow-egress", nsName, clientLabels, serverLabels, 8080), metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred())
	expectConnectivity(kubeClient, nsName, clientLabels, serverIPs, 8080, true)
}

func testKubeAPIServerOperatorNetworkPolicyEnforcement() {
	kubeConfig, err := e2e.NewClientConfigForTest()
	o.Expect(err).NotTo(o.HaveOccurred())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	namespace := "openshift-kube-apiserver-operator"
	serverLabels := map[string]string{"app": "kube-apiserver-operator"}

	g.By("Creating kube-apiserver-operator test pod for policy checks")
	serverIPs, cleanupServer := createServerPod(kubeClient, namespace, "np-kas-op-server", serverLabels, 8443)
	defer cleanupServer()

	g.By("Verifying cross-namespace traffic from monitoring is allowed")
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 8443, true)

	g.By("Verifying unauthorized ports are denied")
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, serverIPs, 12345, false)

	g.By("Verifying within-namespace traffic to metrics port is allowed")
	expectConnectivity(kubeClient, namespace, map[string]string{"app": "kube-apiserver-operator"}, serverIPs, 8443, true)
}

func testCrossNamespaceIngressEnforcement() {
	kubeConfig, err := e2e.NewClientConfigForTest()
	o.Expect(err).NotTo(o.HaveOccurred())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pods in kube-apiserver-operator namespace")
	kasOperatorIPs, cleanupKASOperator := createServerPod(kubeClient, "openshift-kube-apiserver-operator", "np-kas-op-xns", map[string]string{"app": "kube-apiserver-operator"}, 8443)
	defer cleanupKASOperator()

	g.By("Testing cross-namespace ingress: monitoring -> kube-apiserver-operator:8443")
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, kasOperatorIPs, 8443, true)

	g.By("Testing cross-namespace ingress: any pod from monitoring can access metrics")
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app": "any-label"}, kasOperatorIPs, 8443, true)
}

func testMetricsOpenButOtherPortsBlocked() {
	kubeConfig, err := e2e.NewClientConfigForTest()
	o.Expect(err).NotTo(o.HaveOccurred())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pod in kube-apiserver-operator namespace")
	kasOperatorIPs, cleanupKASOperator := createServerPod(kubeClient, "openshift-kube-apiserver-operator", "np-kas-op-unauth", map[string]string{"app": "kube-apiserver-operator"}, 8443)
	defer cleanupKASOperator()

	g.By("Testing metrics port 8443 is now open: default namespace -> kube-apiserver-operator:8443")
	expectConnectivity(kubeClient, "default", map[string]string{"test": "client"}, kasOperatorIPs, 8443, true)

	g.By("Testing metrics port 8443 from openshift-etcd with custom app label: should be denied")
	expectConnectivity(kubeClient, "openshift-etcd", map[string]string{"test": "client"}, kasOperatorIPs, 8443, false)

	g.By("Testing port-based blocking: unauthorized ports are still blocked")
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, kasOperatorIPs, 9999, false)

	g.By("Testing multiple unauthorized ports are still blocked by default-deny")
	for _, port := range []int32{80, 443, 8080, 22, 3306, 9090} {
		expectConnectivity(kubeClient, "default", map[string]string{"test": "any-pod"}, kasOperatorIPs, port, false)
	}
}

func testMetricsIngressOpenAccess() {
	kubeConfig, err := e2e.NewClientConfigForTest()
	o.Expect(err).NotTo(o.HaveOccurred())
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	o.Expect(err).NotTo(o.HaveOccurred())

	g.By("Creating test server pod in kube-apiserver-operator namespace with operator labels")
	kasOperatorIPs, cleanupKASOperator := createServerPod(kubeClient, "openshift-kube-apiserver-operator", "np-metrics-test", map[string]string{"app": "kube-apiserver-operator"}, 8443)
	defer cleanupKASOperator()

	g.By("Testing allow-to-metrics policy: monitoring namespace can access metrics -> operator:8443")
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, kasOperatorIPs, 8443, true)

	g.By("Testing metrics policy: etcd namespace with custom app label should be denied")
	expectConnectivity(kubeClient, "openshift-etcd", map[string]string{"test": "metrics-client"}, kasOperatorIPs, 8443, false)

	g.By("Testing metrics policy: console namespace with custom app label can access metrics")
	expectConnectivity(kubeClient, "openshift-console", map[string]string{"custom-app": "test-client"}, kasOperatorIPs, 8443, true)

	g.By("Testing allow-to-metrics policy: default namespace can access metrics -> operator:8443")
	expectConnectivity(kubeClient, "default", map[string]string{"test": "client"}, kasOperatorIPs, 8443, true)

	g.By("Testing allow-to-metrics policy: same namespace can access metrics -> operator:8443")
	expectConnectivity(kubeClient, "openshift-kube-apiserver-operator", map[string]string{"app": "kube-apiserver-operator"}, kasOperatorIPs, 8443, true)

	g.By("Testing default-deny still blocks unauthorized ports")
	expectConnectivity(kubeClient, "openshift-monitoring", map[string]string{"app.kubernetes.io/name": "prometheus"}, kasOperatorIPs, 9090, false)
}

// Helper functions (previously from library-go)

// createServerPod creates an agnhost netexec server pod, waits for it to be ready,
// and returns all its IPs along with a cleanup function.
func createServerPod(kubeClient kubernetes.Interface, namespace, name string, labels map[string]string, port int32) ([]string, func()) {
	g.GinkgoHelper()
	g.GinkgoWriter.Printf("creating server pod %s/%s port=%d labels=%v\n", namespace, name, port, labels)

	pod := netexecPod(name, namespace, labels, port)
	_, err := kubeClient.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to create server pod %s/%s", namespace, name)

	err = waitForPodReady(kubeClient, namespace, name)
	o.Expect(err).NotTo(o.HaveOccurred(), "server pod %s/%s never became ready", namespace, name)

	created, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	o.Expect(err).NotTo(o.HaveOccurred(), "failed to get server pod %s/%s", namespace, name)

	ips := podIPs(created)
	o.Expect(ips).NotTo(o.BeEmpty(), "server pod %s/%s has no IPs", namespace, name)
	g.GinkgoWriter.Printf("server pod %s/%s ips=%v\n", namespace, name, ips)

	return ips, func() {
		g.GinkgoWriter.Printf("deleting server pod %s/%s\n", namespace, name)
		_ = kubeClient.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	}
}

// netexecPod returns a Pod object running agnhost netexec on the given port.
func netexecPod(name, namespace string, labels map[string]string, port int32) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   boolPtr(true),
				RunAsUser:      int64Ptr(1001),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{
				{
					Name:  "netexec",
					Image: defaultAgnhostImage,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolPtr(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						RunAsNonRoot:             boolPtr(true),
						RunAsUser:                int64Ptr(1001),
					},
					Command: []string{"/agnhost"},
					Args:    []string{"netexec", fmt.Sprintf("--http-port=%d", port)},
					Ports: []corev1.ContainerPort{
						{ContainerPort: port},
					},
				},
			},
		},
	}
}

// podIPs returns all IP addresses assigned to a pod (dual-stack aware).
func podIPs(pod *corev1.Pod) []string {
	var ips []string
	for _, podIP := range pod.Status.PodIPs {
		if podIP.IP != "" {
			ips = append(ips, podIP.IP)
		}
	}
	if len(ips) == 0 && pod.Status.PodIP != "" {
		ips = append(ips, pod.Status.PodIP)
	}
	return ips
}

// waitForPodReady waits up to 2 minutes for a pod to reach the Running phase with a Ready condition.
func waitForPodReady(kubeClient kubernetes.Interface, namespace, name string) error {
	return wait.PollImmediate(2*time.Second, 2*time.Minute, func() (bool, error) {
		pod, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if pod.Status.Phase != corev1.PodRunning {
			return false, nil
		}
		return isPodReady(pod), nil
	})
}

// waitForPodCompletion waits up to 2 minutes for a pod to reach Succeeded or Failed phase.
func waitForPodCompletion(kubeClient kubernetes.Interface, namespace, name string) error {
	return wait.PollImmediate(2*time.Second, 2*time.Minute, func() (bool, error) {
		pod, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed, nil
	})
}

// expectConnectivity checks connectivity from a pod in the given namespace (with clientLabels)
// to each serverIP on the specified port. The check is retried for up to 2 minutes per IP.
func expectConnectivity(kubeClient kubernetes.Interface, namespace string, clientLabels map[string]string, serverIPs []string, port int32, shouldSucceed bool) {
	g.GinkgoHelper()
	for _, ip := range serverIPs {
		family := "IPv4"
		if isIPv6(ip) {
			family = "IPv6"
		}
		g.GinkgoWriter.Printf("checking %s connectivity %s -> %s expected=%t\n", family, namespace, formatIPPort(ip, port), shouldSucceed)
		err := pollConnectivity(kubeClient, namespace, clientLabels, ip, port, shouldSucceed, 2*time.Minute)
		o.Expect(err).NotTo(o.HaveOccurred(), "connectivity check failed for %s %s -> %s (expected %t)", family, namespace, formatIPPort(ip, port), shouldSucceed)
	}
}

// pollConnectivity polls connectivity until it matches the expected result or times out.
func pollConnectivity(kubeClient kubernetes.Interface, namespace string, clientLabels map[string]string, serverIP string, port int32, shouldSucceed bool, timeout time.Duration) error {
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		succeeded, err := runConnectivityCheck(kubeClient, namespace, clientLabels, serverIP, port)
		if err != nil {
			return false, err
		}
		return succeeded == shouldSucceed, nil
	})
}

// runConnectivityCheck creates an ephemeral agnhost connect pod and attempts a TCP connection.
func runConnectivityCheck(kubeClient kubernetes.Interface, namespace string, labels map[string]string, serverIP string, port int32) (bool, error) {
	name := fmt.Sprintf("np-client-%s", rand.String(5))

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   boolPtr(true),
				RunAsUser:      int64Ptr(1001),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{
				{
					Name:  "connect",
					Image: defaultAgnhostImage,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: boolPtr(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						RunAsNonRoot:             boolPtr(true),
						RunAsUser:                int64Ptr(1001),
					},
					Command: []string{"/agnhost"},
					Args: []string{
						"connect",
						"--protocol=tcp",
						"--timeout=5s",
						formatIPPort(serverIP, port),
					},
				},
			},
		},
	}

	_, err := kubeClient.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	defer func() {
		_ = kubeClient.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	}()

	if err := waitForPodCompletion(kubeClient, namespace, name); err != nil {
		return false, err
	}
	completed, err := kubeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if len(completed.Status.ContainerStatuses) == 0 {
		return false, fmt.Errorf("no container status recorded for pod %s", name)
	}
	exitCode := completed.Status.ContainerStatuses[0].State.Terminated.ExitCode
	return exitCode == 0, nil
}

// NetworkPolicy construction helpers

func defaultDenyPolicy(name, namespace string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		},
	}
}

func allowIngressPolicy(name, namespace string, podLabels, fromLabels map[string]string, port int32) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabels},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: fromLabels}},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: port}, Protocol: protocolPtr(corev1.ProtocolTCP)},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
}

func allowEgressPolicy(name, namespace string, podLabels, toLabels map[string]string, port int32) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabels},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: toLabels}},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: port}, Protocol: protocolPtr(corev1.ProtocolTCP)},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
}

// Utility helpers

func isIPv6(ip string) bool {
	return net.ParseIP(ip) != nil && strings.Contains(ip, ":")
}

func formatIPPort(ip string, port int32) string {
	if isIPv6(ip) {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func boolPtr(value bool) *bool {
	return &value
}

func int64Ptr(value int64) *int64 {
	return &value
}

func protocolPtr(protocol corev1.Protocol) *corev1.Protocol {
	return &protocol
}
