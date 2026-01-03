package collector

import (
	"context"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type WorkloadCollector struct {
	include []string
	exclude []string
	results inventory.WorkloadInventory
}

func NewWorkloadCollector(include, exclude []string) *WorkloadCollector {
	return &WorkloadCollector{
		include: include,
		exclude: exclude,
	}
}

func (c *WorkloadCollector) Name() string {
	return "workload"
}

func (c *WorkloadCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		if !shouldIncludeNamespace(pod.Namespace, c.include, c.exclude) {
			continue
		}
		c.results.Pods = append(c.results.Pods, convertPod(&pod))
	}

	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, dep := range deployments.Items {
		if !shouldIncludeNamespace(dep.Namespace, c.include, c.exclude) {
			continue
		}
		c.results.Deployments = append(c.results.Deployments, convertDeployment(&dep))
	}

	daemonsets, err := clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, ds := range daemonsets.Items {
		if !shouldIncludeNamespace(ds.Namespace, c.include, c.exclude) {
			continue
		}
		c.results.DaemonSets = append(c.results.DaemonSets, convertDaemonSet(&ds))
	}

	statefulsets, err := clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, ss := range statefulsets.Items {
		if !shouldIncludeNamespace(ss.Namespace, c.include, c.exclude) {
			continue
		}
		c.results.StatefulSets = append(c.results.StatefulSets, convertStatefulSet(&ss))
	}

	replicasets, err := clientset.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, rs := range replicasets.Items {
		if !shouldIncludeNamespace(rs.Namespace, c.include, c.exclude) {
			continue
		}
		c.results.ReplicaSets = append(c.results.ReplicaSets, convertReplicaSet(&rs))
	}

	jobs, err := clientset.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, job := range jobs.Items {
		if !shouldIncludeNamespace(job.Namespace, c.include, c.exclude) {
			continue
		}
		c.results.Jobs = append(c.results.Jobs, convertJob(&job))
	}

	cronjobs, err := clientset.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, cj := range cronjobs.Items {
		if !shouldIncludeNamespace(cj.Namespace, c.include, c.exclude) {
			continue
		}
		c.results.CronJobs = append(c.results.CronJobs, convertCronJob(&cj))
	}

	return nil
}

func (c *WorkloadCollector) Results() interface{} {
	return c.results
}

func convertPod(pod *corev1.Pod) inventory.PodInfo {
	info := inventory.PodInfo{
		Name:             pod.Name,
		Namespace:        pod.Namespace,
		Labels:           pod.Labels,
		Annotations:      pod.Annotations,
		ServiceAccount:   pod.Spec.ServiceAccountName,
		NodeName:         pod.Spec.NodeName,
		HostNetwork:      pod.Spec.HostNetwork,
		HostPID:          pod.Spec.HostPID,
		HostIPC:          pod.Spec.HostIPC,
		Phase:            string(pod.Status.Phase),
		AutomountSAToken: pod.Spec.AutomountServiceAccountToken,
	}

	if pod.Spec.SecurityContext != nil {
		info.SecurityContext = convertPodSecurityContext(pod.Spec.SecurityContext)
	}

	for _, container := range pod.Spec.Containers {
		info.Containers = append(info.Containers, convertContainer(&container))
	}

	for _, container := range pod.Spec.InitContainers {
		info.InitContainers = append(info.InitContainers, convertContainer(&container))
	}

	for _, volume := range pod.Spec.Volumes {
		info.Volumes = append(info.Volumes, convertVolume(&volume))
	}

	return info
}

func convertPodSecurityContext(sc *corev1.PodSecurityContext) *inventory.PodSecurityContext {
	if sc == nil {
		return nil
	}

	psc := &inventory.PodSecurityContext{
		RunAsUser:          sc.RunAsUser,
		RunAsGroup:         sc.RunAsGroup,
		RunAsNonRoot:       sc.RunAsNonRoot,
		FSGroup:            sc.FSGroup,
		SupplementalGroups: sc.SupplementalGroups,
	}

	if sc.SeccompProfile != nil {
		psc.SeccompProfile = string(sc.SeccompProfile.Type)
	}

	return psc
}

func convertContainer(c *corev1.Container) inventory.ContainerInfo {
	info := inventory.ContainerInfo{
		Name:            c.Name,
		Image:           c.Image,
		ImagePullPolicy: string(c.ImagePullPolicy),
		LivenessProbe:   c.LivenessProbe != nil,
		ReadinessProbe:  c.ReadinessProbe != nil,
		Command:         c.Command,
		Args:            c.Args,
	}

	for _, port := range c.Ports {
		info.Ports = append(info.Ports, inventory.ContainerPort{
			Name:          port.Name,
			ContainerPort: port.ContainerPort,
			Protocol:      string(port.Protocol),
			HostPort:      port.HostPort,
		})
	}

	if c.SecurityContext != nil {
		info.SecurityContext = convertContainerSecurityContext(c.SecurityContext)
	}

	if c.Resources.Requests != nil || c.Resources.Limits != nil {
		info.Resources = inventory.ResourceRequirements{
			Requests: make(map[string]string),
			Limits:   make(map[string]string),
		}
		for k, v := range c.Resources.Requests {
			info.Resources.Requests[string(k)] = v.String()
		}
		for k, v := range c.Resources.Limits {
			info.Resources.Limits[string(k)] = v.String()
		}
	}

	for _, vm := range c.VolumeMounts {
		info.VolumeMounts = append(info.VolumeMounts, inventory.VolumeMount{
			Name:      vm.Name,
			MountPath: vm.MountPath,
			ReadOnly:  vm.ReadOnly,
			SubPath:   vm.SubPath,
		})
	}

	return info
}

func convertContainerSecurityContext(sc *corev1.SecurityContext) *inventory.ContainerSecurityContext {
	if sc == nil {
		return nil
	}

	csc := &inventory.ContainerSecurityContext{
		Privileged:               sc.Privileged,
		RunAsUser:                sc.RunAsUser,
		RunAsGroup:               sc.RunAsGroup,
		RunAsNonRoot:             sc.RunAsNonRoot,
		ReadOnlyRootFilesystem:   sc.ReadOnlyRootFilesystem,
		AllowPrivilegeEscalation: sc.AllowPrivilegeEscalation,
	}

	if sc.Capabilities != nil {
		csc.Capabilities = &inventory.Capabilities{
			Add:  make([]string, len(sc.Capabilities.Add)),
			Drop: make([]string, len(sc.Capabilities.Drop)),
		}
		for i, cap := range sc.Capabilities.Add {
			csc.Capabilities.Add[i] = string(cap)
		}
		for i, cap := range sc.Capabilities.Drop {
			csc.Capabilities.Drop[i] = string(cap)
		}
	}

	if sc.SeccompProfile != nil {
		csc.SeccompProfile = string(sc.SeccompProfile.Type)
	}

	if sc.SELinuxOptions != nil {
		csc.SELinuxOptions = sc.SELinuxOptions.Type
	}

	return csc
}

func convertVolume(v *corev1.Volume) inventory.VolumeInfo {
	info := inventory.VolumeInfo{
		Name: v.Name,
	}

	switch {
	case v.HostPath != nil:
		info.Type = "hostPath"
		info.Source = v.HostPath.Path
	case v.EmptyDir != nil:
		info.Type = "emptyDir"
	case v.Secret != nil:
		info.Type = "secret"
		info.Source = v.Secret.SecretName
	case v.ConfigMap != nil:
		info.Type = "configMap"
		info.Source = v.ConfigMap.Name
	case v.PersistentVolumeClaim != nil:
		info.Type = "persistentVolumeClaim"
		info.Source = v.PersistentVolumeClaim.ClaimName
	case v.Projected != nil:
		info.Type = "projected"
	case v.DownwardAPI != nil:
		info.Type = "downwardAPI"
	default:
		info.Type = "unknown"
	}

	return info
}

func convertDeployment(dep *appsv1.Deployment) inventory.DeploymentInfo {
	info := inventory.DeploymentInfo{
		Name:              dep.Name,
		Namespace:         dep.Namespace,
		Labels:            dep.Labels,
		Replicas:          *dep.Spec.Replicas,
		AvailableReplicas: dep.Status.AvailableReplicas,
		PodTemplate:       convertPodTemplateSpec(&dep.Spec.Template),
	}
	return info
}

func convertPodTemplateSpec(pts *corev1.PodTemplateSpec) inventory.PodTemplateInfo {
	info := inventory.PodTemplateInfo{
		Labels:           pts.Labels,
		ServiceAccount:   pts.Spec.ServiceAccountName,
		HostNetwork:      pts.Spec.HostNetwork,
		HostPID:          pts.Spec.HostPID,
		HostIPC:          pts.Spec.HostIPC,
		AutomountSAToken: pts.Spec.AutomountServiceAccountToken,
	}

	if pts.Spec.SecurityContext != nil {
		info.SecurityContext = convertPodSecurityContext(pts.Spec.SecurityContext)
	}

	for _, c := range pts.Spec.Containers {
		info.Containers = append(info.Containers, convertContainer(&c))
	}

	return info
}

func convertDaemonSet(ds *appsv1.DaemonSet) inventory.DaemonSetInfo {
	return inventory.DaemonSetInfo{
		Name:          ds.Name,
		Namespace:     ds.Namespace,
		Labels:        ds.Labels,
		DesiredNumber: ds.Status.DesiredNumberScheduled,
		CurrentNumber: ds.Status.CurrentNumberScheduled,
		PodTemplate:   convertPodTemplateSpec(&ds.Spec.Template),
	}
}

func convertStatefulSet(ss *appsv1.StatefulSet) inventory.StatefulSetInfo {
	replicas := int32(1)
	if ss.Spec.Replicas != nil {
		replicas = *ss.Spec.Replicas
	}
	return inventory.StatefulSetInfo{
		Name:        ss.Name,
		Namespace:   ss.Namespace,
		Labels:      ss.Labels,
		Replicas:    replicas,
		PodTemplate: convertPodTemplateSpec(&ss.Spec.Template),
	}
}

func convertReplicaSet(rs *appsv1.ReplicaSet) inventory.ReplicaSetInfo {
	replicas := int32(1)
	if rs.Spec.Replicas != nil {
		replicas = *rs.Spec.Replicas
	}
	info := inventory.ReplicaSetInfo{
		Name:      rs.Name,
		Namespace: rs.Namespace,
		Labels:    rs.Labels,
		Replicas:  replicas,
	}
	if len(rs.OwnerReferences) > 0 {
		info.OwnerRef = rs.OwnerReferences[0].Name
	}
	return info
}

func convertJob(job *batchv1.Job) inventory.JobInfo {
	return inventory.JobInfo{
		Name:        job.Name,
		Namespace:   job.Namespace,
		Labels:      job.Labels,
		Completions: job.Spec.Completions,
		PodTemplate: convertPodTemplateSpec(&job.Spec.Template),
	}
}

func convertCronJob(cj *batchv1.CronJob) inventory.CronJobInfo {
	suspend := false
	if cj.Spec.Suspend != nil {
		suspend = *cj.Spec.Suspend
	}
	return inventory.CronJobInfo{
		Name:        cj.Name,
		Namespace:   cj.Namespace,
		Labels:      cj.Labels,
		Schedule:    cj.Spec.Schedule,
		Suspend:     suspend,
		PodTemplate: convertPodTemplateSpec(&cj.Spec.JobTemplate.Spec.Template),
	}
}
