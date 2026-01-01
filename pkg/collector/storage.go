package collector

import (
	"context"
	"fmt"

	"github.com/nelssec/qualys-agentless/pkg/inventory"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type StorageCollector struct {
	include []string
	exclude []string
	results inventory.StorageInventory
}

func NewStorageCollector(include, exclude []string) *StorageCollector {
	return &StorageCollector{
		include: include,
		exclude: exclude,
	}
}

func (c *StorageCollector) Name() string {
	return "storage"
}

func (c *StorageCollector) Collect(ctx context.Context, clientset *kubernetes.Clientset) error {
	pvs, err := clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results.PersistentVolumes = make([]inventory.PersistentVolumeInfo, 0, len(pvs.Items))
	for _, pv := range pvs.Items {
		accessModes := make([]string, 0, len(pv.Spec.AccessModes))
		for _, am := range pv.Spec.AccessModes {
			accessModes = append(accessModes, string(am))
		}

		var claimRef string
		if pv.Spec.ClaimRef != nil {
			claimRef = fmt.Sprintf("%s/%s", pv.Spec.ClaimRef.Namespace, pv.Spec.ClaimRef.Name)
		}

		volumeMode := "Filesystem"
		if pv.Spec.VolumeMode != nil {
			volumeMode = string(*pv.Spec.VolumeMode)
		}

		c.results.PersistentVolumes = append(c.results.PersistentVolumes, inventory.PersistentVolumeInfo{
			Name:          pv.Name,
			Labels:        pv.Labels,
			Capacity:      pv.Spec.Capacity.Storage().String(),
			AccessModes:   accessModes,
			ReclaimPolicy: string(pv.Spec.PersistentVolumeReclaimPolicy),
			StorageClass:  pv.Spec.StorageClassName,
			VolumeMode:    volumeMode,
			Status:        string(pv.Status.Phase),
			ClaimRef:      claimRef,
			VolumeType:    getVolumeType(pv.Spec.PersistentVolumeSource),
			MountOptions:  pv.Spec.MountOptions,
		})
	}

	pvcs, err := clientset.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results.PersistentVolumeClaims = make([]inventory.PersistentVolumeClaimInfo, 0)
	for _, pvc := range pvcs.Items {
		if !shouldIncludeNamespace(pvc.Namespace, c.include, c.exclude) {
			continue
		}

		accessModes := make([]string, 0, len(pvc.Spec.AccessModes))
		for _, am := range pvc.Spec.AccessModes {
			accessModes = append(accessModes, string(am))
		}

		var storageClass string
		if pvc.Spec.StorageClassName != nil {
			storageClass = *pvc.Spec.StorageClassName
		}

		volumeMode := "Filesystem"
		if pvc.Spec.VolumeMode != nil {
			volumeMode = string(*pvc.Spec.VolumeMode)
		}

		var actualStorage string
		if pvc.Status.Capacity != nil {
			actualStorage = pvc.Status.Capacity.Storage().String()
		}

		c.results.PersistentVolumeClaims = append(c.results.PersistentVolumeClaims, inventory.PersistentVolumeClaimInfo{
			Name:             pvc.Name,
			Namespace:        pvc.Namespace,
			Labels:           pvc.Labels,
			StorageClass:     storageClass,
			AccessModes:      accessModes,
			RequestedStorage: pvc.Spec.Resources.Requests.Storage().String(),
			ActualStorage:    actualStorage,
			VolumeMode:       volumeMode,
			VolumeName:       pvc.Spec.VolumeName,
			Status:           string(pvc.Status.Phase),
		})
	}

	scs, err := clientset.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.results.StorageClasses = make([]inventory.StorageClassInfo, 0, len(scs.Items))
	for _, sc := range scs.Items {
		var reclaimPolicy string
		if sc.ReclaimPolicy != nil {
			reclaimPolicy = string(*sc.ReclaimPolicy)
		}

		var volumeBindingMode string
		if sc.VolumeBindingMode != nil {
			volumeBindingMode = string(*sc.VolumeBindingMode)
		}

		isDefault := false
		if sc.Annotations != nil {
			if v, ok := sc.Annotations["storageclass.kubernetes.io/is-default-class"]; ok && v == "true" {
				isDefault = true
			}
		}

		var allowExpansion bool
		if sc.AllowVolumeExpansion != nil {
			allowExpansion = *sc.AllowVolumeExpansion
		}

		c.results.StorageClasses = append(c.results.StorageClasses, inventory.StorageClassInfo{
			Name:                 sc.Name,
			Labels:               sc.Labels,
			Provisioner:          sc.Provisioner,
			ReclaimPolicy:        reclaimPolicy,
			VolumeBindingMode:    volumeBindingMode,
			AllowVolumeExpansion: allowExpansion,
			IsDefault:            isDefault,
			Parameters:           sc.Parameters,
		})
	}

	return nil
}

func (c *StorageCollector) Results() interface{} {
	return c.results
}

func getVolumeType(source corev1.PersistentVolumeSource) string {
	switch {
	case source.AWSElasticBlockStore != nil:
		return "AWSElasticBlockStore"
	case source.GCEPersistentDisk != nil:
		return "GCEPersistentDisk"
	case source.AzureDisk != nil:
		return "AzureDisk"
	case source.AzureFile != nil:
		return "AzureFile"
	case source.NFS != nil:
		return "NFS"
	case source.HostPath != nil:
		return "HostPath"
	case source.Local != nil:
		return "Local"
	case source.CSI != nil:
		return "CSI:" + source.CSI.Driver
	case source.FC != nil:
		return "FC"
	case source.ISCSI != nil:
		return "iSCSI"
	case source.CephFS != nil:
		return "CephFS"
	case source.RBD != nil:
		return "RBD"
	default:
		return "Unknown"
	}
}
