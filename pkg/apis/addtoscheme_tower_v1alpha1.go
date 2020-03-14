package apis

import (
	"kubesphere.io/tower/pkg/apis/tower/v1alpha1"
)

func init() {
	AddToSchemes = append(AddToSchemes, v1alpha1.SchemeBuilder.AddToScheme)
}
