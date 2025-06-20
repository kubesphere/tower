/*
 * Copyright 2025 the KubeSphere Authors.
 * Please refer to the LICENSE file in the root directory of the project.
 * https://github.com/kubesphere/kubesphere/blob/master/LICENSE
 */

package scheme

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	clusterv1alpha1 "kubesphere.io/tower/pkg/api/cluster/v1alpha1"
)

var Scheme = runtime.NewScheme()
var Codecs = serializer.NewCodecFactory(Scheme)
var ParameterCodec = runtime.NewParameterCodec(Scheme)
var localSchemeBuilder = runtime.SchemeBuilder{
	clusterv1alpha1.AddToScheme,
}

var AddToScheme = localSchemeBuilder.AddToScheme

func init() {
	metav1.AddToGroupVersion(Scheme, metav1.SchemeGroupVersion)
	utilruntime.Must(AddToScheme(Scheme))
	utilruntime.Must(k8sscheme.AddToScheme(Scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(Scheme))
}
