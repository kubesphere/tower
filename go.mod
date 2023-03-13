module kubesphere.io/tower

go 1.19

require (
	github.com/gorilla/websocket v1.5.0
	github.com/jpillora/backoff v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.6.1
	github.com/spf13/pflag v1.0.5
	golang.org/x/crypto v0.7.0
	k8s.io/api v0.26.2
	k8s.io/apimachinery v0.26.2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog/v2 v2.90.1
	kubesphere.io/api v0.0.0
	kubesphere.io/kubesphere v0.0.0-20230309025545-f9fe06434ca2
	sigs.k8s.io/controller-runtime v0.14.5
)

replace (
	// GoLand is not working without those
	github.com/projectcalico/api => github.com/kubesphere/calico/api v0.0.0-20230227071013-a73515ddc939 // v3.25.0
	github.com/projectcalico/calico => github.com/kubesphere/calico v0.0.0-20230227071013-a73515ddc939 // v3.25.0
	k8s.io/client-go => k8s.io/client-go v0.26.2
	kubesphere.io/api => kubesphere.io/api v0.0.0-20230118032859-ae333904cc74
	kubesphere.io/client-go => kubesphere.io/client-go v0.3.2-0.20230113095751-07c603a4af6a
	sigs.k8s.io/kubefed => github.com/kubesphere/kubefed v0.0.0-20230207032540-cdda80892665
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/edsrzf/mmap-go v1.1.0 // indirect
	github.com/emicklei/go-restful/v3 v3.10.1 // indirect
	github.com/evanphx/json-patch v5.6.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-kit/kit v0.10.0 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/gnostic v0.6.9 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/projectcalico/libcalico-go v1.7.2-0.20191014160346-2382c6cdd056 // indirect
	github.com/prometheus/client_golang v1.14.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.39.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/prometheus/prometheus v1.8.2-0.20200907175821-8219b442c864 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/uber/jaeger-client-go v2.25.0+incompatible // indirect
	github.com/uber/jaeger-lib v2.2.0+incompatible // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/goleak v1.2.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/oauth2 v0.4.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/term v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	gomodules.xyz/jsonpatch/v2 v2.2.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	istio.io/api v0.0.0-20201113182140-d4b7e3fc2b44 // indirect
	istio.io/gogo-genproto v0.0.0-20201113182723-5b8563d8a012 // indirect
	k8s.io/apiextensions-apiserver v0.26.1 // indirect
	k8s.io/component-base v0.26.1 // indirect
	k8s.io/kube-openapi v0.0.0-20230224204730-66828de6f33b // indirect
	k8s.io/utils v0.0.0-20230202215443-34013725500c // indirect
	sigs.k8s.io/application v0.8.4-0.20201016185654-c8e2959e57a0 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
