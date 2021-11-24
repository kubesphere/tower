module kubesphere.io/tower

go 1.12

require (
	github.com/gorilla/websocket v1.4.0
	github.com/jpillora/backoff v1.0.0
	github.com/pkg/errors v0.8.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975
	golang.org/x/sys v0.0.0-20200302150141-5c8b2ff67527 // indirect
	k8s.io/api v0.18.6
	k8s.io/apimachinery v0.18.6
	k8s.io/client-go v0.18.6
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.4.0
)
