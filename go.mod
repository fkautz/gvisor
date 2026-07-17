module gvisor.dev/gvisor

go 1.26.3

replace github.com/docker/docker => github.com/docker/docker v27.5.1+incompatible
replace github.com/opencontainers/runtime-spec => github.com/opencontainers/runtime-spec v1.2.1

require (
	cloud.google.com/go v0.121.6
	cloud.google.com/go/auth v0.18.2
	cloud.google.com/go/auth/oauth2adapt v0.2.8
	cloud.google.com/go/compute/metadata v0.9.0
	cloud.google.com/go/storage v1.56.0
	github.com/BurntSushi/toml v1.4.0
	github.com/bazelbuild/rules_go v0.27.0
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cilium/ebpf v0.17.1
	github.com/containerd/cgroups/v3 v3.1.3
	github.com/containerd/console v1.0.5
	github.com/containerd/containerd/api v1.11.1
	github.com/containerd/containerd/v2 v2.3.3
	github.com/containerd/errdefs v1.0.0
	github.com/containerd/errdefs/pkg v0.3.0
	github.com/containerd/fifo v1.1.0
	github.com/containerd/go-runc v1.1.1-0.20231002172617-c321e8cd5fc4
	github.com/containerd/log v0.1.0
	github.com/containerd/plugin v1.1.0
	github.com/containerd/ttrpc v1.2.8
	github.com/containerd/typeurl/v2 v2.2.3
	github.com/coreos/go-systemd/v22 v22.7.0
	github.com/creack/pty v1.1.24
	github.com/docker/distribution v2.7.1-0.20190205005809-0d3efadf0154+incompatible
	github.com/docker/go-connections v0.5.0
	github.com/go-echarts/go-echarts/v2 v2.2.3
	github.com/godbus/dbus/v5 v5.2.2
	github.com/gofrs/flock v0.13.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.4
	github.com/google/btree v1.1.3
	github.com/google/go-cmp v0.7.0
	github.com/google/go-github/v75 v75.0.0
	github.com/google/gopacket v1.1.19
	github.com/google/pprof v0.0.0-20260604005048-7023385849c0
	github.com/google/subcommands v1.2.0
	github.com/googleapis/gnostic v0.5.5
	github.com/hanwen/go-fuse/v2 v2.10.1
	github.com/hashicorp/go-multierror v1.1.0
	github.com/mattbaird/jsonpatch v0.0.0-20240118010651-0ba75a80ca38
	github.com/moby/moby v28.5.2+incompatible
	github.com/moby/sys/capability v0.4.0
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/opencontainers/runtime-spec v1.3.0
	github.com/prometheus/common v0.67.5
	github.com/sirupsen/logrus v1.9.4
	github.com/vishvananda/netlink v1.3.1
	github.com/xeipuuv/gojsonschema v1.2.0
	go.uber.org/multierr v1.11.0
	go.uber.org/zap v1.28.0
	golang.org/x/exp v0.0.0-20260218203240-3dfff04db8fa
	golang.org/x/mod v0.36.0
	golang.org/x/net v0.55.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.21.0
	golang.org/x/sys v0.46.0
	golang.org/x/term v0.44.0
	golang.org/x/time v0.15.0
	golang.org/x/tools v0.45.0
	google.golang.org/api v0.264.0
	google.golang.org/appengine/v2 v2.0.6
	google.golang.org/grpc v1.83.0-dev.0.20260708112541-2a112a82f5c5
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	honnef.co/go/tools v0.2.1
	k8s.io/apimachinery v0.36.0
	k8s.io/client-go v0.36.0
)

require (
	cel.dev/expr v0.25.2 // indirect
	cloud.google.com/go/iam v1.5.3 // indirect
	cloud.google.com/go/monitoring v1.24.3 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.33.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.53.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.53.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chzyer/readline v1.5.1 // indirect
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.37.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.11 // indirect
	github.com/googleapis/gax-go/v2 v2.17.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20250417193237-f615e6bd150b // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/spiffe/go-spiffe/v2 v2.7.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.44.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.68.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.68.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/sdk v1.44.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.36.0 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/kube-openapi v0.0.0-20260319004828-5883c5ee87b9 // indirect
	k8s.io/utils v0.0.0-20260319190234-28399d86e0b5 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.2 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
