# This should match the schema defined in external_deps.bzl.
REPOSITORY_LOCATIONS_SPEC = dict(
    bazel_skylib = dict(
        project_name = "bazel-skylib",
        project_desc = "Common useful functions and rules for Bazel",
        project_url = "https://github.com/bazelbuild/bazel-skylib",
        version = "1.7.1",
        sha256 = "bc283cdfcd526a52c3201279cda4bc298652efa898b10b4db0837dc51652756f",
        release_date = "2024-06-03",
        urls = ["https://github.com/bazelbuild/bazel-skylib/releases/download/{version}/bazel-skylib-{version}.tar.gz"],
        use_category = ["api"],
        license = "Apache-2.0",
        license_url = "https://github.com/bazelbuild/bazel-skylib/blob/{version}/LICENSE",
    ),
    com_envoyproxy_protoc_gen_validate = dict(
        project_name = "protoc-gen-validate (PGV)",
        project_desc = "protoc plugin to generate polyglot message validators",
        project_url = "https://github.com/bufbuild/protoc-gen-validate",
        use_category = ["api"],
        sha256 = "9372f9ecde8fbadf83c8c7de3dbb49b11067aa26fb608c501106d0b4bf06c28f",
        version = "1.0.4",
        urls = ["https://github.com/bufbuild/protoc-gen-validate/archive/refs/tags/v{version}.zip"],
        strip_prefix = "protoc-gen-validate-{version}",
        release_date = "2024-01-17",
        implied_untracked_deps = [
            "com_github_iancoleman_strcase",
            "com_github_lyft_protoc_gen_star_v2",
            "com_github_spf13_afero",
            "org_golang_google_genproto",
            "org_golang_x_text",
            "org_golang_x_mod",
            "org_golang_x_sys",
        ],
        license = "Apache-2.0",
        license_url = "https://github.com/bufbuild/protoc-gen-validate/blob/v{version}/LICENSE",
    ),
    rules_jvm_external = dict(
        project_name = "Java Rules for Bazel",
        project_desc = "Bazel rules for Java",
        project_url = "https://github.com/bazelbuild/rules_jvm_external",
        version = "6.6",
        strip_prefix = "rules_jvm_external-{version}",
        sha256 = "3afe5195069bd379373528899c03a3072f568d33bd96fe037bd43b1f590535e7",
        urls = ["https://github.com/bazelbuild/rules_jvm_external/releases/download/{version}/rules_jvm_external-{version}.tar.gz"],
        release_date = "2024-11-25",
        use_category = ["build"],
        license = "Apache-2.0",
        license_url = "https://github.com/bazelbuild/rules_jvm_external/blob/{version}/LICENSE",
    ),
    com_github_cncf_xds = dict(
        project_name = "xDS API",
        project_desc = "xDS API Working Group (xDS-WG)",
        project_url = "https://github.com/cncf/xds",
        # During the UDPA -> xDS migration, we aren't working with releases.
        version = "b4127c9b8d78b77423fd25169f05b7476b6ea932",
        sha256 = "aa5f1596bbef3f277dcf4700e4c1097b34301ae66f3b79cd731e3adfbaff2f8f",
        release_date = "2024-09-05",
        strip_prefix = "xds-{version}",
        urls = ["https://github.com/cncf/xds/archive/{version}.tar.gz"],
        use_category = ["api"],
        license = "Apache-2.0",
        license_url = "https://github.com/cncf/xds/blob/{version}/LICENSE",
    ),
    com_github_openzipkin_zipkinapi = dict(
        project_name = "Zipkin API",
        project_desc = "Zipkin's language independent model and HTTP Api Definitions",
        project_url = "https://github.com/openzipkin/zipkin-api",
        version = "1.0.0",
        sha256 = "6c8ee2014cf0746ba452e5f2c01f038df60e85eb2d910b226f9aa27ddc0e44cf",
        release_date = "2020-11-22",
        strip_prefix = "zipkin-api-{version}",
        urls = ["https://github.com/openzipkin/zipkin-api/archive/{version}.tar.gz"],
        use_category = ["api"],
        license = "Apache-2.0",
        license_url = "https://github.com/openzipkin/zipkin-api/blob/{version}/LICENSE",
    ),
    com_google_googleapis = dict(
        # TODO(dio): Consider writing a Starlark macro for importing Google API proto.
        project_name = "Google APIs",
        project_desc = "Public interface definitions of Google APIs",
        project_url = "https://github.com/googleapis/googleapis",
        version = "fd52b5754b2b268bc3a22a10f29844f206abb327",
        sha256 = "97fc354dddfd3ea03e7bf2ad74129291ed6fad7ff39d3bd8daec738a3672eb8a",
        release_date = "2024-09-16",
        strip_prefix = "googleapis-{version}",
        urls = ["https://github.com/googleapis/googleapis/archive/{version}.tar.gz"],
        use_category = ["api"],
        license = "Apache-2.0",
        license_url = "https://github.com/googleapis/googleapis/blob/{version}/LICENSE",
    ),
    prometheus_metrics_model = dict(
        project_name = "Prometheus client model",
        project_desc = "Data model artifacts for Prometheus",
        project_url = "https://github.com/prometheus/client_model",
        version = "0.6.1",
        sha256 = "b9b690bc35d80061f255faa7df7621eae39fe157179ccd78ff6409c3b004f05e",
        release_date = "2024-04-03",
        strip_prefix = "client_model-{version}",
        urls = ["https://github.com/prometheus/client_model/archive/v{version}.tar.gz"],
        use_category = ["api"],
        license = "Apache-2.0",
        license_url = "https://github.com/prometheus/client_model/blob/v{version}/LICENSE",
    ),
    rules_proto = dict(
        project_name = "Protobuf Rules for Bazel",
        project_desc = "Protocol buffer rules for Bazel",
        project_url = "https://github.com/bazelbuild/rules_proto",
        version = "7.1.0",
        sha256 = "14a225870ab4e91869652cfd69ef2028277fc1dc4910d65d353b62d6e0ae21f4",
        release_date = "2024-12-18",
        strip_prefix = "rules_proto-{version}",
        urls = ["https://github.com/bazelbuild/rules_proto/archive/refs/tags/{version}.tar.gz"],
        use_category = ["api"],
        license = "Apache-2.0",
        license_url = "https://github.com/bazelbuild/rules_proto/blob/{version}/LICENSE",
    ),
    opentelemetry_proto = dict(
        project_name = "OpenTelemetry Proto",
        project_desc = "Language Independent Interface Types For OpenTelemetry",
        project_url = "https://github.com/open-telemetry/opentelemetry-proto",
        version = "1.5.0",
        sha256 = "08f40636adbc5f33d2084bd8e7b64e491dd0239d1a95021dbffbdf1ca8cea454",
        release_date = "2024-12-17",
        strip_prefix = "opentelemetry-proto-{version}",
        urls = ["https://github.com/open-telemetry/opentelemetry-proto/archive/v{version}.tar.gz"],
        use_category = ["api"],
        license = "Apache-2.0",
        license_url = "https://github.com/open-telemetry/opentelemetry-proto/blob/v{version}/LICENSE",
    ),
    com_github_bufbuild_buf = dict(
        project_name = "buf",
        project_desc = "A new way of working with Protocol Buffers.",  # Used for breaking change detection in API protobufs
        project_url = "https://buf.build",
        version = "1.48.0",
        sha256 = "7983f273b21aa4f8f7b42899da8568ed89ce6b81088cd6cc9ced18d469565c58",
        strip_prefix = "buf",
        urls = ["https://github.com/bufbuild/buf/releases/download/v{version}/buf-Linux-x86_64.tar.gz"],
        release_date = "2024-12-19",
        use_category = ["api"],
        license = "Apache-2.0",
        license_url = "https://github.com/bufbuild/buf/blob/v{version}/LICENSE",
    ),
    com_github_chrusty_protoc_gen_jsonschema = dict(
        project_name = "protoc-gen-jsonschema",
        project_desc = "Protobuf to JSON-Schema compiler",
        project_url = "https://github.com/norbjd/protoc-gen-jsonschema",
        strip_prefix = "protoc-gen-jsonschema-{version}",
        sha256 = "ba3e313b10a1b50a6c1232d994c13f6e23d3669be4ae7fea13762f42bb3b2abc",
        version = "7680e4998426e62b6896995ff73d4d91cc5fb13c",
        urls = ["https://github.com/norbjd/protoc-gen-jsonschema/archive/{version}.zip"],
        use_category = ["build"],
        release_date = "2023-05-30",
        license = "Apache-2.0",
        license_url = "https://github.com/norbjd/protoc-gen-jsonschema/blob/{version}/LICENSE",
    ),
    dev_cel = dict(
        project_name = "CEL",
        project_desc = "Common Expression Language -- specification and binary representation",
        project_url = "https://github.com/google/cel-spec",
        strip_prefix = "cel-spec-{version}",
        sha256 = "0661174bb0c965c72f2d037d9d8e8717ed20f9a64f9b1be9851069f9277c9508",
        version = "0.19.1",
        urls = ["https://github.com/google/cel-spec/archive/v{version}.tar.gz"],
        use_category = ["api"],
        release_date = "2024-12-06",
        license = "Apache-2.0",
        license_url = "https://github.com/google/cel-spec/blob/v{version}/LICENSE",
    ),
    envoy_toolshed = dict(
        project_name = "envoy_toolshed",
        project_desc = "Tooling, libraries, runners and checkers for Envoy proxy's CI",
        project_url = "https://github.com/envoyproxy/toolshed",
        version = "0.2.2",
        sha256 = "443fe177aba0cef8c17b7a48905c925c67b09005b10dd70ff12cd9f729a72d51",
        strip_prefix = "toolshed-bazel-v{version}/bazel",
        urls = ["https://github.com/envoyproxy/toolshed/archive/bazel-v{version}.tar.gz"],
        use_category = ["build"],
        release_date = "2024-12-16",
        cpe = "N/A",
        license = "Apache-2.0",
        license_url = "https://github.com/envoyproxy/toolshed/blob/bazel-v{version}/LICENSE",
    ),
)
