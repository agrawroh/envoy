Added a per worker cache of built routes to the :ref:`dynamic modules route specifier
<config_http_route_specifiers_dynamic_modules>`, configured with :ref:`built_route_cache
<envoy_v3_api_field_extensions.router.route_specifiers.dynamic_modules.v3.DynamicModuleRouteSpecifier.built_route_cache>`.
A module calls ``set_route_cache_key`` after selecting a template, and a route built for the key
serves the later requests on the worker, so a specifier whose routes are a function of a small key
builds each route once per worker rather than once per request. A template that resolves its cluster per
request is never cached, and sampled hits are verified against what the module records.
